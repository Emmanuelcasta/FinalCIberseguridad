#!/usr/bin/env bash
# =====================================================================================
# SI3006 — Gate DevSecOps local (equivalente a la etapa "Build/Verificar" del pipeline)
#
#   uso:  ./gate_devsecops.sh <ruta-del-repo>
#   salida: 0 = pipeline en verde | 1 = pipeline rojo (build bloqueado)
#
# Etapas:
#   1. SAST   -> Semgrep p/sql-injection                                     BLOQUEANTE
#   2. SAST   -> Semgrep p/owasp-top-ten                                      INFORMATIVO
#   3. SCA    -> npm audit (severidad >= high)                                 INFORMATIVO
#                (Juice Shop fija a propósito dependencias antiguas: es una app
#                 deliberadamente vulnerable. En un producto real esta etapa sería
#                 BLOQUEANTE con un baseline de excepciones aprobadas por el CISO.)
#   4. Config -> verificación de axle de políticas (endpoints sin rate limit)   INFORMATIVO
# =====================================================================================
set -uo pipefail

REPO="${1:-.}"
IMG_SEMGREP="semgrep/semgrep:latest"
FAIL=0
OUTDIR="$(cd "$(dirname "$0")" && pwd)/resultados"
mkdir -p "$OUTDIR"

hr() { printf '\033[1m%s\033[0m\n' "------------------------------------------------------------------------"; }

hr; echo "ETAPA 1/4 · SAST BLOQUEANTE — Semgrep (p/sql-injection)"; hr
docker run --rm -v "$(cd "$REPO" && pwd)":/src -w /src "$IMG_SEMGREP" \
  semgrep scan --config "p/sql-injection" \
  --severity ERROR --error --quiet --text \
  routes/ models/ lib/ 2>&1 | tee "$OUTDIR/sast_sqli.txt" | tail -30
SAST_RC=${PIPESTATUS[0]}
if [ "$SAST_RC" -ne 0 ]; then
  echo -e "\033[31m[FAIL] SAST: hallazgos bloqueantes de inyeccion SQL (exit $SAST_RC)\033[0m"; FAIL=1
else
  echo -e "\033[32m[PASS] SAST: 0 hallazgos de inyeccion SQL\033[0m"
fi

hr; echo "ETAPA 2/4 · SAST INFORMATIVO — Semgrep (p/owasp-top-ten)"; hr
docker run --rm -v "$(cd "$REPO" && pwd)":/src -w /src "$IMG_SEMGREP" \
  semgrep scan --config "p/owasp-top-ten" --quiet --text \
  routes/ models/ lib/ 2>&1 | tee "$OUTDIR/sast_owasp.txt" | tail -12
echo "  (Juice Shop contiene vulnerabilidades deliberadas: este barrido es un baseline,"
echo "   no un gate. En un producto real se bloquea con excepciones aprobadas por el CISO.)"

hr; echo "ETAPA 3/4 · SCA — npm audit"; hr
if [ -f "$REPO/package.json" ] && [ -d "$REPO/node_modules" ]; then
  ( cd "$REPO" && npm audit --omit=dev --audit-level=high --json ) > "$OUTDIR/sca.json" 2>/dev/null
  python3 - "$OUTDIR/sca.json" <<'PY'
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: d={}
m=d.get("metadata",{}).get("vulnerabilities",{})
print("  dependencias de producción ->", m or "(sin datos)")
crit=m.get("critical",0); high=m.get("high",0)
sys.exit(1 if (crit or high) else 0)
PY
  if [ $? -ne 0 ]; then
    echo -e "\033[33m[WARN] SCA: dependencias de producción con HIGH/CRITICAL (aceptado por baseline del laboratorio)\033[0m"
  else
    echo -e "\033[32m[PASS] SCA: sin HIGH/CRITICAL en producción\033[0m"
  fi
else
  echo "[SKIP] sin package.json / node_modules en esta copia de trabajo"
fi

hr; echo "ETAPA 4/4 · Config as Code — endpoints sensibles sin throttle"; hr
python3 - "$REPO" <<'PY'
import re,sys,pathlib
repo=pathlib.Path(sys.argv[1])
srv=(repo/"server.ts").read_text()
rate=re.findall(r"app\.use\('([^']+)',\s*rateLimit", srv)
need=["/rest/user/login","/rest/user/reset-password"]
missing=[n for n in need if n not in rate]
for n in need:
    print(f"  {'OK ' if n in rate else 'FALTA'} rate limit en {n}")
if missing:
    print(f"  -> {len(missing)} endpoint(s) sensibles sin rate limiting")
PY

hr; echo "RESULTADO DEL GATE"; hr
if [ "$FAIL" -ne 0 ]; then
  echo -e "\033[41;97m PIPELINE ROJO — el despliegue se bloquea \033[0m"; exit 1
fi
echo -e "\033[42;30m PIPELINE VERDE — se permite desplegar \033[0m"; exit 0
