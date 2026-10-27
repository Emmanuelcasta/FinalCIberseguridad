#!/usr/bin/env python3
"""
SI3006 - Blue Team
Detector de Inyeccion SQL (CWE-89) sobre logs de acceso de OWASP Juice Shop.

Fuentes soportadas (autodetectadas):
  1. Log de acceso formato "combined" (morgan)      ->  juice-shop/logs/access.log
  2. Export JSON de Cloud Logging (gcloud logging read ... --format=json)
  3. Log de mitmproxy (mitmdump --set flow_detail=3) -> lineas "GET/POST http://..."

Salida:
  * Alerta JSON por linea (formato ECS-lite) para enviar a Wazuh/ELK/Loki
  * Resumen legible en stderr
  * Exit code 2 si hay alertas de severidad >= high (para usarlo como gate en CI/SOAR)

Uso:
  python3 detector_ids.py /ruta/access.log
  python3 detector_ids.py --format gcp cloud_logging_export.json
  gcloud logging read '...' --format=json | python3 detector_ids.py --format gcp -
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from collections import defaultdict

# --------------------------------------------------------------------------------------
# Reglas de deteccion. Cada regla: (id, severidad, descripcion, regex sobre la URI decodificada)
# Se basan en la sintaxis que el motor SQLite acepta y en la estructura endemica del endpoint.
# --------------------------------------------------------------------------------------
RULES = [
    ("SQLI-001", "critical", "UNION-based SQL injection (extraccion de datos)",
     re.compile(r"(\bunion\b[\s\S]{0,80}?\bselect\b|\bunion%20|\bunion\+|%27\)\)\s*union)", re.I)),
    ("SQLI-002", "critical", "Tautologia OR 1=1 / OR 'a'='a' (bypass de autenticacion)",
     re.compile(r"('\s*or\s*'?\d+'?\s*=\s*'?\d+|'\s*or\s*1\s*=\s*1|\bor\s+1\s*=\s*1)", re.I)),
    ("SQLI-003", "high", "Comentario SQL de truncamiento ('--', '#', '/*')",
     re.compile(r"(--\s*$|--\+|%27--|'\s*--|#\s*$|/\*)")),
    ("SQLI-004", "critical", "Enumeracion de esquema / metadatos",
     re.compile(r"(sqlite_master|information_schema|sys\.tables|pg_catalog|sql\s+from)", re.I)),
    ("SQLI-005", "critical", "Funcion de tiempo / pila apilada (blind SQLi)",
     re.compile(r"(sleep\s*\(|benchmark\s*\(|waitfor\s+delay|;\s*(drop|insert|update|delete)\s+)", re.I)),
    ("SQLI-006", "high", "Desbalance de comillas/parentesis con palabra clave SQL",
     re.compile(r"(\)\)|'\s*\)|\)\s*--)")),
    ("SQLI-007", "critical", "Referencia directa a la tabla de credenciales en la entrada",
     re.compile(r"from\s+users", re.I)),
]

# Reglas de comportamiento (no dependen del payload sino de la secuencia)
RULES_BEHAVIOR = [
    ("AUTH-001", "critical", "Login exitoso desde cliente no-navegador (posible bypass)",
     re.compile(r"^(curl|python|python-urllib|go-http-client|PostmanRuntime|sqlmap|okhttp)", re.I)),
]

MORGAN_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<uri>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)
MITM_RE = re.compile(r'^\d+\.\d+\.\d+\.\d+:\d+: (?P<method>[A-Z]+) (?P<url>http\S+)')
GCP_SQLI_HINT = re.compile(r"union|or\s+1=1|sqlite_master|--", re.I)

AUTH_ENDPOINTS = ("/rest/user/login", "/rest/user/authentication-details")
ADMIN_ENDPOINTS = ("/api/users", "/rest/admin/", "/api/feedbacks", "/rest/user/authentication-details")


def decode_uri(uri: str) -> str:
    """Doble decodificacion: los atacantes suelen ofuscar con %2527 (%27 -> ')."""
    once = urllib.parse.unquote(uri)
    return urllib.parse.unquote(once)


def score_uri(uri: str) -> list[dict]:
    decoded = decode_uri(uri)
    hits = []
    for rule_id, sev, desc, rx in RULES:
        m = rx.search(decoded)
        if m:
            hits.append({"rule": rule_id, "severity": sev, "description": desc, "matched": m.group(0)[:120]})
    return hits


def emit(alert: dict) -> None:
    print(json.dumps(alert, ensure_ascii=False))


def make_alert(src: dict, hits: list[dict], extra: str = "") -> dict:
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    top = max(hits, key=lambda h: sev_rank.get(h["severity"], 0))
    return {
        "@timestamp": src.get("ts") or datetime.now(timezone.utc).isoformat(),
        "event": {
            "kind": "alert",
            "category": "web",
            "type": "sql_injection",
            "severity": top["severity"],
            "dataset": "juice-shop.web.access",
            "module": "si3006.sqlidetector",
        },
        "rule": {
            "id": top["rule"],
            "name": top["description"],
            "description": " | ".join(f'{h["rule"]}:{h["matched"]}' for h in hits),
            "mitre": [
                {"id": "T1190", "name": "Exploit Public-Facing Application"},
                {"id": "T1078", "name": "Valid Accounts"},
            ],
            "cwe": "CWE-89",
            "owasp": "A03:2021 Injection",
        },
        "url": {"original": src.get("uri"), "decoded": decode_uri(src.get("uri") or "")},
        "http": {"method": src.get("method"), "status_code": src.get("status")},
        "source": {"ip": src.get("ip"), "user_agent": src.get("ua")},
        "message": f'SQLi detectada en {src.get("method")} {src.get("uri")} desde {src.get("ip")}' + (f' [{extra}]' if extra else ""),
    }


def from_morgan(lines):
    for line in lines:
        m = MORGAN_RE.match(line.strip())
        if not m:
            continue
        d = m.groupdict()
        uri = d["uri"]
        hits = score_uri(uri)
        ts = d.get("ts")
        try:
            ts = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc).isoformat()
        except Exception:
            pass
        yield {"ts": ts, "ip": d["ip"], "method": d["method"], "uri": uri,
               "status": int(d["status"]), "ua": d.get("ua") or ""}, hits


def from_mitm(lines):
    for line in lines:
        m = MITM_RE.match(line.strip())
        if not m:
            continue
        uri = m.group("url").split("://", 1)[-1].split("/", 1)[-1]
        uri = "/" + uri
        yield {"ts": None, "ip": "proxy-client", "method": m.group("method"),
               "uri": uri, "status": 0, "ua": ""}, score_uri(uri)


def from_gcp(lines):
    buf = "".join(lines)
    try:
        records = json.loads(buf)
    except json.JSONDecodeError:
        # NDJSON
        records = [json.loads(l) for l in lines if l.strip().startswith("{")]
    if isinstance(records, dict):
        records = [records]
    for r in records:
        http = r.get("httpRequest") or {}
        uri = http.get("requestUrl") or ""
        path = "/" + uri.split("://", 1)[-1].split("/", 1)[-1] if "://" in uri else uri
        yield {"ts": r.get("timestamp"), "ip": http.get("remoteIp"), "method": http.get("requestMethod"),
               "uri": path, "status": int(http.get("status") or 0),
               "ua": http.get("userAgent") or ""}, score_uri(path)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("file", nargs="?", default="-")
    ap.add_argument("--format", choices=["auto", "morgan", "mitm", "gcp"], default="auto")
    args = ap.parse_args()

    stream = sys.stdin if args.file == "-" else open(args.file, encoding="utf-8", errors="ignore")
    lines = stream.read().splitlines()

    fmt = args.format
    if fmt == "auto":
        sample = "\n".join(lines[:5])
        fmt = "gcp" if sample.lstrip().startswith(("[", "{")) else ("morgan" if MORGAN_RE.search(sample) else "mitm")

    reader = {"morgan": from_morgan, "mitm": from_mitm, "gcp": from_gcp}[fmt]

    alerts, per_ip, sqli_ips, events = [], defaultdict(int), set(), []

    # --- Fase 1: deteccion por firma de payload -------------------------------------
    for src, hits in reader(lines):
        events.append(src)
        if hits:
            alerts.append(make_alert(src, hits))
            per_ip[src["ip"]] += 1
            sqli_ips.add(src["ip"])

    # --- Fase 2: correlacion de comportamiento --------------------------------------
    # Un login correcto con cliente automatizado solo es relevante si la MISMA fuente ya
    # disparo una firma de SQLi (asi se evita el falso positivo de un script legitimo de
    # monitoreo que hace login con curl cada hora).
    for src in events:
        if (src["method"] == "POST" and src["uri"].lower().startswith("/rest/user/login")
                and src["status"] == 200 and src["ip"] in sqli_ips):
            for rid, sev, desc, rx in RULES_BEHAVIOR:
                if rx.search(src.get("ua") or ""):
                    alerts.append({
                        "@timestamp": src.get("ts") or datetime.now(timezone.utc).isoformat(),
                        "event": {"kind": "alert", "category": "authentication", "type": "auth_bypass",
                                  "severity": sev, "dataset": "juice-shop.web.access"},
                        "rule": {"id": rid, "name": desc, "cwe": "CWE-89 / CWE-287",
                                 "mitre": [{"id": "T1078", "name": "Valid Accounts"}]},
                        "source": {"ip": src["ip"], "user_agent": src.get("ua")},
                        "message": f'Login HTTP 200 con User-Agent automatizado ({src.get("ua")}) desde {src["ip"]} tras intento de SQLi',
                    })

    # Correlacion: muchas respuestas 200/401 en login desde una misma IP => fuerza bruta / automatizacion
    fails = defaultdict(int)
    for line in lines:
        m = MORGAN_RE.match(line.strip())
        if m and m.group("method") == "POST" and m.group("uri").startswith("/rest/user/login") and m.group("status") == "401":
            fails[m.group("ip")] += 1
    for ip, n in fails.items():
        if n >= 10:
            alerts.append({
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "event": {"kind": "alert", "category": "authentication", "type": "brute_force",
                          "severity": "high", "dataset": "juice-shop.web.access"},
                "rule": {"id": "AUTH-002", "name": "Multiples fallos de login desde una IP (fuerza bruta / credential stuffing)",
                         "cwe": "CWE-307", "mitre": [{"id": "T1110", "name": "Brute Force"}]},
                "source": {"ip": ip}, "count": n,
                "message": f"{n} intentos fallidos de login desde {ip}",
            })

    for a in alerts:
        emit(a)

    sys.stderr.write(f"\n[detector] formato={fmt} lineas={len(lines)} alertas={len(alerts)}\n")
    for ip, n in sorted(per_ip.items(), key=lambda x: -x[1]):
        sys.stderr.write(f"[detector]   fuente {ip}: {n} request(s) malicioso(s)\n")
    if not alerts:
        sys.stderr.write("[detector]   sin hallazgos (trafico limpio)\n")
    return 2 if any(a["event"]["severity"] in ("critical", "high") for a in alerts) else 0


if __name__ == "__main__":
    sys.exit(main())
