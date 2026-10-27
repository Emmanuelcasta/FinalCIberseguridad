# SI3006 · Trabajo Final — OWASP Juice Shop: de la explotación a la defensa

**Universidad EAFIT · SI3006 Ciberseguridad · 2026-2**

Todo el trabajo está en esta carpeta y es **reproducible con un comando**. El servicio
vulnerable está desplegado en Google Cloud y el parche se demuestra en vivo sobre una copia
compilada desde el código fuente.

| | |
|---|---|
| **Servicio desplegado (GCP)** | <https://juice-shop-si3006-478542386940.us-central1.run.app> |
| **Proyecto / región** | `dw-mateo-lopera-2026` · `us-central1` · Cloud Run + Artifact Registry |
| **Aplicación** | OWASP Juice Shop **v20.3.0** (commit `f189f52`, tag `v20.3.0`) |
| **Vulnerabilidad explotada** | SQL Injection (CWE-89) → auth bypass + exfiltración de la tabla `Users` · **CVSS 9.1** |
| **Presentación** | [`presentacion/index.html`](presentacion/index.html) · [`presentacion/SI3006_TrabajoFinal_JuiceShop.pdf`](presentacion/SI3006_TrabajoFinal_JuiceShop.pdf) |

---

## Índice por punto de la rúbrica

| Punto | Peso | Evidencia / artefacto |
|---|---:|---|
| **1 · Despliegue** | 5 % | Despliegue real en Cloud Run (`gcloud run services describe juice-shop-si3006`) + build local desde fuente (`juice-shop/`). Guion: [`DEMO.sh --setup`](DEMO.sh) |
| **2 · Explotación** | 5 % | Reporte completo: [`informe/reporte_vulnerabilidad.md`](informe/reporte_vulnerabilidad.md). Evidencia: [`evidencias/01_login_bypass_respuesta.json`](evidencias/), [`02_union_dump_usuarios.txt`](evidencias/), [`captura_ataque_mitmproxy.txt`](evidencias/) |
| **3 · Remediación** | 10 % | Parche: [`fix/parche_completo.patch`](fix/parche_completo.patch) · antes/después: [`fix/antes/`](fix/antes/), [`fix/despues/`](fix/despues/) · prueba: [`evidencias/03_comparativa_antes_despues.txt`](evidencias/) |
| **4 · Arquitectura segura** | 5 % | [`arquitectura/arquitectura_actual.png`](arquitectura/), [`arquitectura_segura.png`](arquitectura/), [`costos_arquitectura.md`](arquitectura/costos_arquitectura.md), política WAF real: [`cloud_armor_policy_evidencia.json`](arquitectura/) |
| **5 · Herramienta defensiva** | 10 % | Captura de red + Cloud Logging + detector con alertas: [`blue-team/detector_ids.py`](blue-team/detector_ids.py), reglas [`sigma/`](blue-team/sigma/), [`wazuh/`](blue-team/wazuh/), alertas en [`evidencias/alertas_ids_*.log`](evidencias/) |
| **6 · Políticas y estándares** | 5 % | [`politicas/politicas_estandares.md`](politicas/politicas_estandares.md) — ISO/IEC 27001:2022 **A.8.28** y OWASP **ASVS 4.0.3 / WSTG 4.2 / SAMM 2.0** (no el Top 10) |
| **7 · DevSecOps** | 10 % | [`devsecops/gate_devsecops.sh`](devsecops/gate_devsecops.sh) (rojo/verde demostrado), [`devsecops/.github-workflows-devsecops.yml`](devsecops/), [`sast/`](sast/) |
| **8 · Reporte (presentación)** | 20 % | [`presentacion/SI3006_TrabajoFinal_JuiceShop.pdf`](presentacion/SI3006_TrabajoFinal_JuiceShop.pdf) (32 diapositivas, 16:9) y la versión HTML interactiva |
| **9 · Sustentación** | 30 % | Guion minuto a minuto en [`GUION_SUSTENTACION.md`](GUION_SUSTENTACION.md) y demo ejecutable [`DEMO.sh`](DEMO.sh) |

---

> **Ubicación del código fuente:** el árbol de Juice Shop (clon del tag `v20.3.0`) vive en
> `../juice-shop` y es el que contiene el parche aplicado. `../juice-shop` es también el que se
> usa para `npm start` en `:3001` y para el gate DevSecOps en verde.

## Estructura

```
deliverables/
├── DEMO.sh                     demo en vivo de todo el ataque (8 pasos)
├── GUION_SUSTENTACION.md       guion minuto a minuto para los 30 min
├── informe/
│   └── reporte_vulnerabilidad.md         reporte formal (formato de clase)
├── fix/
│   ├── parche_completo.patch             git diff (48 líneas, 3 archivos)
│   ├── antes/                            login.ts · search.ts · server.ts originales
│   └── despues/                          los mismos archivos remediados
├── sast/
│   ├── semgrep_ANTES_vulnerable.txt      2 hallazgos bloqueantes
│   └── semgrep_DESPUES_remediado.txt     0 hallazgos
├── devsecops/
│   ├── gate_devsecops.sh                 ejecuta el gate (SAST/SCA/config)
│   ├── .github-workflows-devsecops.yml   pipeline completo (GHA)
│   └── resultados/                       salidas de semgrep y npm audit
├── blue-team/
│   ├── detector_ids.py                   detector de SQLi con alertas JSON
│   ├── sigma/sqli_juice_shop.yml         2 reglas Sigma
│   └── wazuh/juice_shop_sqli_rules.xml   8 reglas Wazuh + active response
├── arquitectura/
│   ├── generar_diagramas.py              genera los dos diagramas (SVG+PNG)
│   ├── arquitectura_actual.svg/.png
│   ├── arquitectura_segura.svg/.png
│   ├── costos_arquitectura.py            modelo de costos
│   ├── costos_arquitectura.md/.csv/.png  4 escenarios, precios reales
│   ├── precios_gcp_verificados.txt       salida cruda de Cloud Billing API
│   └── cloud_armor_policy_evidencia.json política WAF creada en el proyecto
├── politicas/
│   └── politicas_estandares.md           ISO 27001 + OWASP ASVS/WSTG/SAMM
├── evidencias/
│   ├── generar_evidencias.sh             regenera toda la evidencia
│   ├── 01_login_bypass_respuesta.json
│   ├── 02_union_dump_usuarios.json/.txt  24 cuentas exfiltradas
│   ├── 03_comparativa_antes_despues.txt  9 payloads × 2 versiones
│   ├── captura_ataque_mitmproxy.txt      captura de red (tipo Burp)
│   ├── cloud_logging_juice_shop.json     request logs de producción
│   ├── alertas_ids_local.log / _GCP.log  alertas del detector
│   ├── waf_modsecurity_alertas.txt       bloqueo 403 con OWASP CRS
│   └── gate_antes_VULNERABLE.log / gate_despues_REMEDIADO.log
└── presentacion/
    ├── index.html                        presentación interactiva (← →, N notas, F fullscreen)
    └── SI3006_TrabajoFinal_JuiceShop.pdf 32 diapositivas para entregar
```

---

## Cómo reproducirlo

### Requisitos
`docker`, `node ≥ 22`, `curl`, `python3` y, para los diagramas/costos, `matplotlib`.

### 1. Levantar el entorno

```bash
cd deliverables
./DEMO.sh --setup
```

Esto deja en marcha:

| Puerto | Qué es |
|---|---|
| `:3000` | Juice Shop **vulnerable** (imagen oficial `bkimminich/juice-shop:v20.3.0`) |
| `:3001` | Juice Shop **remediado** (código fuente propio + parche, compilado con `tsc`) |
| `:8090` | WAF de demostración (ModSecurity + OWASP CRS) delante de `:3000` |

### 2. Ejecutar la demo

```bash
./DEMO.sh          # ataque, impacto, remediación, WAF y detección
./DEMO.sh --down   # apagar todo
```

### 3. Regenerar la evidencia y los artefactos

```bash
./evidencias/generar_evidencias.sh                 # ataque + comparativa + regresión
./devsecops/gate_devsecops.sh /tmp/gate-vuln       # gate ROJO  (código vulnerable)
./devsecops/gate_devsecops.sh ../juice-shop        # gate VERDE (código remediado)
python3 arquitectura/generar_diagramas.py          # diagramas
python3 arquitectura/costos_arquitectura.py        # modelo de costos
python3 blue-team/detector_ids.py --format gcp evidencias/cloud_logging_juice_shop.json
```

Para el código vulnerable del gate:

```bash
cd ../juice-shop && git worktree add /tmp/gate-vuln HEAD
```

### 4. Presentación

```bash
open presentacion/index.html
```

* `←` `→` / espacio: navegar · `N`: notas del orador · `F`: pantalla completa
* Regenerar el PDF: `"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless=new --no-pdf-header-footer --print-to-pdf=presentacion/SI3006_TrabajoFinal_JuiceShop.pdf --virtual-time-budget=10000 "file://$PWD/presentacion/index.html"`

---

## Resumen del hallazgo

**`routes/login.ts:34`** y **`routes/search.ts:23`** construyen SQL por interpolación de
plantillas. Dos primitivas derivan de la misma causa raíz:

1. **Bypass de autenticación** — `{"email":"' OR 1=1--","password":"x"}` devuelve **HTTP 200**
   con un JWT de `admin@juice-sh.op` (`role: "admin"`), sin conocer ninguna contraseña.
2. **Exfiltración** — `q=qwert')) UNION SELECT id,email,password,1,1,1,1,1,1,1 FROM Users--`
   devuelve **24 cuentas** con correo y hash MD5 sin sal (`0192023a…` = `admin123`) en una sola
   petición HTTP 200.

**Remediación:** consultas parametrizadas (`bind: [$1, $2]`) + validación con lista blanca +
`rateLimit` por IP real en el login + errores genéricos al cliente. **48 líneas**, 3 archivos.

**Verificación:** los 5 payloads de login pasan de `200 (admin)` a `401`; el `UNION` pasa de
24 filas filtradas a 0; los dos logins legítimos siguen devolviendo `200`; Semgrep pasa de
2 hallazgos bloqueantes a 0; el gate DevSecOps pasa de **ROJO** a **VERDE**.

---

## Descargo de responsabilidad

Todas las pruebas se ejecutaron sobre una instancia de laboratorio propia y sobre la aplicación
deliberadamente vulnerable OWASP Juice Shop, en el marco académico de SI3006. Los autores no se
responsabilizan del uso de estas técnicas fuera de entornos autorizados.
