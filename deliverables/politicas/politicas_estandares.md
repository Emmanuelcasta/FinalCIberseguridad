# Punto 6 — Gestión de políticas y estándares
## Cómo una política y un estándar habrían asegurado Juice Shop frente a la inyección SQL

> Vulnerabilidad explotada: **CWE-89 / SQL Injection** en `routes/login.ts` (bypass de
> autenticación) y `routes/search.ts` (exfiltración de la tabla `Users`).
> Afecta: **A03:2021 Injection** (OWASP Top 10, como referencia) — pero el marco que se
> exige en este punto **no** es el Top 10.

---

## 1. ISO/IEC 27001:2022 — control específico

### Control principal

| Campo | Detalle |
|---|---|
| **Control** | **A.8.28 — Secure coding (Codificación segura)** |
| **Categoría** | A.8 *Technological controls* |
| **Texto del control** | «Se deben aplicar principios de codificación segura al desarrollo de software.» |
| **Qué exige (ISO/IEC 27002:2022 §8.28)** | Establecer y aplicar reglas de codificación segura por lenguaje y framework; cubrir, entre otros, *input validation*, *output encoding*, **uso de consultas parametrizadas / ORM**, manejo de errores, gestión de secretos y gestión de dependencias. Revisar el cumplimiento mediante revisión de código y **análisis estático (SAST)**. |
| **Implementación en Juice Shop** | Regla organizativa: «*toda consulta a base de datos se construye exclusivamente con sentencias parametrizadas o con el ORM; la concatenación de entrada del usuario en SQL está prohibida*». Verificación automática con Semgrep (`p/sql-injection`) como *gate* bloqueante del pipeline. |

### Controles de soporte (una sola vulnerabilidad se cubre con varios controles)

| Control ISO 27001:2022 | Por qué aplica a **esta** vulnerabilidad | Evidencia / artefacto |
|---|---|---|
| **A.8.26 — Application security requirements** | Define como requisito de seguridad *no funcional* que la aplicación valide y neutralice la entrada antes de usarla en consultas. Sin requisito escrito, el desarrollador no tiene contra qué cumplir. | Requisito REQ-SEC-01 (abajo) |
| **A.8.27 — Secure system architecture and engineering principles** | El endpoint de búsqueda usaba *SQL crudo* en lugar del ORM ya presente en la app (violación de *least functionality* y de defensa en profundidad). | `arquitectura_segura.png` |
| **A.8.29 — Security testing in development and acceptance** | El SAST en el pipeline habría detectado la concatenación en `login.ts` y `search.ts` (demostrado en `sast/`). | `semgrep_ANTES_vulnerable.txt` |
| **A.8.24 — Use of cryptography** | Contraseñas almacenadas con **MD5 sin sal** (`0192023a…` = `admin123`): el volcado de la tabla se convierte en *account takeover* inmediato. | Evidencia UNION dump |
| **A.8.5 — Secure authentication** | El *bypass* produjo un JWT con `role: admin` sin conocer ninguna credencial. | Captura mitmproxy |
| **A.8.20 / A.8.21 — Networks security / security of network services** | Mientras el defecto exista, el único control posible en el borde es un **WAF** (Cloud Armor) y la restricción de exposición del servicio. | `security-policies describe juice-shop-waf` |
| **A.8.15 / A.8.16 — Logging / Monitoring activities** | El ataque es visible en los *request logs*; sin regla de detección y sin alerta nadie se enteró. | `evidencias/alertas_ids_GCP.log` |
| **A.8.8 — Management of technical vulnerabilities** | Requiere un proceso de gestión de vulnerabilidades (identificar, priorizar por CVSS, remediar en SLA). | Ver §4 SLA de remediación |
| **A.8.31 — Separation of dev/test/prod** · **A.8.32 — Change management** | El *fix* debe pasar por PR + revisión + SAST antes de llegar a producción. | `.patch` + pipeline |
| **A.5.24–A.5.26 — Incident management** | Playbook de respuesta: ban de IP en Cloud Armor, rotación de credenciales, invalidación de JWT. | `blue-team/` |
| **A.8.12 — Data leakage prevention** | El UNION SELECT exfiltró 24 correos + hashes en una sola petición HTTP 200. | `evidencias/union_dump` |
| **A.5.15 / A.8.3 — Access control / information access restriction** | La cuenta de base de datos de la app no debería poder leer más tablas/columnas de las necesarias. | Cloud SQL en la arquitectura propuesta |

### Declaración de aplicabilidad (SoA) — extracto

| Control | ¿Aplica? | Justificación | Estado | Responsable |
|---|---|---|---|---|
| A.8.28 | Sí | Desarrollo propio de una aplicación web expuesta a Internet | No conforme → hallazgo **NC-01** | Líder técnico |
| A.8.29 | Sí | Se requiere verificación automatizada en cada cambio | No conforme → **NC-02** | DevSecOps |
| A.8.20 | Sí | Servicio publicado en Internet sin control de borde | No conforme → **NC-03** | Cloud/Infra |

---

## 2. Estándar OWASP utilizado (y por qué)

> **No se usa el OWASP Top 10** (es una lista de concienciación, no un estándar verificable).

### 2.1 OWASP ASVS 4.0.3 — *Application Security Verification Standard* (estándar principal)

Es el estándar adecuado porque **es verificable, medible y auditable**: define requisitos
numerados con nivel de rigor (L1/L2/L3) que se pueden convertir en criterios de aceptación y
en pruebas automáticas.

| Requisito ASVS 4.0.3 | Texto | Nivel | Cómo se cumple en Juice Shop |
|---|---|---|---|
| **V5.3.4** | «Verificar que la selección de datos o las consultas a la base de datos (p. ej. SQL, HQL, ORM, NoSQL) utilizan **consultas parametrizadas**, ORM o *stored procedures*, de modo que los caracteres especiales interpretados por el motor no puedan alterar la estructura de la consulta.» | L1 | `routes/login.ts` y `routes/search.ts` migrados a `sequelize.query(..., { bind: [...] })`. **Antes: NO conforme.** |
| **V5.1.3** | «Verificar que todos los datos de entrada se validan con una **lista blanca** positiva (caracteres permitidos, longitud, formato).» | L1 | `EMAIL_RE` + longitud máxima de contraseña en el *fix*. |
| **V5.1.4** | «Verificar que la aplicación valida **estructuralmente** los datos de entrada fuertemente tipados (…).» | L2 | Coerción explícita `typeof req.body.email === 'string'`. |
| **V5.3.10** | «Verificar que los datos de entrada se validan y **codifican** para evitar *injection* en el intérprete al que se envían.» | L1 | *Bindings* posicionales (`$1`, `$2`). |
| **V7.4.1** | «Verificar que se utiliza una política general de manejo de errores para evitar **fugas de información** en los mensajes de error.» | L1 | El `SQLITE_ERROR` crudo se reemplazó por un 500 genérico. |
| **V2.4.1** | «Verificar que las contraseñas se almacenan con un **hash de derivación de clave con sal** resistente a *brute force*.» | L1 | Hallazgo adicional: MD5 sin sal → se recomienda Argon2id/bcrypt (control compensatorio en la arquitectura mientras se migra). |
| **V13.1.3** | «Verificar que solo se exponen los servicios y recursos necesarios.» | L1 | `ingress = internal-and-cloud-load-balancing` + IAP en la arquitectura. |
| **V14.2.3** | «Verificar que el servidor no revela el framework ni la versión…» | L2 | `/rest/admin/application-version` expuesto públicamente. |

**Por qué ASVS y no el Top 10:** el Top 10 dice «*cuidado con la inyección*» (categoría A03);
ASVS dice «*la consulta debe estar parametrizada, verificable en L1, comprobable por prueba
automatizada*». La diferencia es exactamente la que permite aprobar o rechazar el código en un
pipeline.

### 2.2 OWASP WSTG v4.2 — *Web Security Testing Guide* (procedimiento de prueba)

* **WSTG-INPV-05 — Testing for SQL Injection**: es el procedimiento que se ejecutó en el punto 2
  (inyección en parámetros GET/POST, tautologías, UNION, comentarios, enumeración de esquema).
* **WSTG-ATHN-01 / ATHN-03** — pruebas de autenticación y bypass.
* **WSTG-CONF-02 / CONF-06** — prueba de *verbose errors* y de métodos HTTP.

Permite declarar el hallazgo como **reproducible y estandarizado**, no como una intuición.

### 2.3 OWASP SAMM v2 — modelo de madurez (gobernanza)

| Práctica SAMM | Nivel actual | Nivel objetivo | Cambio requerido |
|---|---|---|---|
| **Implementation → Secure Build** | 0 (sin controles en el build) | 1 | Gate SAST + SCA en cada PR |
| **Verification → Security Testing** | 0 (solo pruebas funcionales) | 2 | SAST + DAST (ZAP) + *abuse cases* |
| **Design → Threat Assessment** | 0 | 1 | *Threat model* por historia de usuario |
| **Operations → Incident Management** | 0 | 1 | Playbook + SIEM (Wazuh) |
| **Governance → Policy & Compliance** | 1 | 2 | Política de desarrollo seguro aprobada |

### 2.4 Otros estándares OWASP aplicados (justificación breve)

| Estándar | Uso concreto en este trabajo |
|---|---|
| **OWASP CRS (Core Rule Set 4.30)** | Es el conjunto de reglas que Google Cloud Armor usa para `sqli-v33-stable`; se usó además ModSecurity + CRS para demostrar el bloqueo sin tocar el código. |
| **OWASP Cheat Sheet — SQL Injection Prevention** | Fuente de las cuatro opciones de defensa (consultas parametrizadas → procedimientos almacenados → *allow-list* → *escaping* como último recurso). |
| **OWASP ZAP** | DAST en la etapa «Runtime» (detecta la misma firma sobre la app corriendo). |
| **OWASP Dependency-Check / CycloneDX SBOM** | SCA y SBOM en el pipeline (la imagen trae 17 vulnerabilidades de dependencias). |
| **OWASP ASVS + OWASP Juice Shop** | La propia aplicación es el material de entrenamiento oficial de OWASP; se usa como banco de pruebas. |

---

## 3. Política propuesta (texto para aprobación)

**POL-SEC-DEV-01 — Política de Desarrollo Seguro (extracto)**

1. **Acceso a datos.** Toda interacción con una base de datos se realizará mediante consultas
   parametrizadas, ORM o procedimientos almacenados. Queda prohibida la concatenación o
   interpolación de variables en texto SQL. *Responsable:* desarrollador que firma el PR.
2. **Validación de entrada.** Toda entrada se validará con una lista blanca positiva
   (tipo, formato, longitud, rango) en el servidor, nunca solo en el cliente.
3. **Manejo de errores.** Ninguna respuesta HTTP expondrá trazas, mensajes del motor de base de
   datos ni versiones de componentes. Los detalles irán al *log* del servidor con un
   identificador de correlación.
4. **Secretos.** Ninguna clave, contraseña o certificado se almacenará en el repositorio; se
   obtendrán de un gestor de secretos (Secret Manager) con identidad dedicada.
5. **Verificación automática.** El pipeline ejecutará SAST (Semgrep), SCA (npm audit /
   Dependency-Check) y escaneo de imagen (Trivy). Un hallazgo **HIGH/CRITICAL** en una regla de
   inyección **bloquea** el despliegue.
6. **Gestión de vulnerabilidades.** Los hallazgos se clasifican por CVSS v3.1 y se remedian en:
   **Crítico ≤ 7 días, Alto ≤ 30 días, Medio ≤ 90 días**.
7. **Revisión por pares.** Ningún cambio llega a producción sin revisión de un segundo
   ingeniero y sin la trazabilidad del pipeline en verde.
8. **Registro y monitoreo.** Los *request logs* y *audit logs* se centralizan con retención de
   90 días y se correlacionan con reglas de detección (Sigma/Wazuh) con alerta 24×7.

**REQ-SEC-01 (requisito derivado, verificable)**
> «Las consultas de autenticación y de búsqueda de productos deben usar *bindings*
> posicionales. Criterio de aceptación: `semgrep --config p/sql-injection routes/` devuelve 0
> hallazgos y las pruebas de regresión confirman que el login legítimo sigue funcionando.»

---

## 4. Cómo se demuestra el cumplimiento (evidencia)

| Requisito | Evidencia generada en este trabajo |
|---|---|
| ASVS V5.3.4 | `fix/parche_completo.patch` (consulta con `bind`) + `sast/semgrep_DESPUES_remediado.txt` (0 hallazgos) |
| ASVS V5.1.3 / V5.1.4 | `fix/despues/login.ts` (regex de lista blanca + coerción de tipos) |
| ASVS V7.4.1 | `fix/despues/login.ts` (500 genérico) |
| ISO A.8.29 | `sast/semgrep_ANTES_vulnerable.txt` (2 hallazgos bloqueantes) |
| ISO A.8.20 | `arquitectura/cloud_armor_policy_evidencia.json` |
| ISO A.8.15/A.8.16 | `evidencias/alertas_ids_GCP.log` + reglas Sigma/Wazuh |
| WSTG-INPV-05 | `evidencias/comparativa_antes_despues.txt` |
| SAMM Secure Build | `devsecops/` (pipeline propuesto y ejecución del gate) |
