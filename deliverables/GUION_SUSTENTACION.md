# Guion de sustentación — SI3006 Trabajo Final
## 30 minutos de exposición + 15 de preguntas

> Regla del docente: *«cambio de roles: experto técnico en desarrollo, practicante que aprende,
> experto en ciberseguridad, experto en DevOps y gerente que se preocupa por el presupuesto»*.
> Este guion está organizado para que **cada cambio de rol tenga munición preparada** (ver §4).

---

## 1. Reparto del tiempo (30 min)

| Min | Bloque | Diapositivas | Quién | Qué se ve / se hace |
|---:|---|---|---|---|
| 0:00 | Apertura y objetivo | 1–2 | Todos (1 frase cada uno) | Presentación del equipo y del hilo conductor: *explotar → arreglar → blindar → detectar → automatizar* |
| 2:00 | **P1 Despliegue** | 3–5 | Perfil *cloud/dev* | Servicio real en Cloud Run + build desde fuente. `gcloud run services describe` en pantalla |
| 5:00 | **P2 Reporte de la vulnerabilidad** | 6–10 | Perfil *red team* | **DEMO en vivo (3 min)**: bypass + `/api/Users` + UNION dump + crack del MD5 |
| 11:00 | **P3 Remediación** | 11–14 | Perfil *dev* | **DEMO en vivo (2 min)**: `npx tsc` → repetir payloads → 401 y 0 filas → login legítimo 200 |
| 15:00 | **P4 Arquitectura segura** | 15–20 | Perfil *arquitecto/cloud* | Diagrama, control compensatorio y **DEMO WAF (1 min)**: 403 con código sin parchear. Costos |
| 20:30 | **P5 Blue team** | 21–25 | Perfil *blue team* | Captura mitmproxy, Cloud Logging, **DEMO detector (1 min)** + reglas Sigma/Wazuh |
| 24:00 | **P6 Políticas y estándares** | 26–29 | Perfil *GRC* | ISO A.8.28, ASVS/WSTG/SAMM, política POL-SEC-DEV-01 y SLA |
| 27:00 | **P7 DevSecOps** | 30 | Perfil *DevOps* | **DEMO gate (1 min)**: rojo con el código vulnerable, verde con el parche |
| 29:00 | Conclusiones y cierre | 31–32 | Todos | Lección aprendida + gracias |
| **30:00** | **Preguntas** | — | Todos | 15 minutos |

> **Regla de oro:** nunca se queda un solo integrante más de 5 minutos seguidos hablando, y cada
> uno debe poder responder de cualquier punto (el docente preguntará a todos por todo).

---

## 2. Guion palabra por palabra de la apertura (para memorizar)

> «Buenos días. Somos el equipo de SI3006. Tomamos OWASP Juice Shop, la desplegamos en Google
> Cloud, la rompimos, la arreglamos en el código y montamos alrededor todo el sistema que debería
> haberla protegido: arquitectura, detección en red, políticas y pipeline.
> La idea que queremos que se lleven es una sola: **una vulnerabilidad no se cierra cuando se
> corrige, se cierra cuando el test que la reproduce se pone rojo en el pipeline.**»

---

## 3. Comandos exactos para cada demo (copiar y pegar)

### 3.1 Preparar antes de entrar al salón (5 min antes)
```bash
cd deliverables
./DEMO.sh --setup        # deja :3000 vulnerable, :3001 parcheado y :8090 con WAF
cd ../juice-shop && git worktree add /tmp/gate-vuln HEAD   # árbol vulnerable para el gate
```
Abrir además en pestañas separadas:
* `presentacion/index.html` en pantalla completa (F)
* la consola de Cloud Run / Cloud Logging del proyecto
* `deliverables/evidencias/` en el explorador de archivos (por si falla el wifi)

### 3.2 Demo P2 — el ataque (3 min)
```bash
# 1. bypass
curl -s -X POST http://localhost:3000/rest/user/login \
  -H 'Content-Type: application/json' -d '{"email":"'"'"' OR 1=1--","password":"x"}'

# 2. somos admin
TOK=$(... )                       # o usar ./DEMO.sh que lo hace todo
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOK" http://localhost:3000/api/Users

# 3. volcado
curl -s -G --data-urlencode "q=qwert')) UNION SELECT id,email,password,1,1,1,1,1,1,1 FROM Users--" \
  http://localhost:3000/rest/products/search

# 4. el hash es MD5 sin sal
python3 -c "import hashlib;print(hashlib.md5(b'admin123').hexdigest())"
```

### 3.3 Demo P3 — la remediación (2 min)
```bash
# el parche ya está compilado en :3001
curl -s -X POST http://localhost:3001/rest/user/login \
  -H 'Content-Type: application/json' -d '{"email":"'"'"' OR 1=1--","password":"x"}'    # 401

curl -s -G --data-urlencode "q=qwert')) UNION SELECT id,email,password,1,1,1,1,1,1,1 FROM Users--" \
  http://localhost:3001/rest/products/search                                            # 0 filas

curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3001/rest/user/login \
  -H 'Content-Type: application/json' -d '{"email":"admin@juice-sh.op","password":"admin123"}'   # 200

# y el código
git -C ../juice-shop diff routes/login.ts
```

### 3.4 Demo P4 — el WAF (1 min)
```bash
curl -s -o /dev/null -w 'login  -> %{http_code}\n' -X POST http://localhost:8090/rest/user/login \
  -H 'Content-Type: application/json' -d '{"email":"'"'"' OR 1=1--","password":"x"}'     # 403
curl -s -o /dev/null -w 'union  -> %{http_code}\n' -G --data-urlencode \
  "q=qwert')) UNION SELECT id,email,password,1,1,1,1,1,1,1 FROM Users--" \
  http://localhost:8090/rest/products/search                                             # 403
curl -s -o /dev/null -w 'apple  -> %{http_code}\n' http://localhost:8090/rest/products/search?q=apple  # 200

gcloud compute security-policies describe juice-shop-waf        # la política real en GCP
```

### 3.5 Demo P5 — detección (1 min)
```bash
python3 deliverables/blue-team/detector_ids.py deliverables/evidencias/cloud_logging_juice_shop.json
# muestra alerta JSON + exit code 2 (dispara el playbook)
```

### 3.6 Demo P7 — el gate (1 min)
```bash
./deliverables/devsecops/gate_devsecops.sh /tmp/gate-vuln      # PIPELINE ROJO
./deliverables/devsecops/gate_devsecops.sh ../juice-shop       # PIPELINE VERDE
```

---

## 4. Munición por rol del docente

### 4.1 «Soy experto técnico en desarrollo»
| Pregunta probable | Respuesta corta y correcta |
|---|---|
| ¿Por qué `bind` y no escapar comillas? | Porque escapar depende de **conocer el motor y su juego de caracteres**; el `bind` separa datos de código en el protocolo. `bind` elimina la clase; *escaping* solo el caso conocido. |
| ¿Por qué no usaron el ORM (`UserModel.findOne`)? | Se podía. Se eligió `sequelize.query` con `bind` para mantener el `model: UserModel, plain: true` que espera el resto del código y minimizar el diff. Ambas opciones son válidas; la regla es: **nunca concatenar**. |
| ¿`bind` funciona con SQLite en Sequelize? | Sí: Sequelize emite *prepared statements* posicionales (`$1`, `$2`). Verificado: los 5 payloads devuelven 401 y los logins legítimos 200. |
| ¿La regex de email no rompe correos válidos? | Se probaron los 24 usuarios sembrados, incluidos `J12934@`, `bjoern.kimminich@gmail.com` y `demo`. La regex solo prohíbe espacios, comillas, `\`, `;`, `(`, `)`, `<`, `>` — que nunca aparecen en un correo legítimo. |
| ¿No es frágil validar antes de consultar? | Es **defensa en profundidad**: si la regex falla, la consulta sigue siendo segura. Las dos capas son independientes. |
| ¿Por qué tipar `req.body.email` a string? | Porque en Express un atacante puede enviar un objeto o un arreglo y las plantillas lo serializan (`[object Object]`); también habilita *prototype pollution* si se pasa a Sequelize. ASVS V5.1.4. |

### 4.2 «Soy el practicante que está aprendiendo»
| Pregunta | Respuesta en lenguaje llano |
|---|---|
| ¿Qué es SQL injection, en una frase? | La aplicación mezcla **lo que el usuario escribe** con **las instrucciones de la base de datos**. Si el usuario escribe una instrucción, la base la obedece. |
| ¿Por qué el `--` es importante en el payload? | Porque `--` comenta el resto de la consulta: sirve para **borrar la condición de la contraseña**. |
| ¿Qué significa «saltarse el login»? | Que el servidor le entrega un **token de sesión** sin haber comprobado nunca la contraseña: el sistema cree que somos el administrador. |
| ¿Qué es un hash y por qué importa aquí? | Es una huella de la contraseña. Con **MD5 sin sal** la huella se puede buscar en tablas públicas: la contraseña del admin se obtiene en segundos. |
| ¿Qué es un WAF? | Un filtro que se pone delante de la aplicación y **rechaza peticiones que parecen ataques**. Es una barrera, no una cura: si el código está mal, sigue estando mal. |
| ¿Qué es SAST? | Un análisis **automático del código fuente** que busca patrones peligrosos, como concatenar datos del usuario dentro de un SQL. |

### 4.3 «Soy experto en ciberseguridad»
| Pregunta | Respuesta |
|---|---|
| ¿Cómo calcularon el CVSS? | `AV:N` (remoto, publicado en Internet) `AC:L` (un `curl`) `PR:N` (pre-autenticación) `UI:N` `S:U` `C:H` (24 cuentas + cualquier tabla) `I:H` (JWT admin escrito en la DB) `A:N`. Impacto 5,18 + Explotabilidad 3,89 = 9,07 → **9,1 Crítica**. La variante solo-lectura (`UNION`) da **7,5**. |
| ¿Su exploit es ciego o con eco? | **Con eco**: el `UNION` usa el propio JSON de la búsqueda como canal. Por eso el número de columnas se descubrió por prueba de error (10 columnas). |
| ¿Qué controles compensatorios propusieron y por qué no bastan? | Cloud Armor con `sqli-v33-stable`, IAP, rate-limit y Cloud SQL con permisos mínimos. Mitigan, pero un *bypass* del WAF o un payload polimórfico sigue llegando a una consulta mal construida: la corrección de fondo es parametrizar. |
| ¿Cómo verificarían el WAF de verdad? | El punto 4 lo demuestra con ModSecurity + **OWASP CRS 4.30** delante de la copia vulnerable: los dos payloads devuelven 403 y el tráfico legítimo 200. En GCP la regla es equivalente (`evaluatePreconfiguredWaf('sqli-v33-stable')`), ya creada en la política `juice-shop-waf`. |
| ¿Qué evidencia dejan en red? | `captura_ataque_mitmproxy.txt` con los tres flujos (login → UNION → `/api/Users`), `cloud_logging_juice_shop.json` con la URL completa del payload, la IP pública y el código 200, y el `access.log` del servicio. |
| ¿MTTD? | MTTD real = infinito (nadie miraba). Objetivo < 5 min con métrica basada en log + regla Sigma. MTTR objetivo < 30 min con playbook. |
| ¿La detección tiene falsos positivos? | Sí, y se documentan: la regla `AUTH-001` correlaciona por IP, así que un script legítimo que hace login con `curl` desde la misma IP alerta. Se afina con lista blanca de User-Agent y con *distinct usernames*. |
| ¿Qué otros hallazgos encontraron? | (1) `X-Forwarded-For` como clave del rate limit en `/rest/user/reset-password` → eludible; (2) `/rest/admin/application-version` público → fingerprinting; (3) MD5 sin sal; (4) `eval` en `userProfile.ts` (fuera de alcance, documentado como baseline). |

### 4.4 «Soy experto en DevOps»
| Pregunta | Respuesta |
|---|---|
| ¿Por qué SAST bloqueante y SCA no? | El SAST se limita a la regla de inyección, que **no tiene falsos positivos** en este código y **bloquea** el despliegue. El SCA sí tiene hallazgos porque Juice Shop **fija a propósito** dependencias antiguas: en un producto real sería bloqueante con un **baseline de excepciones aprobadas por el CISO**. |
| ¿Cómo se despliega un cambio? | PR → `sast` → `sca` → `secrets-iac` → `container` (build + Trivy + `cosign` sign) → `deploy` con `--no-traffic --tag canary`, smoke test + ZAP, y `update-traffic --to-latest`. Rollback = mover el tráfico a la revisión anterior. |
| ¿Qué pasa si alguien hace *push* directo? | El pipeline corre igual en `push` a `master`; y el despliegue exige `environment: production` con aprobación manual. Además la imagen se firma con `cosign` y Cloud Run podría exigir la firma (Binary Authorization). |
| ¿Cómo manejan secretos? | Secret Manager montado con `--set-secrets`, con una *service account* de runtime sin roles de proyecto (verificado con `get-iam-policy`: no tiene bindings). |
| ¿Métricas DORA? | Frecuencia de despliegue: varias/día (Cloud Run + canary). *Lead time*: < 1 día. *Change failure rate*: objetivo < 15 % (canary + rollback automático). *MTTR*: < 30 min. |
| ¿Todo esto cabe en el presupuesto del pipeline? | Semgrep, Trivy, Checkov, Gitleaks y cosign son OSS. El costo marginal del CI son minutos de *runner*; Cloud Build da 120 min/día gratis. |

### 4.5 «Soy el gerente que se preocupa por el presupuesto y no sé nada técnico»
| Pregunta | Respuesta |
|---|---|
| En una frase: ¿qué tan grave era? | **9,1 de 10.** Cualquier persona en Internet podía entrar como administrador y descargarse todas las cuentas y contraseñas. |
| ¿Cuánto cuesta arreglarlo? | El arreglo del código es **0 USD**: son 48 líneas y lo hace el propio equipo en un día. |
| ¿Y cuánto cuesta la protección alrededor? | **26 USD/mes (≈ 316 USD/año)** para el núcleo que bloquea el ataque sin tocar el código (balanceador + WAF + control de identidad). El paquete completo con base de datos gestionada y monitoreo: **140 USD/mes (≈ 1 675 USD/año)**. |
| ¿Eso es caro? | El costo medio de una brecha de datos es **4,44 M USD** (IBM 2025). El control completo cuesta el **0,04 %** de eso. Y no toda la plataforma es nueva: la base de datos gestionada y el monitoreo se pueden diferir. |
| ¿Por qué necesito el paquete completo si el de 26 USD ya bloquea el ataque? | Porque el de 26 USD evita el ataque conocido, pero **no** protege los datos detrás: sin base de datos gestionada no hay respaldo con recuperación a un punto en el tiempo ni cifrado con llave propia, y sin monitoreo usted se entera de la brecha por la prensa. |
| ¿Cómo justifico el gasto ante la junta? | Con tres números: riesgo materializado (brecha promedio 4,44 M USD), costo del control (1,7 mil USD/año) y evidencia de cumplimiento (**ISO 27001 A.8.28**, OWASP ASVS) que se traduce en menos hallazgos de auditoría y en requisitos de clientes. |
| ¿Esto se puede replicar en la empresa? | Sí: la arquitectura usa servicios gestionados estándar y el pipeline es 100 % OSS; la política POL-SEC-DEV-01 es el documento que se firma. |
| ¿Cuánto tiempo toma implementarlo? | Semana 1–2: parche + política. Semana 3–4: pipeline con gate. Mes 2: WAF + IAP. Mes 3: base de datos gestionada y SIEM. |

---

## 5. Errores que hay que evitar en la sustentación

1. **No leer las diapositivas.** Cada diapositiva tiene una idea; el resto lo dice la voz.
2. **No prometer lo que no está hecho.** Si algo es propuesta (Cloud SQL, KMS, IAP), decir **«propuesta»**; lo ejecutado (parche, WAF, gate, detector, política WAF en GCP) está demostrado.
3. **No decir «la IA lo hizo».** Decir qué se probó, qué falló y cómo se corrigió: eso demuestra autoría.
4. **No decir «el WAF soluciona la vulnerabilidad».** El WAF **mitiga**; el código es lo que corrige.
5. **Respetar el tiempo.** A los 30:00 se corta. Si van retrasados, el bloque recortable es el detalle de costos (diapositiva 20) y el de SAMM (diapositiva 28).

---

## 6. Lista de verificación (5 minutos antes)

- [ ] `./DEMO.sh --setup` → `:3000`, `:3001` y `:8090` responden 200
- [ ] `git worktree add /tmp/gate-vuln HEAD` creado en `juice-shop`
- [ ] `deliverables/presentacion/index.html` abierto en pantalla completa
- [ ] PDF de respaldo abierto (por si falla el proyector o el navegador)
- [ ] Terminal con fuente grande y fondo oscuro, historial limpio
- [ ] Carpeta `evidencias/` abierta en el explorador de archivos
- [ ] Consola de GCP con `juice-shop-si3006` y Cloud Logging
- [ ] Cronómetro visible · uno del equipo hace de *timekeeper*
- [ ] Todos saben quién habla en cada bloque (§1)
