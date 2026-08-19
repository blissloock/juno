# 🛰️ Juno — Plataforma de Monitoreo de Redes con Dashboard en la Nube



Juno es una plataforma ligera de monitoreo de infraestructura de red. Recolecta tráfico **NetFlow** (v5/v9/IPFIX), métricas **SNMP** (CPU/RAM de hosts Linux y equipos Cisco), realiza **escaneos y descubrimiento de red con Nmap**, prueba conectividad por **ping**, detecta anomalías con un **IDS ligero basado en entropía de Shannon**, y expone todo en un dashboard web con autenticación **JWT + Argon2id**.

Diseñado bajo la filosofía **KISS** (inspirada en Arch Linux): la menor cantidad de piezas móviles que resuelvan el problema, cada decisión de arquitectura documentada en el propio código para la defensa del proyecto.

---

## 📚 Índice

1. [Stack tecnológico](#-stack-tecnológico)
2. [Arquitectura](#-arquitectura)
3. [Requisitos previos](#-requisitos-previos)
4. [Instalación y arranque](#-instalación-y-arranque)
5. [Variables de entorno (.env)](#-variables-de-entorno-env)
6. [Crear el primer usuario administrador](#-crear-el-primer-usuario-administrador)
7. [Comandos de Docker más usados](#-comandos-de-docker-más-usados)
8. [Endpoints principales de la API](#-endpoints-principales-de-la-api)
9. [Exposición pública con Cloudflare Tunnel](#-exposición-pública-con-cloudflare-tunnel)
10. [Puertos utilizados](#-puertos-utilizados)
11. [Estructura del proyecto](#-estructura-del-proyecto)
12. [Notas de seguridad](#-notas-de-seguridad)
13. [Problemas conocidos / pendientes para la defensa](#-problemas-conocidos--pendientes-para-la-defensa)
14. [Solución de problemas comunes](#-solución-de-problemas-comunes)

---

## 🧱 Stack tecnológico

| Componente         | Tecnología                                                              |
|---------------------|--------------------------------------------------------------------------|
| Backend             | Rust + Actix-web                                                        |
| Base de datos       | PostgreSQL + extensión TimescaleDB (hypertables)                        |
| Frontend            | HTML / CSS / JavaScript vanilla, servido por Nginx                      |
| Autenticación       | JWT (`jsonwebtoken`) + hashing de contraseñas con Argon2id (`argon2`)   |
| Recolección de red  | NetFlow (parseo manual v5, `netflow_parser` para v9/IPFIX), SNMP (`snmp`), Nmap (subproceso + `quick-xml`), ping ICMP |
| Alertas             | SMTP de Gmail vía `lettre`                                              |
| Contenedores        | Docker + Docker Compose (build multi-stage con `cargo-chef`)            |
| Exposición pública  | Cloudflare Tunnel (`cloudflared`), empaquetado junto al frontend        |

---

## 🏗️ Arquitectura

```
┌─────────────┐        ┌──────────────────┐        ┌─────────────────────┐
│   Usuario   │ ─────▶ │ frontend (Nginx)  │ ─────▶ │ backend (Actix-web) │
│  (browser)  │        │  + cloudflared    │  HTTP  │       :8080         │
└─────────────┘        └──────────────────┘        └──────────┬──────────┘
                                                                │
                              UDP :2055 (NetFlow)               │
                    ┌────────────────────────────────────────────┘
                    ▼
        ┌────────────────────────────┐
        │  db (TimescaleDB/Postgres)  │
        │  - usuarios                 │
        │  - eventos (JSONB)          │
        │  - alertas                  │
        │  - dispositivos             │
        └────────────────────────────┘
```

- **`eventos`**: colección tipo documento (JSONB) para NetFlow / SNMP / Nmap — esquema flexible por tipo de evento, particionado por tiempo (hypertable).
- **`dispositivos`**: catálogo relacional pequeño con `UNIQUE(ip)`, es el "maestro" de qué equipos existen.
- **`usuarios`** y **`alertas`**: relacionales, por las mismas razones de integridad (ver comentarios en `migrations/`).

En producción, `app.juno-monitor.win` sirve el frontend y `api.juno-monitor.win` el backend, ambos a través del mismo túnel de Cloudflare.

---

## ✅ Requisitos previos

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (o Docker Engine + Docker Compose) — versión reciente, con soporte para `--platform=linux/amd64` si desarrollas en Apple Silicon (usa QEMU internamente).
- Git.
- (Opcional) Una cuenta de Gmail con **contraseña de aplicación** generada, si quieres que las alertas críticas lleguen por correo.
- (Opcional) Un dominio en Cloudflare + túnel configurado, si quieres exponer el proyecto a internet.

> **Nota para Apple Silicon (M1/M2/M3/M4):** el backend se compila y corre forzado a `linux/amd64` (ver `Dockerfile.backend` y `docker-compose.yml`), por lo que Docker Desktop usará emulación QEMU. Es normal que el primer build tarde varios minutos más que en x86 nativo.

---

## 🚀 Instalación y arranque

### 1. Clonar el repositorio

```bash
git clone https://github.com/blissloock/juno
cd juno
```

### 2. Configurar las variables de entorno

Copia el archivo de ejemplo y llena tus propios valores:

```bash
cp .env.example .env
```

Edita `.env` con tu editor favorito (ver la sección [Variables de entorno](#-variables-de-entorno-env) para el detalle de cada campo). **Nunca subas este archivo a git** — ya está incluido en `.gitignore`.

### 3. Levantar la infraestructura completa

```bash
docker compose up --build -d
```

Esto construye y levanta tres contenedores:

| Contenedor       | Servicio                                  |
|-------------------|--------------------------------------------|
| `juno_db`         | TimescaleDB / PostgreSQL                   |
| `juno_backend`     | API Rust (Actix-web) + sondas en background |
| `juno_frontend`    | Nginx sirviendo el dashboard + cloudflared |

Las migraciones SQL (`migrations/*.sql`) se aplican **automáticamente** al arrancar el backend — no hace falta correr nada a mano.

### 4. Verificar que todo esté arriba

```bash
docker compose ps
curl http://localhost:8080/health
```

Deberías ver `{"status":"ok"}`. Los servicios quedan disponibles en:

- **Frontend:** http://localhost
- **Backend API:** http://localhost:8080
- **Puerto NetFlow:** UDP 2055

### 5. Crear tu primer usuario administrador

El dashboard no sirve de nada sin una cuenta para entrar — ve la sección siguiente.

---

## 🔐 Variables de entorno (`.env`)

| Variable                              | Obligatoria | Descripción |
|----------------------------------------|:-----------:|-------------|
| `POSTGRES_DB`                          | ✅          | Nombre de la base de datos. |
| `POSTGRES_USER`                        | ✅          | Usuario de PostgreSQL. |
| `POSTGRES_PASSWORD`                    | ✅          | Contraseña de PostgreSQL — usa una fuerte, este contenedor queda expuesto en la red interna de Docker. |
| `GMAIL_USER`                           | ⛔ opcional | Cuenta de Gmail remitente de alertas críticas. |
| `GMAIL_PASS`                           | ⛔ opcional | **Contraseña de aplicación** de Google (no la contraseña normal de la cuenta — Gmail la rechaza si tienes verificación en dos pasos, que es lo recomendado). |
| `JWT_SECRET`                           | ✅          | Secreto para firmar los tokens de sesión. Genera uno con `openssl rand -hex 32`. Nunca lo reutilices entre entornos. |
| `FRONTEND_ORIGIN`                      | ✅          | Origen(es) permitido(s) por CORS. Acepta varios separados por coma, ej. `http://localhost,http://192.168.1.50`. **Debe coincidir EXACTO** con lo que el navegador reporta como origen (`http://localhost:80` ≠ `http://localhost`). |
| `NETFLOW_ENTROPIA_UMBRAL`              | ⛔ opcional | Umbral (en bits) de entropía de tráfico NetFlow para disparar una alerta de posible escaneo/anomalía. Default: `3.5`. |
| `NETFLOW_ENTROPIA_INTERVALO_SEGUNDOS`  | ⛔ opcional | Cada cuántos segundos se reevalúa la entropía. Default: `60`. |
| `ALERT_EMAIL_TO`                       | ⛔ opcional | Destinatario de las alertas críticas. Si se omite, se manda a `GMAIL_USER`. |
| `SNMP_HOSTS`                           | ⛔ opcional | Hosts a monitorear por SNMP, formato `host:community,host2:community2`. Ej: `192.168.1.1:public,192.168.2.2:public`. Si se omite, el monitor SNMP queda inactivo. |
| `SNMP_INTERVALO_SEGUNDOS`              | ⛔ opcional | Frecuencia del polling SNMP. Default: `30`. |
| `SNMP_AUTO_IDENTIFICAR`                | ⛔ opcional | `true`/`false`. Si está activo, usa `sysName`/`sysDescr` de SNMP para renombrar/reclasificar automáticamente los dispositivos ya registrados (⚠️ sobreescribe nombres puestos a mano). Default: `false`. |
| `NMAP_HOSTS`                           | ⛔ opcional | Hosts para el escáner Nmap periódico (además del escaneo bajo demanda desde el dashboard). Formato: `192.168.1.1,192.168.1.10`. |
| `NMAP_INTERVALO_SEGUNDOS`              | ⛔ opcional | Frecuencia del escáner periódico. Default: `300` (5 min). |
| `NETWORK_CIDR`                         | ⛔ opcional | Rango CIDR por defecto para el botón "Descubrir red" si no se especifica uno en la petición. |
| `PORT`                                 | ⛔ opcional | Puerto interno del backend. Default: `8080`. |

---

## 👤 Crear el primer usuario administrador

Crear usuarios **no es un endpoint HTTP a propósito** — es una operación sensible y se hace vía CLI para que solo alguien con acceso al servidor/contenedor pueda crear cuentas (ver comentarios en `src/bin/crear_admin.rs`).

### Dentro del contenedor ya construido (uso normal, recomendado)

```bash
docker compose exec backend ./crear_admin <username> <password> [rol]
```

Ejemplo:

```bash
docker compose exec backend ./crear_admin admin "MiPasswordSegura123!" admin
```

- `rol` es opcional y por defecto es `admin`. El otro rol válido es `lector` (solo lectura, sin permisos de crear/editar/eliminar dispositivos ni disparar escaneos).
- La contraseña debe tener al menos 8 caracteres (validación mínima del lado del CLI).
- La contraseña se guarda **hasheada con Argon2id**, nunca en texto plano.

### En desarrollo local (sin Docker, con `cargo` directo)

```bash
cargo run --bin crear_admin -- <username> <password> [rol]
```

Requiere que `DATABASE_URL` esté disponible en el entorno (o en un `.env` que cargue tu shell) y que la base de datos ya sea alcanzable.

### Crear un usuario lector

```bash
docker compose exec backend ./crear_admin lector1 "OtraPasswordSegura456!" lector
```

---

## 🐳 Comandos de Docker más usados

```bash
# Levantar todo (con reconstrucción de imágenes)
docker compose up --build -d

# Ver logs en vivo del backend (útil para depurar NetFlow/SNMP/Nmap)
docker compose logs -f backend

# Ver logs de todos los servicios
docker compose logs -f

# Apagar los contenedores SIN borrar datos de la base
docker compose down

# Apagar y BORRAR también los volúmenes (reinicio completo de la BD)
docker compose down -v

# Reconstruir solo el backend tras un cambio de código
docker compose up --build -d backend

# Reconstruir forzando recompilar (necesario tras cambiar variables
# baked-in como FRONTEND_ORIGIN en el frontend, --force-recreate no basta)
docker compose up --build -d

# Entrar a una shell dentro del contenedor del backend
docker compose exec backend sh

# Ver el estado / salud de los contenedores
docker compose ps
```

> ⚠️ **Nota importante:** si el volumen de la base de datos (`db_data`) ya se inicializó *antes* de que existiera tu `.env` (por ejemplo, si levantaste el proyecto sin haber copiado `.env.example` primero), Postgres **no vuelve a leer** `POSTGRES_USER`/`POSTGRES_PASSWORD` en arranques posteriores. Hay que limpiar el volumen para que tome los valores nuevos:
> ```bash
> docker compose down -v
> docker compose up --build -d
> ```

---

## 🔌 Endpoints principales de la API

Todos los endpoints bajo `/api/*` (excepto `/auth/login`) requieren el header:

```
Authorization: Bearer <token>
```

El token se obtiene desde `/auth/login`.

| Método | Ruta                                         | Rol requerido | Descripción |
|--------|-----------------------------------------------|----------------|-------------|
| GET    | `/health`                                     | —              | Chequeo de salud (BD incluida). |
| POST   | `/auth/login`                                 | —              | Login, regresa `{ token, rol }`. |
| GET    | `/api/perfil`                                 | cualquiera     | Datos del usuario autenticado. |
| GET    | `/api/eventos?tipo=&origen=&limite=`          | cualquiera     | Consulta la colección JSONB de eventos (NetFlow/SNMP/Nmap). |
| POST   | `/api/nmap/escanear`                          | admin          | Escaneo Nmap bajo demanda contra un host (`{ "host": "..." }`). |
| POST   | `/api/nmap/descubrir`                         | admin          | Descubrimiento de red por CIDR (`{ "red": "192.168.1.0/24" }`). |
| GET    | `/api/dispositivos`                           | cualquiera     | Lista el catálogo de dispositivos. |
| POST   | `/api/dispositivos`                           | admin          | Crea un dispositivo. |
| PUT    | `/api/dispositivos/{id}`                      | admin          | Edita un dispositivo. |
| DELETE | `/api/dispositivos/{id}`                      | admin          | Elimina un dispositivo. |
| POST   | `/api/dispositivos/eliminar-masivo`           | admin          | Elimina varios dispositivos por lote de IDs. |
| POST   | `/api/dispositivos/limpiar-inactivos`         | admin          | Elimina todos los dispositivos en estado `offline`. |
| POST   | `/api/dispositivos/{id}/ping`                 | cualquiera     | Ping real al dispositivo, actualiza su estado y genera alerta si cambió. |
| GET    | `/api/alertas`                                | cualquiera     | Historial de alertas (últimas 100). |
| GET    | `/api/netflow/grafica`                        | cualquiera     | Serie de tiempo, top hosts y entropía de tráfico NetFlow. |

---

## 🌐 Exposición pública con Cloudflare Tunnel

El frontend y el túnel corren en el **mismo contenedor** (`frontend/Dockerfile` + `frontend/entrypoint.sh`), así todo lo que da la cara al público viaja como una sola imagen portable.

1. Crea el túnel desde tu cuenta de Cloudflare (`cloudflared tunnel create juno`).
2. Coloca las credenciales generadas en `cloudflared/creds.json` (este archivo **no se sube a git**, ver `.gitignore`).
3. Edita `cloudflared/config.yml` con tu `<TUNNEL_ID>` real y tus hostnames:

```yaml
tunnel: <TUNNEL_ID>
credentials-file: /etc/cloudflared/creds.json

ingress:
  - hostname: app.tudominio.com
    service: http://localhost:80
  - hostname: api.tudominio.com
    service: http://backend:8080
  - service: http_status:404
```

4. Levanta el proyecto normalmente con `docker compose up --build -d`. Si `config.yml` y `creds.json` no están presentes todavía, el frontend sigue funcionando en local (puerto 80) sin túnel — no rompe el desarrollo.

En el proyecto actual, los dominios configurados son:

- Frontend: `https://app.juno-monitor.win`
- Backend: `https://api.juno-monitor.win`

---

## 🔢 Puertos utilizados

| Puerto      | Protocolo | Servicio                          |
|-------------|-----------|-------------------------------------|
| `80`        | TCP       | Frontend (Nginx)                    |
| `8080`      | TCP       | Backend API (Rust/Actix)            |
| `2055`      | UDP       | Sonda NetFlow (recepción de flujos) |
| `5432`      | TCP       | PostgreSQL/TimescaleDB (interno, no expuesto al host por defecto) |

---

## 📁 Estructura del proyecto

```
.
├── Cargo.toml / Cargo.lock        # Dependencias Rust
├── Dockerfile.backend             # Build multi-stage con cargo-chef
├── docker-compose.yml
├── .env.example
├── migrations/
│   ├── 0001_init.sql              # Esquema base (usuarios, alertas, tablas legadas)
│   ├── 0002_documentos_json.sql   # Migración a colección "eventos" (JSONB)
│   └── 0003_dispositivos.sql      # Catálogo relacional de dispositivos
├── src/
│   ├── main.rs                    # Rutas HTTP, arranque del servidor y de las sondas
│   ├── lib.rs                     # Exposición como librería (para src/bin/*)
│   ├── auth.rs                    # Argon2id + JWT + extractor de Actix
│   ├── db.rs                      # Acceso a datos (sqlx, consultas parametrizadas)
│   ├── netflow.rs                 # Sonda UDP NetFlow (v5 manual, v9/IPFIX vía crate)
│   ├── snmp.rs                    # Polling SNMP (Linux + Cisco)
│   ├── nmap.rs                    # Escaneo bajo demanda + descubrimiento de red
│   ├── ping.rs                    # Prueba de conectividad ICMP
│   ├── ids.rs                     # Detección de anomalías por entropía de tráfico
│   ├── alerts.rs                  # Registro de alertas + envío por correo (Gmail)
│   └── bin/
│       └── crear_admin.rs         # CLI para crear usuarios
├── frontend/
│   ├── Dockerfile                 # Nginx + cloudflared en la misma imagen
│   ├── entrypoint.sh
│   ├── index.html / style.css / script.js
└── cloudflared/
    └── config.yml                 # Configuración del túnel (creds.json NO se versiona)
```

---

## 🔒 Notas de seguridad

- Contraseñas hasheadas con **Argon2id** (ganador de la Password Hashing Competition), sal aleatoria por usuario.
- Sesión vía **JWT** con expiración de 8 horas (`EXP_HORAS` en `src/auth.rs`).
- Creación de usuarios **solo por CLI**, nunca por endpoint HTTP.
- **CORS restringido** por `FRONTEND_ORIGIN` — nunca se usa `Cors::permissive()`.
- Consultas SQL **100% parametrizadas** (`sqlx` con `.bind()`), sin concatenación de strings — previene inyección SQL.
- Contenedor del backend corre como usuario **no-root** (`appuser`).
- Límite de tamaño de body JSON (64 KB) para mitigar DoS por payloads gigantes.
- Cabeceras de seguridad estándar (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`).
- Rate limiting de intentos de login por IP (`rate_limit.rs`).
- El escaneo Nmap **no usa `-O` ni `-sS`** por defecto (requieren `NET_RAW`/`NET_ADMIN`, deshabilitadas en el contenedor) — usa TCP connect scan.

---

## ⚠️ Problemas conocidos / pendientes para la defensa

Documentados a propósito para ser honestos sobre el alcance del proyecto:

- El **JWT se guarda en `localStorage`** del navegador (trade-off reconocido, no `httpOnly cookie`).
- El **IDS usa un único umbral global** de entropía, no un umbral por host.
- **Sin pruebas unitarias/de integración** todavía (posible pendiente si da tiempo antes de la defensa).
- Los paquetes NetFlow **v9/IPFIX** se guardan como texto de `Debug` (no estructurados) por una limitación del crate `netflow_parser` v0.5.9, que no expone serialización para esos tipos. v5 sí queda completamente estructurado (parseo manual, ver `src/netflow.rs`).

---

## 🛠️ Solución de problemas comunes

**El backend no arranca / "GLIBC_2.XX not found"**
La imagen de ejecución (`debian:trixie-slim`) debe tener una glibc igual o más nueva que la imagen de compilación (`cargo-chef`). Si actualizas la versión de Rust en `Dockerfile.backend`, revisa que ambas etapas sigan siendo compatibles.

**CORS bloqueado en el navegador**
Revisa que `FRONTEND_ORIGIN` en `.env` coincida **exactamente** con el origen que reporta el navegador (incluyendo el puerto). `http://localhost` y `http://localhost:80` son orígenes distintos para el navegador.

**Cambié `.env` pero no se refleja**
Para el frontend, un simple `--force-recreate` no recompila nada horneado en la imagen; usa `docker compose up --build -d`. Para la base de datos, si el volumen ya se inicializó con credenciales viejas, hace falta `docker compose down -v`.

**No veo tráfico NetFlow**
Verifica que el router exportando NetFlow sea el que efectivamente enruta el tráfico (en una topología con dos routers, exporta desde el que hace el ruteo real, no desde uno intermedio). Tráfico entre hosts del mismo segmento/subred no genera registros NetFlow.

**SNMP no responde en un equipo Cisco**
Los OIDs de `UCD-SNMP-MIB` son específicos de Linux. Cisco IOS necesita `CISCO-PROCESS-MIB` / `CISCO-MEMORY-POOL-MIB` (ya contemplados con fallback en `src/snmp.rs`), además de tener SNMP habilitado y el `community` correcto configurado en el propio equipo.

---

*Universidad Politécnica de Texcoco · Proyecto Integrador II · Equipo Linux Monsters (5MTII1) · Profesora: Luna Becerril*
