# Proyecto Operación Ciudadela

Sistema de pagos seguro basado en microservicios, diseñado aplicando los principios de la **Tríada CIA** (Confidencialidad, Integridad y Disponibilidad), **Mínimo Privilegio** y protección contra vulnerabilidades OWASP.

---

## Arquitectura

El proyecto tiene dos niveles:

```
proyecto-operacion-ciudadela/
│
├── docker-compose.yml          → Versión básica (desarrollo/pruebas)
├── database/init.sql           → Esquema base de datos
├── auth-service/               → Autenticación básica
├── transfer-service/           → Transferencias básicas
│
└── securepay-iac/              → Versión completa (producción)
    ├── api-gateway/            → Punto de entrada único
    ├── auth-service/           → Auth con bloqueo por fuerza bruta
    ├── transfer-service/       → Transferencias con integridad SHA-256
    ├── audit-logs/             → Trazabilidad de eventos
    ├── docker-compose.yml
    └── .env
```

### Diagrama de flujo

```
Cliente
  │
  ▼
[API Gateway :3000]  ←── JWT verification + Rate Limiting
  │
  ├──▶ [Auth Service :3001]      POST /auth/register, /auth/login
  │
  ├──▶ [Transfer Service :3002]  POST /transfer/create
  │         │                    GET  /transfer/balance
  │         │                    GET  /transfer/history
  │         │                    GET  /transfer/verify/:id
  │         └──▶ [Audit Logs :3003]
  │
  └──▶ [Audit Logs :3003]        GET /audit/logs  (solo admin)
            │
            ▼
       [PostgreSQL]  ←── Red interna Docker (no expuesta)
```

---

## Principios de Seguridad Implementados

### Tríada CIA

| Principio | Implementación |
|---|---|
| **Confidencialidad** | JWT en cada petición · Cuentas aisladas por usuario · Red Docker interna sin exposición de la BD |
| **Integridad** | Hash SHA-256 por transferencia · Transacciones atómicas `BEGIN/COMMIT/ROLLBACK` · Comparación en tiempo constante (`timingSafeEqual`) · Consultas parametrizadas (Anti-SQLi) |
| **Disponibilidad** | Rate limiting (100 req/15 min global, 10 req/15 min en auth) · Health checks en todos los servicios · Reintentos Docker · Bloqueo de cuenta tras 5 intentos fallidos |

### Mínimo Privilegio

Cada microservicio usa su propio usuario de PostgreSQL con permisos restringidos:

| Usuario BD | Servicio | Permisos |
|---|---|---|
| `auth_svc` | auth-service | `SELECT, INSERT, UPDATE` en `users`, `accounts` |
| `transfer_svc` | transfer-service | `SELECT, UPDATE` en `accounts` · `SELECT, INSERT, UPDATE` en `transfers` |
| `audit_svc` | audit-logs | `SELECT, INSERT` en `audit_logs` |

Los contenedores Docker también corren con usuario no-root.

### Anti-Inyección SQL

Todas las consultas usan parámetros posicionales (`$1, $2...`) con `node-postgres`. No existe concatenación de strings en ninguna query.

---

## Tecnologías

- **Runtime:** Node.js 20 + Express 4
- **Base de datos:** PostgreSQL 16
- **Autenticación:** JWT (`jsonwebtoken`) + bcrypt
- **Seguridad HTTP:** Helmet · CORS · Rate Limiting (`express-rate-limit`)
- **Proxy:** `http-proxy-middleware`
- **Validación:** `express-validator`
- **Contenedores:** Docker + Docker Compose

---

## Puesta en marcha

### Requisitos

- Docker >= 24
- Docker Compose >= 2.20

### Versión básica (raíz)

```bash
docker compose up --build
```

Servicios disponibles:

| Servicio | URL |
|---|---|
| Auth Service | http://localhost:3001 |
| Transfer Service | http://localhost:3002 |

### Versión completa con IAC (recomendada)

```bash
cd securepay-iac
docker compose up --build
```

Un único punto de entrada:

| Gateway | URL |
|---|---|
| API Gateway | http://localhost:3000 |

---

## Endpoints de la API

> Todos los endpoints pasan por el API Gateway en `http://localhost:3000`

### Autenticación

| Método | Ruta | Descripción | Auth |
|---|---|---|---|
| `POST` | `/auth/register` | Registrar usuario | No |
| `POST` | `/auth/login` | Iniciar sesión, obtener JWT | No |
| `GET` | `/auth/profile` | Ver perfil y cuenta | JWT |

#### Registro

```bash
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com","password":"Alice1234"}'
```

#### Login

```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.com","password":"Alice1234"}'
```

### Transferencias

> Requieren cabecera `Authorization: Bearer <token>`

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/transfer/balance` | Consultar saldo |
| `POST` | `/transfer/create` | Realizar transferencia |
| `GET` | `/transfer/history` | Historial de movimientos |
| `GET` | `/transfer/verify/:id` | Verificar integridad de una transferencia |

#### Crear transferencia

```bash
curl -X POST http://localhost:3000/transfer/create \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"toAccountNumber":"ACC-1234567890","amount":100.00,"description":"Pago cuota"}'
```

#### Verificar integridad

```bash
curl http://localhost:3000/transfer/verify/1 \
  -H "Authorization: Bearer <token>"
```

Respuesta cuando la integridad es válida:

```json
{
  "transferId": 1,
  "status": "completed",
  "integrityOk": true,
  "message": "La transferencia no ha sido manipulada."
}
```

### Auditoría (solo admin/auditor)

| Método | Ruta | Descripción |
|---|---|---|
| `GET` | `/audit/logs` | Listar eventos con filtros |
| `GET` | `/audit/logs/stats` | Estadísticas por severidad |

```bash
curl "http://localhost:3000/audit/logs?severity=ERROR&limit=20" \
  -H "Authorization: Bearer <token-admin>"
```

---

## Variables de entorno

El archivo `securepay-iac/.env` contiene todos los secretos. **No subir al repositorio en producción.**

| Variable | Descripción |
|---|---|
| `POSTGRES_USER` | Usuario administrador de PostgreSQL |
| `POSTGRES_PASSWORD` | Contraseña de PostgreSQL |
| `POSTGRES_DB` | Nombre de la base de datos |
| `JWT_SECRET` | Clave secreta para firmar los tokens JWT |
| `JWT_EXPIRES_IN` | Tiempo de expiración del JWT (ej. `1h`) |
| `RATE_LIMIT_MAX_REQUESTS` | Máximo de peticiones por ventana de tiempo |

---

## Estructura de la base de datos

```
users          → Identidades y roles
accounts       → Cuentas bancarias (1 por usuario)
transfers      → Registro inmutable de movimientos + integrity_hash
audit_logs     → Trazabilidad completa de eventos del sistema
```

---

## Credenciales de prueba (admin por defecto)

| Campo | Valor |
|---|---|
| Email | `admin@securepay.local` |
| Password | `Admin1234!` |
| Rol | `admin` |
