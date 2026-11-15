# Toroka Enterprise API (Bank Pilot Operations Layer — Phase 3.1)

The Toroka Enterprise API is a standalone, bank-facing operations service that interfaces with the Toroka Enterprise investigation engine. It establishes a secure, bank-controlled identity and access boundary separate from the consumer Toroka application.

---

## 1. Architectural Separation

```
services/
├── api/                       # Consumer Toroka API (independent user model, sessions)
└── enterprise_api/            # Bank-facing Enterprise operations API
    ├── toroka_enterprise_api/
    │   ├── __init__.py
    │   ├── main.py            # App factory, correlation ID & security headers middleware
    │   ├── config.py          # EnterpriseSettings with strict validation
    │   ├── auth.py            # OIDC JWT signature, JWKS retrieval, development adapter
    │   ├── permissions.py     # Role model, casework principal adapter, dual-approval
    │   └── routers/
    │       ├── system.py      # /health/live, /me, /capabilities
    │       └── contract.py    # /data-contract, /detectors
    └── tests/                 # Dedicated Enterprise API test suite (37 tests)
```

### Key Architectural Boundaries:
- **Zero Consumer Bleed**: Bank authentication and enterprise casework never share user records or session tokens with the consumer API.
- **Engine as Core Logic**: The underlying investigation engine (`toroka_enterprise`) remains the source of truth for all scenario detection, scoring, and data contracts.
- **Fail-Closed Security**: In production mode, all endpoints require signed OIDC bearer tokens. Development mode is strictly prohibited from running in production.

---

## 2. Configuration Reference

The service is configured via environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `TOROKA_ENT_ENV` | `development` | Environment name: `development`, `test`, or `production`. |
| `TOROKA_ENT_AUTH_MODE` | `oidc` | Authentication mode: `oidc` (mandatory in production) or `development`. |
| `TOROKA_ENT_OIDC_ISSUER` | `""` | Bank IDP issuer URL (e.g. `https://idp.bank.example.com`). |
| `TOROKA_ENT_OIDC_AUDIENCE` | `""` | Expected JWT audience (e.g. `toroka-enterprise-api`). |
| `TOROKA_ENT_OIDC_JWKS_URL` | `""` | Bank IDP JSON Web Key Set URL for key discovery and rotation. |
| `TOROKA_ENT_ROLE_CLAIM` | `groups` | Token claim containing group/role strings (e.g. `groups`, `roles`). |
| `TOROKA_ENT_OIDC_ALGORITHMS` | `RS256` | Supported JWT signing algorithms (e.g. `RS256`, `RS256,ES256`). |
| `TOROKA_ENT_ROLE_MAP_JSON` | `{}` | JSON map translating bank IDP group names to Toroka roles. |

### Valid Toroka Internal Roles:
- `investigator`: Reviews surfaced candidate focuses, inspects audit evidence, requests identity reveals.
- `authoriser`: Evaluates and dual-approves identity reveal requests.
- `auditor`: Reads append-only audit chains, verification logs, and system reports.
- `data_steward`: Validates data feeds, inspects data quality reports, reviews mapping.
- `system_administrator`: Manages service configuration and health; **cannot** override casework or reveal identities.

---

## 3. Local Development Startup

To run the Enterprise API locally in development mode:

### Windows (PowerShell):
```powershell
$env:TOROKA_ENT_ENV = "development"
$env:TOROKA_ENT_AUTH_MODE = "development"
uv run uvicorn toroka_enterprise_api.main:create_app_from_env `
  --factory `
  --app-dir services/enterprise_api `
  --host 127.0.0.1 `
  --port 8101
```

### Linux / macOS:
```bash
export TOROKA_ENT_ENV="development"
export TOROKA_ENT_AUTH_MODE="development"
uv run uvicorn toroka_enterprise_api.main:create_app_from_env \
  --factory \
  --app-dir services/enterprise_api \
  --host 127.0.0.1 \
  --port 8101
```

---

## 4. Querying Endpoints in Development

In `development` auth mode, requests originating from `127.0.0.1` (loopback) authenticate using development headers:

### A. Health Liveness (Public)
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8101/health/live"
```
**Response:**
```json
{
  "status": "alive",
  "service": "toroka-enterprise-api"
}
```

### B. Current Identity
```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8101/api/enterprise/v1/me" `
  -Headers @{
    "X-Dev-User" = "demo.investigator"
    "X-Dev-Roles" = "investigator"
  }
```
**Response:**
```json
{
  "subject": "demo.investigator",
  "roles": ["investigator"]
}
```

### C. Data Contract Specification & Fingerprint
```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8101/api/enterprise/v1/data-contract" `
  -Headers @{
    "X-Dev-User" = "demo.investigator"
    "X-Dev-Roles" = "investigator"
  }
```
**Response:**
```json
{
  "version": "2.0.0",
  "sha256": "3d2fa5df86a37dc1903b55ef3f4318819395842dcc8d901a931f7bed9c769c40",
  "contract": { ... }
}
```

### D. Canonical Detector Registry
```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8101/api/enterprise/v1/detectors" `
  -Headers @{
    "X-Dev-User" = "demo.investigator"
    "X-Dev-Roles" = "investigator"
  }
```

---

## 5. Bank Production Deployment (OIDC)

In production deployments:
1. Set `TOROKA_ENT_ENV=production` and `TOROKA_ENT_AUTH_MODE=oidc`.
2. Supply `TOROKA_ENT_OIDC_ISSUER`, `TOROKA_ENT_OIDC_AUDIENCE`, and `TOROKA_ENT_OIDC_JWKS_URL`.
3. Provide the group-to-role mapping in `TOROKA_ENT_ROLE_MAP_JSON`.
4. Callers must pass standard `Authorization: Bearer <JWT>` tokens.
5. All requests receive `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY`, and an `X-Correlation-ID`.
6. Interactive API documentation (`/docs`, `/redoc`) is disabled automatically.
