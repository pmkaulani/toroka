# Toroka Enterprise API & Workbench (Bank Pilot Operations Layer — Phase 3.3)

The Toroka Enterprise API is a standalone, bank-facing operations service that interfaces with the Toroka Enterprise investigation engine. It establishes a secure, bank-controlled identity and access boundary separate from the consumer Toroka application, backed by durable transactional persistence, an isolated identity vault, and a dedicated **Investigator & Authoriser Workbench** (`apps/enterprise-workbench`).

---

## 1. Architectural Separation

```
apps/
└── enterprise-workbench/      # Institutional React + TypeScript workbench (mounted at /workbench)
services/
├── api/                       # Consumer Toroka API (independent user model, sessions)
└── enterprise_api/            # Bank-facing Enterprise operations API
    ├── toroka_enterprise_api/
    │   ├── __init__.py
    │   ├── main.py            # App factory, static workbench mount, CORS, correlation ID & security headers
    │   ├── config.py          # EnterpriseSettings with strict validation (PostgreSQL in prod)
    │   ├── auth.py            # OIDC JWT signature, JWKS retrieval, development adapter
    │   ├── permissions.py     # Role model, casework principal adapter, maker-checker dual-approval
    │   ├── schemas.py         # Pydantic request/response models (closure, intake, overview, timeline)
    │   ├── dependencies.py    # Database session, vault, installation_id, and service dependencies
    │   ├── persistence/       # Operational persistence & isolated vault
    │   │   ├── database.py    # Engine and sessionmaker factory
    │   │   ├── models.py      # Operational models (Cases, Notes, Closure Proposals, Audit, Runs)
    │   │   ├── repositories.py# CaseRepository, ClosureProposalRepository, RevealRepository, RunRepository
    │   │   ├── audit.py       # Append-only hash chain audit log with allowlist filtering & verification
    │   │   └── vault.py       # Isolated VaultRecord, VaultCipher protocol, Fernet implementation
    │   ├── services/          # Transaction-owning application services
    │   │   ├── cases.py       # CaseService (assignments, notes, maker-checker closures, trusted intake)
    │   │   ├── reveals.py     # RevealService (row-locked dual approval & single-use consumption)
    │   │   └── runs.py        # RunService (manifest & result digest persistence, installation scoping)
    │   └── routers/
    │       ├── system.py      # /health/live, /health/ready, /me, /capabilities
    │       ├── contract.py    # /data-contract, /detectors
    │       ├── cases.py       # Casework, notes, intake & proposal endpoints
    │       ├── governance.py  # Maker-checker closure review, overview, case timeline, audit verification
    │       ├── reveals.py     # Identity reveal request, approval & consumption endpoints
    │       └── runs.py        # Manifest & run endpoints
    ├── migrations/            # Operational database Alembic migrations (001, 002)
    ├── vault_migrations/      # Dedicated Identity Vault Alembic migrations
    ├── alembic.ini            # Operational database migration configuration
    ├── vault_alembic.ini      # Identity Vault migration configuration
    └── tests/                 # Dedicated Enterprise API test suite (63 tests)
```

### Key Architectural Boundaries:
- **Zero Consumer Bleed**: Bank authentication and enterprise casework never share user records, databases, or session tokens with the consumer API.
- **Engine as Core Logic**: The underlying investigation engine (`toroka_enterprise`) remains the source of truth for all scenario detection, scoring, and data contracts.
- **Separated Identity Vault**: Plaintext identities are never stored in operational case tables. Pseudonym mappings are encrypted at rest with versioned keys and stored in an isolated database with its own connection credentials.
- **Fail-Closed Security**: In production mode, all endpoints require signed OIDC bearer tokens. SQLite is strictly forbidden in production; separate PostgreSQL instances are required for casework and the vault.

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
| `TOROKA_ENT_DATABASE_URL` | `sqlite:///./enterprise_operational.db` | Operational database connection string (PostgreSQL mandatory in production). |
| `TOROKA_ENT_VAULT_DATABASE_URL` | `sqlite:///./enterprise_vault.db` | Isolated Identity Vault database URL (PostgreSQL mandatory in production). |
| `TOROKA_ENT_VAULT_KEY` | `""` | Base64-encoded 32-byte encryption key for Identity Vault. |
| `TOROKA_ENT_VAULT_KEY_VERSION` | `v1` | Active vault encryption key version. |
| `TOROKA_ENT_INSTALLATION_ID` | `toroka-default-installation` | Bank installation identifier for audit chains and case partitioning. |

---

## 3. Database Migrations

Toroka Enterprise uses independent Alembic migration environments for operational persistence and the identity vault:

```bash
# 1. Migrate operational database (Cases, Notes, Reveals, Runs, Audit)
uv run alembic -c services/enterprise_api/alembic.ini upgrade head

# 2. Migrate separated Identity Vault database
uv run alembic -c services/enterprise_api/vault_alembic.ini upgrade head
```

---

## 4. Local Development Startup

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

---

## 5. Casework & Identity Reveal Operations

### A. Health & Readiness Probe
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8101/health/ready"
```
**Response:**
```json
{
  "status": "ready",
  "service": "toroka-enterprise-api",
  "persistence": "connected",
  "vault": "connected"
}
```

### B. List Assigned Cases
```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8101/api/enterprise/v1/cases" `
  -Headers @{ "X-Dev-User" = "demo.investigator"; "X-Dev-Roles" = "investigator" }
```

### C. Append Case Note (Append-Only)
```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8101/api/enterprise/v1/cases/<case_id>/notes" `
  -Method Post `
  -Headers @{ "X-Dev-User" = "demo.investigator"; "X-Dev-Roles" = "investigator" } `
  -Body (ConvertTo-Json @{ body = "Interviewed branch manager regarding suspense ledger override." }) `
  -ContentType "application/json"
```

### D. Request Identity Reveal
```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8101/api/enterprise/v1/cases/<case_id>/reveal-requests" `
  -Method Post `
  -Headers @{ "X-Dev-User" = "demo.investigator"; "X-Dev-Roles" = "investigator" } `
  -Body (ConvertTo-Json @{
    pseudonym = "STF-934dc54be9e3c4da0d31ff7ff04f055b"
    reason = "Escalating confirmed uninstructed contact redirection to Fraud Risk Committee."
    ttl_hours = 24
  }) `
  -ContentType "application/json"
```

### E. Dual-Approval (Authoriser Only)
Self-approval is cryptographically and logically blocked. An authoriser with a distinct subject ID must approve:
```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8101/api/enterprise/v1/reveal-requests/<request_id>/approve" `
  -Method Post `
  -Headers @{ "X-Dev-User" = "demo.authoriser"; "X-Dev-Roles" = "authoriser" }
```

### F. Single-Use Consumption (Original Requesting Investigator Only)
```powershell
Invoke-RestMethod `
  -Uri "http://127.0.0.1:8101/api/enterprise/v1/reveal-requests/<request_id>/consume" `
  -Method Post `
  -Headers @{ "X-Dev-User" = "demo.investigator"; "X-Dev-Roles" = "investigator" }
```
**Response:**
```json
{
  "request_id": "<request_id>",
  "pseudonym": "STF-934dc54be9e3c4da0d31ff7ff04f055b",
  "plaintext_identity": "EMP-04192",
  "consumed_at": "2026-11-15T20:00:00Z"
}
```
*Note: Any second attempt to consume the token returns HTTP 400 (`Reveal token has already been consumed`). The audit log records the consumption event without logging the plaintext identity.*
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

---

## 6. Investigator & Authoriser Workbench (Phase 3.3)

The Enterprise Workbench (`apps/enterprise-workbench`) provides an institutional banking frontend for authorized personnel:

- **Investigator Workspace**: View assigned cases, evaluate provenance digests, append immutable chronological notes, request single-use identity unmasking, and submit closure recommendations with documented alternatives.
- **Authoriser Workspace**: Maker-checker review queues for pending identity reveals and case closures. Dual-approval enforcement logically prevents self-approval.
- **Auditor Workspace**: Read-only access to case registers, chronological event timelines (`/cases/{id}/timeline`), and full cryptographic hash chain verification from Genesis to Head (`/audit/verify`).
- **Data Steward Workspace**: Visibility into Data Contract v2.0.0 feeds, fields, and the detector readiness matrix (READY / DEGRADED / BLOCKED). Technical data steward role is blocked (HTTP 403) from casework, identities, and notes.

### Running Workbench Locally:
```bash
# Run standalone Vite development server with proxy to API
cd apps/enterprise-workbench
npm run dev

# Or serve production build directly mounted at /workbench from Enterprise API
uv run uvicorn toroka_enterprise_api.main:create_app_from_env --factory --app-dir services/enterprise_api --port 8101
# Open http://127.0.0.1:8101/workbench/
```

