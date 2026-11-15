# Toroka Enterprise — Security Test Evidence & Verification Records
**Phase 3.4 Security Hardening Verification**
**Date of Execution**: 15 November 2026
**Target Repository**: `pmkaulani/toroka`

---

## 1. Test Execution Summary

| Test Suite / Target | Command Executed | Tests Run | Result | Duration |
| :--- | :--- | :--- | :--- | :--- |
| **Enterprise API Hardening & Persistence** | `uv run pytest services/enterprise_api/tests -q` | 76 | **76 PASSED (100%)** | 11.01s |
| **Isolated Identity Vault Service** | `uv run pytest services/identity_vault/tests -q` | 5 | **5 PASSED (100%)** | 7.39s |
| **Enterprise Investigation Engine** | `uv run pytest packages/enterprise/tests -q` | 82 | **82 PASSED (100%)** | 134.91s |
| **Core Utilities & Cryptography** | `uv run pytest packages/core/tests -q` | 16 | **16 PASSED (100%)** | 3.18s |
| **Consumer Toroka API (Regression check)** | `uv run pytest services/api/tests -q` | 626 | **626 PASSED (100%)** | 165.29s |
| **Total Automated Tests** | | **805** | **805 PASSED (100%)** | |

---

## 2. Specific Security Hardening Verification Details

### 2.1 Production Configuration & Policy Validation (`test_production_hardening.py`)
- `test_production_rejects_development_auth`: **PASSED**. Confirmed that `TOROKA_ENT_AUTH_MODE=development` raises `RuntimeError` when `TOROKA_ENT_ENV=production`.
- `test_production_rejects_raw_vault_key`: **PASSED**. Confirmed that passing a raw Fernet key to the Enterprise API in production raises `RuntimeError("Production must not use a raw Fernet key inside the Enterprise API")`.
- `test_production_requires_https_cors_origins`: **PASSED**. Confirmed that HTTP or wildcard CORS origins are rejected in production.
- `test_production_requires_vault_service_url`: **PASSED**. Confirmed that production fails closed if `TOROKA_ENT_VAULT_SERVICE_URL` is omitted.
- `test_production_requires_expected_schema_revision`: **PASSED**. Confirmed that unverified database migration status blocks startup in production.
- `test_production_requires_postgresql`: **PASSED**. Confirmed that SQLite persistence is blocked in production.

### 2.2 Network & Browser Security Protections (`test_production_hardening.py`)
- `test_security_headers_and_csp`: **PASSED**. Verified presence of:
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer`
  - `Cache-Control: no-store`
  - `X-Frame-Options: DENY`
  - `Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none';`
- `test_correlation_id_validation_and_sanitization`: **PASSED**. Verified that invalid characters or potential injection payloads in `X-Correlation-ID` are sanitized to a clean UUID.
- `test_payload_too_large_rejection`: **PASSED**. Verified that requests exceeding 10MB receive `HTTP 413 Payload Too Large`.
- `test_rate_limiting_on_sensitive_consume`: **PASSED**. Verified that exceeding 20 requests per minute on `/reveal-requests/.../consume` receives `HTTP 429 Too Many Requests`.

### 2.3 Identity Vault Isolation & Envelope Encryption (`test_vault_service.py`)
- `test_envelope_encryption_roundtrip`: **PASSED**. Verified 256-bit AES-GCM envelope encryption and unwrap.
- `test_envelope_encryption_fails_on_aad_mismatch`: **PASSED**. Verified that altering `installation_id` or `pseudonym` in AAD causes decryption failure.
- `test_vault_internal_service_authentication_required`: **PASSED**. Confirmed missing or invalid `X-Internal-Service-Token` returns `HTTP 401 / 422`.
- `test_vault_store_and_consume_end_to_end`: **PASSED**. Stored mapping, successfully consumed with matching installation, and verified that mismatched installation scope returns `HTTP 404`.

### 2.4 Cryptographic Audit Checkpointing & Tamper Detection (`test_production_hardening.py`)
- `test_audit_checkpoint_signing_and_verification`: **PASSED**.
  - Generated HMAC-signed checkpoint from active audit head.
  - Successfully verified intact database against checkpoint.
  - Verified that immutable store prevents duplicate key overwrites (`FileExistsError`).
  - Intentionally altered a row in `enterprise_audit_records` (`event_hash = 'tampered_fake_hash_value'`); verified that `AuditCheckpointManager.verify_checkpoint` detects tampering immediately.

### 2.5 Enterprise Workbench Build Verification
- Command: `cd apps/enterprise-workbench && npm run build`
- Result: **0 errors, 0 warnings**.
  - TypeScript type-checking: clean.
  - Vite production bundle generated at `apps/enterprise-workbench/dist/`.
  - Static distribution successfully mounted in FastAPI application at `/workbench`.
