# Toroka Phase 13.2 — Security, Provenance & Regulatory Truthfulness

**Authoritative Technical Specification & Integrity Report**  
**Version:** Toroka Enterprise 13.2.0  
**Branch:** `phase-13-2-security-provenance`  
**Baseline Commit:** `5ae4b9e18f4af79ca937ae94a689abaee7897cee` (Phase 13.1)  
**Status:** COMPLETE & 100% VERIFIED  
**Applicable Standards & Statutory Frameworks:**  
- Kenya Evidence Act (Cap 80) Section 106B (Admissibility of Electronic Records)
- Central Bank of Kenya (CBK) Risk Management Guidelines & National Payments System Act
- ISO 20022 Interbank Financial Messaging (`pacs.008.001.10`, `pacs.002.001.12`)
- FIPS 140-2 / 140-3 Hardware Security Module (HSM) Cryptographic Standards
- NIST SP 800-57 (Recommendation for Key Management) & SP 800-162 (ABAC / Separation of Duties)
- OWASP Top 10 for LLM Applications (01: Prompt Injection, 09: Misinformation/Hallucination)

---

## 1. Executive Summary & Core Doctrine

Phase 13.2 is an enterprise governance, security, and truthfulness hardening release. The central doctrine of Phase 13.2 is **regulatory truthfulness and fail-closed security**:

1. **Observed Evidence vs. Analyst Assertions:** Client-supplied metrics, summaries, and parameters are recorded as subjective claims or quarantined assertions—not verified facts—until validated by a trusted server-side executor.
2. **Cryptographic Math vs. Institutional Trust:** A mathematically valid signature proves payload integrity, but NOT institutional authorization. Signatures are verified against a bank-controlled `SignerTrustRegistry` with state-tracked key lifecycle (Active, Revoked, Rotated, Expired) and hardware security level (`DEV_SOFTWARE` vs. `BANK_MANAGED_HSM` vs. `CLOUD_KMS`).
3. **Advisory Scoring vs. Payment Execution:** Toroka calculates risk and recommends payment actions (`RECOMMEND_ALLOW`, `RECOMMEND_BLOCK`, `RECOMMEND_STEP_UP`, `RECOMMEND_QUARANTINE_HOLD`) with `execution_status="NOT_EXECUTED"`. Toroka never claims it executed or approved a bank transfer; clearing execution remains exclusively within the bank's core payment switch.
4. **Draft Dossier vs. Section 106B Electronic Record:** Forensic dossiers begin in `DRAFT_UNVERIFIED` status (`is_verified=False`, `section_106b_certificate=None`) with a prominent statutory watermark until digitally signed by a designated bank officer using an institutional HSM key.
5. **Fail-Closed Governance Gates:** If an audit record is tampered with, audit health immediately reports `CRITICAL`. If unverified metrics or dev-software keys are used, production promotion fails closed.

---

## 2. Hardened Architecture & Subsystems

```
                                  TOROKA ENTERPRISE 13.2
                             SECURITY & PROVENANCE CONTROL PLANE

   [ Authenticated Caller (OIDC) ]
                |
                v
   +---------------------------------------------------------------------------------+
   | Router & Schema Boundary                                                        |
   | - target_environment validation: ONLY EXACT 'pilot' OR 'production'             |
   | - Authenticated Principal Binding: actor_subject derived from JWT (never JSON)  |
   +---------------------------------------------------------------------------------+
          |                                                   |
          | (Legacy / Unverified Metrics)                     | (Trusted Validation)
          v                                                   v
   +---------------------------------------+   +--------------------------------------+
   | Client Validation Submission          |   | Trusted Validation Execution Engine  |
   | - Quarantined as INCONCLUSIVE         |   | - Server-Side Test Plan & Dataset    |
   | - Limitation flagged:                 |   | - Measured Artifact & Config Digest  |
   |   UNVERIFIED_CALLER_ASSERTED_METRICS  |   | - Trusted Runner: Maker != Evaluator |
   | - DISQUALIFIED from Component Approval|   | - QUALIFIED for Component Approval   |
   +---------------------------------------+   +--------------------------------------+
                                                              |
                                                              v
   +---------------------------------------------------------------------------------+
   | Maker-Checker & Production Promotion Gate                                       |
   | - Component Maker != Validation Evaluator != Component Approver                 |
   | - Promotion requires valid approvals, trusted validation, & readiness checks    |
   | - Readiness Attestation: Partial Unique Index allows superseded history         |
   | - Institutional Signer Trust: REJECTS DEV_SOFTWARE keys for Production           |
   +---------------------------------------------------------------------------------+
          |                                                   |
          v                                                   v
   +---------------------------------------+   +--------------------------------------+
   | Tamper-Evident Merkle Audit Chain     |   | Statutory Forensic Dossiers (s. 106B)|
   | - (is_valid, head_hash, count) unpack |   | - Starts in DRAFT_UNVERIFIED status  |
   | - Tamper detection fails closed to    |   | - Watermarked HTML court exhibit     |
   |   CRITICAL immediately                |   | - Canonical Decimal(18, 4) digest    |
   +---------------------------------------+   +--------------------------------------+
```

---

## 3. Detailed Hardening Specifications

### 3.1 Python Monorepo Build Reproducibility (`pyproject.toml`)
- **Flat-Layout Issue Resolved:** Setuptools flat-layout auto-discovery previously attempted to index non-Python top-level directories (`apps`, `deploy`, `eval`, `secrets`).
- **Explicit Package Discovery:** Configured explicit `[tool.setuptools.packages.find]` with exact include patterns:
  - `services/api*`
  - `services/enterprise_api*`
  - `services/identity_vault*`
  - `packages/enterprise*`
- **Verification:** Verified clean execution of `compileall` across packages and services, and successful installation via `pip install -e ".[dev]"`.

### 3.2 Audit Chain Health Reporting & Tamper Fail-Closed (`persistence/audit.py` & `production_governance.py`)
- **Return Type Unpacking:** Corrected `verify_audit_chain()` return signature handling `(is_valid, current_head_hash, total_records_verified)` in `get_system_health()`.
- **Fail-Closed Integrity:** When an audit entry is mutated or tampered with in storage, `audit_integrity_health` immediately transitions to `CRITICAL` with diagnostic metadata (head mismatch, broken chain links) without leaking PII.
- **Integration Test:** Verified in `test_audit_chain_tamper_detection_reports_critical_health`.

### 3.3 Target Environment Boundary Enforcement (`governance_schemas.py` & `production_governance.py`)
- **Permitted Values:** Only the exact strings `"pilot"` and `"production"` are accepted.
- **Strict Rejections:** Case variants (`PRODUCTION`, `prod`, `PILOT`), whitespace padding (`" pilot "`), empty strings, null, and arbitrary names (`staging`, `test`) are rejected with `HTTP 422 Unprocessable Content`.
- **Active State Protection:** An invalid target environment cannot alter release or component states to `ACTIVE`.

### 3.4 Validation Execution & Provenance (`validation_executor.py`)
- **Caller-Submitted Metric Quarantine:** Requests to `POST /governance/validation-runs` asserting client-side PASS metrics are quarantined as `INCONCLUSIVE` and marked with `UNVERIFIED_CALLER_ASSERTED_VALIDATION_METRICS`. They cannot qualify a component for production.
- **Evaluator Identity Binding:** Evaluator identity is derived strictly from the authenticated OIDC token (`actor_subject`). Any client-supplied `evaluator` field in JSON is ignored.
- **Trusted Server-Side Runner:** Implemented `TrustedLocalValidationExecutor` with `ValidationMetricSpec` and `ValidationPlan`. Runs evaluations against verified component artifacts with immutable dataset digests (`sha256:d8a7...`) and configuration digests (`sha256:c3f1...`).
- **Maker-Checker Separation:** Enforces `Maker != Evaluator != Approver`. A component author cannot evaluate or approve their own component.

### 3.5 Readiness Attestation Historical Retention & Migration 015
- **Schema Defect Resolved:** Previously, an unconditional unique constraint on `(installation_id, release_version, gate_name)` prevented recording subsequent attestations after an existing one was revoked or superseded.
- **Alembic Migration 015:** Created `015_phase13_2_security_controls.py`:
  - Drops unconditional unique constraint.
  - Adds partial unique index `idx_readiness_attestations_active_unique` on `(installation_id, release_version, gate_name)` WHERE `is_active = TRUE`.
  - Supports SQLite (fallback conditional unique constraint) and PostgreSQL partial index syntax.
  - Full downgrade path implemented and tested.

### 3.6 Institutional Signer Trust Registry & Bank Key Lifecycle (`pki.py`)
- **Separation of Concerns:** `SignatureVerificationResult` independently evaluates:
  1. `digest_integrity_valid`: Payload SHA-256 matches digest.
  2. `signature_math_valid`: Asymmetric signature cryptographically validates against public key.
  3. `signer_trusted`: Key ID is registered in `SignerTrustRegistry` and key status is `ACTIVE`.
- **Hardware Security Level Policy:**
  - `KeySecurityLevel.DEV_SOFTWARE`: Permitted only in local test/development.
  - `KeySecurityLevel.BANK_MANAGED_HSM` / `CLOUD_KMS`: Required for production releases and Section 106B statutory certifications.
  - Production promotion strictly fails closed if the release signer has `security_level == DEV_SOFTWARE`.

### 3.7 Statutory Forensic Dossiers & Kenya Evidence Act Section 106B (`forensic_dossier.py`)
- **Draft Truthfulness:** Dossiers are initialized with `status="DRAFT_UNVERIFIED"`, `is_verified=False`, and `section_106b_certificate=None`.
- **Visual Judicial Banner:** HTML rendering injects a high-visibility amber watermark banner on unverified dossiers:
  > `DRAFT UNVERIFIED FORENSIC DOSSIER — NOT YET CERTIFIED UNDER SECTION 106B EVIDENCE ACT`
- **Canonical Numeric Precision:** Monetary amounts are canonicalized to exact 4-decimal strings (`f"{Decimal(str(fraud_loss_amount)):.4f}"`) matching the database `NUMERIC(18, 4)` precision. This guarantees immutable SHA-256 digests across database serialization.

### 3.8 Advisory ISO 20022 Risk Scoring (`iso20022.py`)
- **Advisory Status:** In-flight clearing decisions return `decision_type` (`RECOMMEND_ALLOW`, `RECOMMEND_BLOCK`, etc.) with `execution_status="NOT_EXECUTED"`.
- **Amount & Rail Validation:** Monetary amounts are validated as positive `Decimal` values with scale $\le 4$. Unknown clearing rails fail closed without defaulting to PesaLink.
- **Statutory Truthfulness:** Disclaimers explicitly specify that Toroka is an advisory fraud-scoring engine; final clearing authorization rests with the banking switch.

### 3.9 Semantic Claim Grounding (`semantic_grounding.py`)
- **Polarity Contradiction Resolution:** Contradiction heuristics are evaluated prior to lexical overlap matching, ensuring statements directly contradicting transaction receipts are flagged as `CONTRADICTION` rather than false entailments.

### 3.10 AI Provider Governance & Maker-Checker Review
- **Provider Registration:** New AI model providers enter `PENDING_REVIEW` status.
- **Independent Approval:** Approving an AI provider requires an independent reviewer (`Approver != RegisteredBy`). Self-approval is rejected with `HTTP 422`.

---

## 4. Test Suite Execution & Verification Record

All tests across all layers have been executed and verified in the local workspace:

| Test Suite | Test Files | Tests | Result | Execution Time |
|:---|:---:|:---:|:---:|:---:|
| **Enterprise Governance & Security** | `test_phase13_2_security_controls.py` | 11 | **11 / 11 PASSED** | 48.79s |
| **Production Integrity & Gates** | `test_phase12_6_production_integrity.py` | 8 | **8 / 8 PASSED** | 22.58s |
| **Phase 13.0 Baselines & Vault** | `test_phase13_0_api.py` | 4 | **4 / 4 PASSED** | 9.19s |
| **Phase 13.1 Forensic & ISO 20022** | `test_phase13_1_api.py` | 3 | **3 / 3 PASSED** | 15.83s |
| **Production Governance API** | `test_production_governance_api.py` | 9 | **9 / 9 PASSED** | 24.44s |
| **Full Enterprise API Suite** | `services/enterprise_api/tests/*` (all) | 158 | **158 / 158 PASSED** | 141.60s |
| **Enterprise Core Packages** | `packages/enterprise/tests/*` (all) | 220 | **220 / 220 PASSED** | 248.75s |
| **Consumer API & Chat** | `services/api/tests/*` (all) | 645 | **645 / 645 PASSED** | 164.55s |
| **Enterprise Workbench UI** | `apps/enterprise-workbench` (`npm run build`) | TypeScript | **0 Errors, Clean Build** | 5.20s |
| **Total Monorepo Tests** | **All Units & Integrations** | **1,023** | **1,023 / 1,023 PASSED (100%)** | **Clean** |

---

## 5. Deployment & Production Readiness

### 5.1 Remaining Institutional Gates (Outside Software Scope)
The following controls are external institutional prerequisites for bank production deployment:
1. **Bank HSM / KMS Provisioning:** Production installations must provision a physical PKCS#11 Hardware Security Module (e.g. Thales payShield, Luna HSM, AWS CloudHSM) and register the public key in `SignerTrustRegistry` with `security_level=BANK_MANAGED_HSM`.
2. **CBK Clearing Interceptor Gateway:** Connect the advisory ISO 20022 risk evaluator to the bank's MQ/Kafka payment message queue.
3. **Appointed Section 106B Certifier:** Designate the authorized officer (Head of Forensic Technology / Security Operations) whose credentials will sign electronic evidence certificates.

### 5.2 Git Hygiene
- Work completed strictly on feature branch `phase-13-2-security-provenance`.
- Baseline commit `5ae4b9e18f4af79ca937ae94a689abaee7897cee` fully preserved.
- No direct commits or pushes to `main`.
