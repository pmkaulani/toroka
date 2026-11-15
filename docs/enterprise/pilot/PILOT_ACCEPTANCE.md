# Toroka Enterprise — Bank Pilot Acceptance & Sign-off Framework

## 1. Acceptance Scope & Criteria

This acceptance document establishes the formal gateway criteria required before Toroka Enterprise can be authorized for operation within the institution's pilot environment.

All evaluations must be performed using synthetic or de-identified bank test data.

---

## 2. Institutional Sign-off Workstreams

### Workstream 1: Information Security & Cryptography (CISO / InfoSec)
- [ ] Network segmentation verified: Enterprise API cannot connect to `vault-db`.
- [ ] Envelope encryption and AAD binding verified with bank KMS adapter.
- [ ] Non-root container runtime verified (`UID 10001`).
- [ ] Ingress security headers, CSP, and CORS restrictions verified.
- [ ] Emergency reveal kill switch verified operational.
- **Status**: `PENDING BANK PILOT REVIEW`

### Workstream 2: Identity & Access Management (IAM / IdP)
- [ ] Bank OIDC provider integrated (RS256 / ES256).
- [ ] Maker-Checker dual authorization verified: self-approval blocked.
- [ ] Role mapping configured for `investigator`, `authoriser`, `auditor`, `data_steward`, and `system_administrator`.
- **Status**: `PENDING BANK PILOT REVIEW`

### Workstream 3: Data Governance & Data Integration (Data Stewards)
- [ ] Data Contract v2.0.0 specifications reviewed and validated.
- [ ] Missing feed / field detection and readiness indicators confirmed.
- [ ] Redacted ingestion boundaries verified: no customer account numbers or unmasked staff PII in telemetry.
- **Status**: `PENDING BANK PILOT REVIEW`

### Workstream 4: Fraud Investigations Operations (Internal Fraud / Forensics)
- [ ] Investigator workbench usability, case assignment, and note ledger confirmed.
- [ ] Case closure maker-checker proposal and review workflow verified.
- [ ] Ephemeral identity unmasking confirmed: plaintext purged upon modal close.
- **Status**: `PENDING BANK PILOT REVIEW`

### Workstream 5: Internal Audit & Compliance (Audit Committee / Inspection)
- [ ] Tamper-evident SHA-256 hash chain verified from genesis.
- [ ] Independent signed checkpoint export to WORM storage validated.
- [ ] Full audit log access and timeline review confirmed.
- **Status**: `PENDING BANK PILOT REVIEW`

---

## 3. Formal Pilot Authorization Sign-off Table

| Institutional Role | Representative Name | Department / Title | Decision (Approved / Rejected) | Date | Signature |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Chief Information Security Officer** | | Information Security | | | |
| **Head of Fraud & Financial Crime** | | Forensic Investigations | | | |
| **Head of Enterprise Architecture / IT** | | Technology Operations | | | |
| **Chief Data Officer / Steward** | | Data Governance | | | |
| **Head of Internal Audit** | | Internal Audit | | | |
