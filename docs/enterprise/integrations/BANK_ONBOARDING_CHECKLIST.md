# Toroka Enterprise — Bank Onboarding & Connectivity Checklist

## 1. Overview & Phased Deployment Plan

This checklist guides bank enterprise architecture, information security, and core banking teams through connecting a new bank environment to Toroka Enterprise.

---

## 2. Onboarding Phases

### Phase 1: Security & Network Clearances
- [ ] Establish network routes / firewall rules between Toroka instances and internal bank reporting replicas / API gateways.
- [ ] Configure TLS 1.3 / mTLS mutual authentication certificates.
- [ ] Populate domain allowlists in Toroka settings (`allowed_hosts`).
- [ ] Provision dedicated, read-only database service accounts with `SELECT` grants only on approved views.

### Phase 2: Feed Configuration & Field Mapping
- [ ] Map Core Banking transaction extract columns to `CanonicalTransactionRecord`.
- [ ] Map Active Directory / HR roster fields to `CanonicalStaffRecord`.
- [ ] Map CBS audit log entries to `CanonicalAuditLogRecord`.
- [ ] Verify handling of optional fields (`counter_party`, `narrative`, `posting_staff_ref`).

### Phase 3: Ingestion Verification in Sandbox
- [ ] Execute test batch sync of 1,000 transactions using `BankRestConnector` or `BankFileConnector`.
- [ ] Verify duplicate idempotency: Re-run identical batch and confirm `records_duplicates == 1000`.
- [ ] Test versioned correction: Alter one amount, re-ingest, and verify `records_corrected == 1`.
- [ ] Deliver signed test event and verify HMAC validation and replay acknowledgement.

### Phase 4: Data Quality & Scenario Certification
- [ ] Run `GET /api/enterprise/v1/integrations/quality` to inspect quality issues.
- [ ] Review scenario readiness matrix on Enterprise Workbench (`READY`, `DEGRADED`, `BLIND`).
- [ ] Execute reconciliation report and confirm `discrepancy == 0`.
- [ ] Sign off with bank Data Steward and Information Security Officer (CISO).
