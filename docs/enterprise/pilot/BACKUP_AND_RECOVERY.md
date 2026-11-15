# Toroka Enterprise — Backup, Restoration & Disaster Recovery

## 1. Scope of Protected Data

| Data Component | System of Record | Encryption at Rest | Backup Method |
| :--- | :--- | :--- | :--- |
| **Casework & Runs** | Operational PostgreSQL | Encrypted Volume / pg_dump | Scheduled pg_basebackup + WAL archiving |
| **Audit Ledger** | Operational PostgreSQL | Encrypted Volume | Continuous WAL archiving + signed external checkpoints |
| **Audit Anchors** | Immutable Object Storage (WORM) | S3-SSE-KMS / WORM lock | Cloud replication to secondary region |
| **Identity Mappings** | Vault PostgreSQL | Envelope Encryption (AES-GCM) | Encrypted logical backup with separate credentials |
| **Secrets & Keys** | Bank KMS / Secrets Store | Bank HSM | Native KMS multi-region key replication |

---

## 2. Institutional RPO & RTO Targets (Agreed with Bank)

> [!NOTE]
> Recovery Point Objective (RPO) and Recovery Time Objective (RTO) must be configured in accordance with the institution's business continuity policy.
> - **Recommended Target RPO**: ≤ 15 minutes (via continuous WAL archiving).
> - **Recommended Target RTO**: ≤ 2 hours (via automated container redeployment and DB restore).

---

## 3. Coordinated Restoration Procedure

> [!CAUTION]
> Operational casework and Identity Vault records must be restored with temporal consistency.
> If Operational DB is restored to 14:00 and Vault DB is restored to 12:00, reveal requests approved between 12:00 and 14:00 may reference missing vault records.

### 3.1 Step-by-Step Restoration Order
1. **Stop Application Containers**:
   ```bash
   docker compose -f compose.enterprise.yaml stop enterprise-api identity-vault
   ```
2. **Restore PostgreSQL Instances**:
   - Restore Vault DB to timestamp `T_restore`.
   - Restore Operational DB to the identical timestamp `T_restore`.
3. **Verify Database Consistency & Revisions**:
   ```bash
   # Run schema compatibility check
   alembic -c services/enterprise_api/alembic.ini current
   ```
4. **Run Audit Integrity Verification**:
   - Verify that the internal audit hash chain is unbroken up to the restore point:
     ```python
     is_valid, current_hash, count = verify_audit_chain(db, installation_id)
     assert is_valid is True
     ```
   - Verify the database chain against the latest external signed checkpoint from WORM storage (`AuditCheckpointManager.verify_checkpoint`).
5. **Cross-Database Reveal Reconciliation**:
   - Query all `used` reveal requests in `enterprise_reveal_requests`.
   - Verify that each pseudonym exists in `enterprise_identity_vault`.
   - If any discrepancy is found, mark those requests `suspended_discrepancy` before resuming service.
6. **Start Application Services**:
   ```bash
   docker compose -f compose.enterprise.yaml up -d
   ```
7. **Perform Health & Readiness Check**:
   ```bash
   curl -f https://toroka.bank.internal/health/ready
   ```
