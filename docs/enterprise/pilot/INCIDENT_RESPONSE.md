# Toroka Enterprise — Security Incident Response & Emergency Operations

## 1. Regulatory Context & Institutional Responsibility

> [!IMPORTANT]
> Under Central Bank of Kenya (CBK) cybersecurity guidelines and relevant regulatory frameworks, licensed financial institutions bear sole statutory responsibility for reporting material cybersecurity incidents and customer data compromises to the regulator and relevant authorities within stipulated timelines (e.g. within 2 hours of confirmation).
> 
> **Toroka Enterprise is investigative and security software; it does not submit regulatory reports, provide legal counsel, or substitute for the bank's statutory incident reporting obligations.**
> 
> This runbook defines software-level containment controls, forensic data preservation procedures, and emergency kill switches to assist the bank's Incident Response Team (IRT) and Chief Information Security Officer (CISO).

---

## 2. Emergency Reveal Kill Switch (Immediate Containment)

If unauthorized identity unmasking, credential compromise, or rogue investigator activity is suspected:

### Option A: Revoke Vault Service Authentication (Immediate Ingress Halt)
To immediately block **all** identity unmasking attempts across all instances:
```bash
# Invalidate the internal vault service token in secrets
echo "REVOKED_EMERGENCY_KILL_SWITCH" > /opt/toroka/secrets/vault_service_token.txt

# Force reload of identity-vault container
docker compose -f compose.enterprise.yaml restart identity-vault
```
*Effect*: All subsequent `/reveal-requests/{id}/consume` API calls return `HTTP 500 / 401 Identity Vault service unavailable`. All ordinary casework, notes, and evidence browsing remain intact.

### Option B: KMS Key Disable
In the bank's cloud KMS console, immediately **Disable** the Master KEK:
*Effect*: The vault cannot decrypt any data encryption keys. System fails closed; no plaintext identities can be retrieved by any user or administrator.

---

## 3. Incident Severity Triage Matrix

| Severity | Example Scenario | Immediate Action | Escalation |
| :--- | :--- | :--- | :--- |
| **Critical** | Cryptographic audit chain broken or altered | Trigger reveal kill switch. Isolate database. Take snapshot. | Bank CISO, Internal Audit, Legal |
| **Critical** | Unauthorized bulk reveal attempts | Trigger reveal kill switch. Terminate investigator OIDC session. | CISO, Fraud Operations Head |
| **High** | Privilege escalation in IdP group mapping | Revoke user token in IdP. Review all casework updated by user. | Identity Operations, Security Operations Center (SOC) |
| **Medium** | Rate limit spikes on sensitive endpoints | Block source IP at WAF. Inspect correlation IDs in logs. | Bank SOC / Network Engineering |

---

## 4. Forensic Evidence Preservation

Before restarting or restoring any system after a security event:
1. **Preserve Operational Database Snapshot**:
   ```bash
   pg_dump -U toroka_ent -d toroka_enterprise -F c -b -v -f /forensics/toroka_operational_snapshot_$(date +%s).dump
   ```
2. **Export and Sign Current Audit Chain Head**:
   ```bash
   # Export raw records and head verification proof
   curl -H "Authorization: Bearer $AUDITOR_TOKEN" \
     https://toroka.bank.internal/api/enterprise/v1/audit/verify > /forensics/audit_verification_proof.json
   ```
3. **Capture Container Logs with Correlation IDs**:
   ```bash
   docker logs enterprise-api > /forensics/enterprise_api_logs_$(date +%s).log
   docker logs identity-vault > /forensics/identity_vault_logs_$(date +%s).log
   ```
4. **Deliver Evidence to Bank Forensic Examiner**:
   Generate SHA-256 checksums of all forensic artefacts and transfer to secure bank custody.
