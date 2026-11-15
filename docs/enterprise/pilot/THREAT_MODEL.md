# Toroka Enterprise — Threat Model & Security Architecture

## 1. Protected Institutional Assets

1. **Staff Real Identities (HR PII)**: Real names, employee numbers, and payroll destination accounts.
2. **Investigation Findings & Evidence**: Redacted ledger transactions, suspicious communications, and scenario indicators.
3. **Casework Deliberations**: Investigator working notes, hypothesis records, and case closure justifications.
4. **Audit Integrity**: Cryptographic chain of custody recording all case activities, intake actions, and identity unmaskings.
5. **Cryptographic Material**: Bank KMS Key Encryption Keys (KEKs), service authentication tokens, and OIDC signing trust stores.

---

## 2. Threat Actors & Capability Profiles

| Actor | Profile | Motive | Potential Vector |
| :--- | :--- | :--- | :--- |
| **Rogue Investigator** | Authorized bank employee with investigator role | Stalking colleagues, unmasking insiders prematurely, deleting case records | Attempting self-approval, replaying reveal tokens, unauthorized API calls |
| **Compromised Authoriser** | Authorized bank supervisor with authoriser role | Collusion with insider target, approving arbitrary reveals | Approving unfounded reveal requests without investigator initiation |
| **Privileged Database Admin** | Sysadmin with direct access to PostgreSQL operational DB | Tampering with audit logs, dropping case history to conceal fraud | Updating audit record rows, modifying sequence numbers |
| **Internal Lateral Mover** | Network attacker on internal bank LAN | Lateral expansion, eavesdropping, identity harvest | Sniffing internal traffic, attacking vault database directly |
| **External Attacker** | Internet-facing adversary probing perimeter | Ransomware, data breach, extortion | Ingress exploitation, CORS exploitation, brute-force |

---

## 3. Threat Matrix & Countermeasure Architecture

### 3.1 Rogue Investigator Unmasking Colleagues (Maker-Checker Breach)
- **Threat**: An investigator attempts to unmask a staff member's identity without supervisory oversight or tries to approve their own reveal request.
- **Mitigation**:
  - Enforced server-side in `toroka_enterprise_api.permissions.assert_dual_approval`.
  - Self-approval is unconditionally rejected, even if an individual holds both `investigator` and `authoriser` group memberships in the bank IdP.
  - Reveal request requires minimum 10-character written justification.
  - Single-use consumption: token status transitions atomically from `approved` to `used`.

### 3.2 Database Administrator Log Alteration (Tamper-Evidence Breach)
- **Threat**: A DBA modifies `enterprise_audit_records` to alter an investigator's actions or delete evidence of an unmasking.
- **Mitigation**:
  - Each audit record is cryptographically linked to the previous record's SHA-256 hash.
  - Independent periodic checkpoints are signed with a bank KMS signing key and written to immutable WORM storage via `AuditCheckpointManager`.
  - Modification of any record breaks the verification sequence against external signed checkpoints.

### 3.3 Direct Identity Vault Compromise & Plaintext Harvesting
- **Threat**: An attacker breaches the Enterprise API process and attempts to dump the entire database of real employee identities.
- **Mitigation**:
  - Process & network isolation: The Enterprise API has **no database credentials** and **no network connectivity** to `vault-db`.
  - The Identity Vault Service does **not** expose a `/decrypt` or bulk dump endpoint; it only supports single-pseudonym resolution for an approved, unconsumed reveal ID.
  - Mappings are protected with Envelope Encryption (AES-256-GCM) with AAD binding.
  - Even if raw ciphertext in `vault-db` is stolen, it cannot be decrypted without real-time KMS unwrap authorization.

### 3.4 Cross-Tenant / Cross-Installation Data Bleed
- **Threat**: In an environment hosting multiple installations or environments, data from Installation A is accessed by Installation B.
- **Mitigation**:
  - `installation_id` is required and enforced on every repository query, audit head, and vault mapping.
  - AES-GCM Authenticated Additional Data (`AAD`) binds ciphertext to `f"{installation_id}:{pseudonym}"`. Decrypting a ciphertext under a different installation ID results in an immediate authentication tag verification failure.

---

## 4. Residual Risks & Bank Responsibilities

1. **Bank Ingress & TLS Enforcement**: HSTS and mTLS must be enforced at the bank's reverse proxy/WAF.
2. **KMS Policy & Key Access Auditing**: The bank must restrict KMS key unwrap permissions strictly to the `identity-vault` container execution role and monitor KMS CloudTrail/audit logs for anomalous decrypt spikes.
3. **WORM Storage Immutability Policy**: The bank infrastructure team must configure object lock / retention policies on the external audit bucket to prevent administrator deletion.
