# Toroka Enterprise — Pilot Architecture & Deployment Model

## 1. Overview & Institutional Boundary

Toroka Enterprise is designed to deploy within a bank's controlled infrastructure as a dedicated single-tenant instance. It isolates insider financial-crime casework, investigative leads, Maker-Checker identity-unmasking workflows, and tamper-evident audit logs from public consumer networks and unauthorized internal staff.

```
                      +---------------------------------------+
                      |           Bank Users / Roles          |
                      |  Investigators, Authorisers, Auditors |
                      +---------------------------------------+
                                          |
                                          | HTTPS / mTLS
                                          v
                      +---------------------------------------+
                      |       Bank Ingress & API Gateway      |
                      |      TLS Termination, WAF, SIEM       |
                      +---------------------------------------+
                                          |
                     +--------------------+--------------------+
                     |                                         |
                     v                                         v
+------------------------------------------+  +---------------------------------+
|        Enterprise Operations API         |  |       Bank Identity Provider    |
| (FastAPI, Non-root, In-memory rate-limit)|  |        (OIDC, RS256/ES256)      |
+------------------------------------------+  +---------------------------------+
          |                      |
          |                      | Internal Network (mTLS / Service Token)
          |                      v
          |           +-----------------------------------------+
          |           |       Isolated Identity Vault Service   |
          |           | (Non-root, Purpose-Specific Reveals)    |
          |           +-----------------------------------------+
          |                      |                    |
          |                      |                    | Envelope Encryption (AES-GCM)
          v                      v                    v
+-------------------+  +-------------------+  +---------------------------------+
|  Operational DB   |  |     Vault DB      |  |         Bank KMS / HSM          |
| (PostgreSQL 16)   |  | (PostgreSQL 16)   |  |  (Master KEK, Data Key Unwrap)  |
| Cases, Evidence,  |  | Encrypted Mappings|  +---------------------------------+
| Audit Chains      |  | Isolated Network  |
+-------------------+  +-------------------+
          |
          v
+------------------------------------------+
|  Independent Immutable Checkpoint Store  |
| (WORM Storage, KMS-signed Audit Anchors) |
+------------------------------------------+
```

---

## 2. Network & Trust Boundaries

| Boundary Layer | Network Segment | Protocol / Port | Trust Assumption |
| :--- | :--- | :--- | :--- |
| **Ingress Layer** | Perimeter DMZ | HTTPS (443) | Untrusted bank LAN / VPN. Authenticated via Bank OIDC Bearer tokens. |
| **Application Layer** | `application` network | HTTP (8101) behind TLS proxy | Trusted internal network. Same-origin serving of Enterprise Workbench. |
| **Operational Persistence** | `operational_db` network | TCP (5432) PostgreSQL | Internal network only. No host-published ports. Password file mounted secrets. |
| **Vault Service Boundary** | `vault_service` network | HTTP (8200) | Isolated internal service network. Mutual service token / mTLS. No external routing. |
| **Vault Persistence** | `vault_database` network | TCP (5432) PostgreSQL | Dedicated network accessible **only** by `identity-vault`. Completely blocked from Enterprise API. |
| **Audit Anchor Boundary** | External Object Storage | S3 API / WORM / File | Bank-controlled immutable store with append-only / write-once-read-many (WORM) policy. |

---

## 3. Cryptographic Separation & Identity Vault Isolation

1. **Separation of Concerns**:
   - The **Enterprise API** manages casework, notes, leads, approvals, and cryptographic audit chains. It has **no network route** to the vault database and holds **no master encryption keys**.
   - The **Identity Vault Service** manages encrypted staff pseudonym-to-real-identity mappings. It exposes strictly purpose-specific operations (`POST /internal/v1/reveals/consume`), enforces installation boundaries, and validates dual-approval tokens.
2. **Envelope Encryption & AAD Binding**:
   - Mappings are protected using AES-256-GCM with unique ephemeral Data Encryption Keys (DEKs).
   - DEKs are encrypted (wrapped) by the bank KMS/HSM using a dedicated Master Key Encryption Key (KEK).
   - Authenticated Additional Data (`AAD = f"{installation_id}:{pseudonym}"`) is bound to the ciphertext, preventing cross-tenant substitution or pseudonym swapping.

---

## 4. Audit Anchoring & Tamper-Evidence

- In-database audit records form an immutable SHA-256 hash chain starting from an installation-specific `GENESIS_HASH`.
- Periodically, the current audit head sequence and hash are encapsulated, signed using a bank KMS signing key, and exported to an independent, write-once object store (`AuditCheckpointManager`).
- Even a privileged database administrator with full access to PostgreSQL cannot rewrite history without creating detectable discrepancies against external signed checkpoints.
