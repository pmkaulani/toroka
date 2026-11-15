# Toroka Enterprise — Known Limitations & Architectural Boundaries

This document records the genuine architectural boundaries, external dependencies, and unsupported capabilities of the Phase 3.4 release.

---

## 1. Architectural Boundaries & Unsupported Modes

1. **Multi-Bank Shared Tenancy Not Supported**:
   - The current architecture is designed strictly for **single-tenant institutional deployment** (one dedicated deployment stack per bank or institution).
   - Multi-tenant shared database hosting with dynamic tenant sharding is **not** supported and must not be configured for pilot operations.
2. **Batch / Manifest Ingestion vs. Live Core Banking Streaming**:
   - In Phase 3.4, investigation data enters through cryptographically signed run manifests conforming to Data Contract v2.0.0.
   - Real-time streaming connectors into legacy core banking databases (e.g. T24, Finacle, Flexcube) are part of the upcoming Bank Integration Layer (Phase 4), not the Phase 3 operational pilot.
3. **Step-up Authentication Delegated to Bank IdP**:
   - The Enterprise API does not directly issue hardware WebAuthn/FIDO2 MFA challenges during identity reveal consumption.
   - The bank IdP must enforce appropriate step-up or session re-authentication policies for authoriser and investigator roles.

---

## 2. Mandatory External Dependencies

1. **Bank Key Management Service (KMS)**:
   - The production Identity Vault requires an external KMS capable of 256-bit data key generation and unwrapping. If KMS is unreachable, reveal consumption fails closed.
2. **Bank Identity Provider (OIDC)**:
   - Authentication relies completely on an external bank OIDC provider with accessible JWKS endpoints. There is no local password database or backdoor administrative login in production mode.
3. **Immutable Object Storage (WORM)**:
   - Independent signed audit checkpoints require external immutable storage (e.g. AWS S3 with Object Lock in Compliance Mode, Azure Immutable Blob, or on-premise WORM storage).

---

## 3. Unverified Infrastructure Controls in Local Test Environments

- **Physical HSM / PKCS#11 Driver**:
  - The envelope cipher was tested against standard AES-256-GCM KMS key provider protocols (`LocalKMSKeyProvider`). Direct hardware appliance testing against physical Thales/Luna HSMs must be conducted on bank-premises hardware during installation.
- **TLS Certificate Validation & Ingress Termination**:
  - Mutual TLS and HSTS are designed to terminate at the bank's perimeter reverse proxy (e.g. Nginx, F5 BIG-IP). This was verified via configuration simulation and requires bank network team deployment.
