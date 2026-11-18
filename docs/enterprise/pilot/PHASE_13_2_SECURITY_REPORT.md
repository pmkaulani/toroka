# Toroka Phase 13.2 — Security Controls & Provenance Verification Report

**Document:** Pilot & Production Security Verification Report  
**Release:** Toroka Enterprise 13.2.0  
**Branch:** `phase-13-2-security-provenance`  
**Date:** November 2026  
**Status:** ALL CONTROLS VERIFIED & PASSING  

---

## 1. Scope & Verification Overview

This report provides the compliance and security verification audit trail for Toroka Phase 13.2. Phase 13.2 closes confirmed security and integrity defects in the enterprise control plane, enforces cryptographic and institutional provenance, and guarantees regulatory truthfulness across forensic and payment risk systems.

### 1.1 Summary of Verified Security Controls

| Control ID | Description | Mechanism | Status |
|:---|:---|:---|:---:|
| **SEC-132-01** | Python Monorepo Package Discovery | Flat-layout fix in `pyproject.toml` with explicit service & enterprise includes | **VERIFIED** |
| **SEC-132-02** | Audit Chain Tamper Fail-Closed | Unpacks `(is_valid, head_hash, count)`; reports `CRITICAL` on broken link | **VERIFIED** |
| **SEC-132-03** | Release Environment Validation | Strict enum boundary: only exact `'pilot'` or `'production'` allowed | **VERIFIED** |
| **SEC-132-04** | Evaluator Identity Authentication | Evaluator bound to authenticated OIDC JWT `sub`; client JSON ignored | **VERIFIED** |
| **SEC-132-05** | Caller-Asserted Metric Quarantine | Unverified client metrics quarantined as `INCONCLUSIVE`; cannot approve components | **VERIFIED** |
| **SEC-132-06** | Trusted Validation Runner | Server-side execution against immutable dataset and config digests | **VERIFIED** |
| **SEC-132-07** | Attestation History & Migration 015 | Partial unique index retains superseded attestations while enforcing 1 active | **VERIFIED** |
| **SEC-132-08** | Institutional Signer Trust Registry | Key state tracking (Active/Revoked); rejects `DEV_SOFTWARE` in production | **VERIFIED** |
| **SEC-132-09** | Section 106B Dossier Truthfulness | Drafts start as `DRAFT_UNVERIFIED` with watermarked HTML court exhibit | **VERIFIED** |
| **SEC-132-10** | Dossier Decimal Canonicalization | Formats `f"{Decimal(str(fraud_loss_amount)):.4f}"` to match `NUMERIC(18, 4)` | **VERIFIED** |
| **SEC-132-11** | Advisory ISO 20022 Separation | Emits advisory recommendations (`execution_status="NOT_EXECUTED"`) | **VERIFIED** |
| **SEC-132-12** | AI Provider Maker-Checker | Registration requires independent review (`Approver != RegisteredBy`) | **VERIFIED** |

---

## 2. Test Verification Matrix

All 1,023 unit and integration tests across the Toroka monorepo passed cleanly:

- `packages/enterprise/tests`: **220 / 220 passed** (100%)
- `services/enterprise_api/tests`: **158 / 158 passed** (100%)
- `services/api/tests`: **645 / 645 passed** (100%)
- `apps/enterprise-workbench`: **TypeScript build succeeded with 0 errors**

---

## 3. Institutional Integration Checklist for Bank Security Team

Prior to promoting releases to live bank clearing networks:

1. **Hardware Security Module (HSM):**
   - Provision PKCS#11 HSM keypair.
   - Register public key in Toroka `SignerTrustRegistry` with `security_level=BANK_MANAGED_HSM`.
2. **Payment Clearing Interception:**
   - Integrate Toroka ISO 20022 advisory scoring into interbank message queue (MQ / SWIFT Alliance Gateway / PesaLink Switch).
3. **Statutory Certifier Designation:**
   - Designate forensic officer under Section 106B of the Kenya Evidence Act.
