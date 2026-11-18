# Phase 13.2 — Security, Provenance & Regulatory Truthfulness

**Status:** Implementation branch; CI verification in progress  
**Branch:** `feat/phase-13-2-security-integrity`  
**Baseline:** Phase 13.1  
**Scope:** Correctness and trust-boundary hardening. This phase does not claim bank certification or production payment interception.

## What changed

### Build and delivery
- Added explicit setuptools build-system and monorepo package-discovery configuration to prevent flat-layout auto-discovery failures during `pip install -e ".[dev]"`.
- Added migration `015_phase13_2_readiness_history`: readiness attestations are retained as append-only history, with a partial unique index allowing at most one active attestation per installation/release/gate.

### Governance and validation
- Release target environments are restricted to `pilot` and `production`; unrecognized values cannot bypass production checks.
- Audit-health evaluation now reads the boolean result from `verify_audit_chain` rather than treating its non-empty result tuple as truthy.
- Validation evaluator identity is derived from the authenticated principal, not a caller-supplied name.
- Metrics submitted directly through the validation API are persisted as `inconclusive` until a trusted validation execution worker and signed result attestation are integrated. This intentionally blocks component approval based only on caller-asserted metrics.
- Release approval IDs and validation-run IDs must exactly match the persisted records attached to the approved release components.
- Production promotion fails closed until a bank-controlled readiness evidence resolver is configured. Readiness URLs are not accepted as proof; artifact references must resolve to bank-managed evidence and match their digest.
- AI-provider registration creates a pending review record. Automated policy screening is not an approval decision.

### Signing and key trust
- Local ephemeral software signing is rejected when `TOROKA_ENT_ENV=production`.
- Asymmetric signature verification requires a separately trusted public key; an embedded public key is not itself a trust anchor.
- Production verification can resolve keys from `TOROKA_ENT_TRUSTED_SIGNING_KEYS_JSON`, a JSON object mapping key IDs to trusted public-key PEM strings.
- The current branch intentionally does **not** claim a complete bank HSM/KMS integration. A bank-managed signer adapter, key lifecycle and revocation controls must be integrated before production signing is enabled.

### Dossiers and evidence claims
- Forensic dossier creation verifies the case exists in the same installation.
- Client-submitted evidence and mule-node claims are labelled `UNVERIFIED_CLIENT_SUBMISSION`.
- User-supplied certifier names/declarations no longer create a Section 106B certificate.
- New dossiers remain `DRAFT_UNVERIFIED`; signing changes them to `DRAFT_SIGNED`, not a certified or court-ready status.
- HTML exports are review drafts and no longer impersonate a Kenyan court, regulator or public authority.
- Dossier verification distinguishes content integrity/signature from legal certification. A signed draft is not reported as a valid court dossier.

### Payment and Copilot truthfulness
- Unknown ISO 20022 clearing rails are rejected instead of defaulting to PesaLink.
- Client-supplied prior-beneficiary transfer counts are ignored until bank-controlled history is connected; unknown history is not treated as zero.
- Payment evaluation outputs are advisory only. They no longer state that Toroka has blocked, held or released funds.
- Copilot semantic checks can report textual consistency for excerpts supplied in the request, but they are marked `CALLER_SUPPLIED_TEXT_ONLY` and never as evidence-verified until evidence is resolved from an authorized case store.

## Deliberate production gates still open

These are integration dependencies, not features to fake:

1. **Bank HSM/KMS signer:** implement the institution's approved PKCS#11/KMS adapter; enforce key allowlisting, key ownership, rotation, revocation and audit.
2. **Bank readiness evidence resolver:** retrieve evidence by immutable bank-owned artifact ID, authorize scope, recalculate digest and validate release/version binding and freshness.
3. **Trusted validation executor:** execute tests against controlled datasets/configurations, preserve run artifacts, compute metrics server-side and issue signed execution attestations.
4. **Case evidence resolver for Copilot:** load authorized persisted evidence by case and record ID; do not treat caller-supplied excerpts as source records.
5. **Payment rail integration:** connect to the bank's authenticated payment gateway/event stream and bank policy approval. Until then, scoring is a simulator/advisory result only.
6. **Money precision and schema validation:** ISO 20022 transfer amounts and dossier loss amounts still require a Decimal/Numeric migration, and XML parsing still needs formal ISO 20022 XSD validation.

## Environment configuration

- `TOROKA_ENT_ENV=production` is required for production-mode service signing guards.
- `TOROKA_ENT_TRUSTED_SIGNING_KEYS_JSON` is the current trust-key registry input. Protect it as bank-controlled deployment configuration; never accept arbitrary caller keys as production trust anchors.

Example shape (use institution-issued PEM material; do not commit keys):
```json
{
  "bank-release-signing-key-2026": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----"
}
```

## Verification

The workflow `Toroka CI` is the authoritative automated check for this branch:
- Python dependency installation
- Python package compilation
- Full Python test suite
- Enterprise Workbench install, type-check and build

Do not treat a successful local digest check, a synthetic validation payload, a self-signed key, or a caller-submitted evidence URL as a bank approval or statutory certificate.

## Exit criteria

Phase 13.2 is ready for review when CI passes, migration 015 is verified against the supported database backends, negative tests prove the trust-boundary failures are rejected, and the deliberate production gates above are clearly documented. Phase 13.3 should focus on integrating institution-controlled adapters and a supervised pilot, not adding unrelated features.
