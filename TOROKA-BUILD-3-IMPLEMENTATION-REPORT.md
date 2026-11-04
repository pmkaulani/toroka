# Toroka Build 3 — Official Identity & Cross-Platform Entity Verification

**Baseline:** Toroka Build 2 (uploaded project ZIP)  
**Version:** Build 3.0.0  
**Implementation:** integrated into the existing FastAPI application and guest-facing check flow

## Summary

Build 3 adds two Kenya-specific registry workflows and an evidence-backed relationship layer:

1. **NEA public-register snapshots.** An administrator or moderator imports a CSV exported from the official National Employment Authority public register. Toroka validates the source URL, parses the register, minimizes contact data to domains, stores snapshot provenance and freshness, and allows name/registration-number lookups.
2. **BRS/eCitizen review records.** Because BRS official searches are performed inside eCitizen and a CR12 is addressed to the applicant, Toroka does not automate a private BRS login. A moderator records only the minimum result needed to compare a business name and masked registration number. The full CR12, director/shareholder details and original document bytes are not stored by this module.
3. **Separately reviewed digital associations.** A moderator can attest a business-controlled website domain. A social profile or business email domain can then be attached only when the moderator supplies evidence from that previously reviewed official website. These are provenance-bearing associations, not an ownership guarantee.
4. **Reverse matching.** A website domain, business email domain or supported social profile can be checked against reviewed associations even when the user does not know the BRS registration number.
5. **Main investigation integration.** Recruitment/NEA and business/BRS contexts in `/v1/checks` receive an additive `investigation_intelligence.entity_verification` object. It does not alter the deterministic assessment label or score.
6. **Bilingual presentation.** English and Kiswahili evidence panels display registry status, snapshot date/freshness, matching details, separately reviewed links, source pages and limitations.

## Verification

- 21 focused Build 3 tests passed.
- 517 API tests passed.
- 748 project tests passed with the optional `packages/rules/tests/test_robustness.py` excluded because the `hypothesis` dependency is not installed in the build environment.
- JavaScript syntax validation (`node --check`) passed.
- Python compilation passed.
- Alembic upgrade from revision `0003` to `0004` passed against a clean SQLite database.

The 21 Build 3 focused tests are included in the 748 project total; they are not an additional count.

## Not implemented / operational caveats

- No BRS/eCitizen login automation, scraping or public API is claimed.
- NEA data is not pulled continuously. A moderator must obtain an official public-register CSV and import it. The snapshot's `data_as_of` date is displayed; data older than 30 days is stale and cannot support a current-valid claim.
- No live credentials were used in test runs. The NEA importer is exercised with synthetic fixture data; BRS review is exercised with moderator-supplied synthetic record metadata.
- Moderator-supplied `evidence_sha256` is a fingerprint of evidence the moderator reviewed. The endpoint does not validate that external evidence file itself.
- BRS reviewed records and associations require re-review when `review_due` passes. No profile or domain is automatically treated as controlled by a registered entity.
- Full browser end-to-end testing and accessibility review remain deployment checks.

## Migration

New Alembic revision: `0004_build3_entity_verification.py` (down revision `0003`). It adds:

- `nea_registry_snapshots`
- `nea_registry_entries`
- `brs_business_records`
- `brs_business_associations`

For production, run `alembic upgrade head` using the existing production database URL and a stable `HMAC_KEY` before deploying code that reads these tables. Do not replace an existing database with a fresh development database.
