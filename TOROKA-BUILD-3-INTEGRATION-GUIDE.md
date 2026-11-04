# Toroka Build 3 — Integration & Operations Guide

## 1. What is connected

Build 3 is mounted by `services/api/app/main.py` and adds router `services/api/app/routes_build3.py`. Its registry context is called additively by the regular check pipeline in `services/api/app/routes_core.py`.

The normal guest check remains:

`Guest chat → POST /v1/checks → existing assessment and investigation intelligence → Build 3 registry context when relevant → evidence presentation`

Build 3 performs no outbound registry requests while a user is checking a message. NEA lookups use a moderator-imported snapshot. BRS lookups use moderator-reviewed records. This avoids blocking chat on unavailable private government portals and makes the age/provenance of each record explicit.

## 2. Database migration

Build 3 adds Alembic revision `0004` after `0003`.

From `services/api/` with the normal production environment variables loaded:

```bash
alembic upgrade head
```

Keep the existing production `DATABASE_URL` and stable `HMAC_KEY`. The BRS registration number is stored as an HMAC lookup digest plus a masked display value; changing the HMAC key without an explicit re-key migration makes those stored registration numbers unsearchable.

The application also uses `Base.metadata.create_all()` as a development convenience. Production deployments should still run the Alembic migration as part of release operations.

## 3. Import an NEA public-register snapshot

1. Open the official NEA public register: <https://www.diaspora.go.ke/verify> or <https://www.neaims.go.ke/EmploymentAgencyList.aspx>.
2. Obtain a CSV export using the official site's supported export mechanism. Do not use an unofficial third-party copy.
3. Record the date that the public register data represents. Do not use today's date merely because the file was downloaded today.
4. Sign in to Toroka with an `admin` or `moderator` account and upload the CSV.

Example:

```bash
curl -X POST "$TOROKA_API/v1/admin/build3/nea/import" \
  -H "Authorization: Bearer $TOROKA_MODERATOR_TOKEN" \
  -F "file=@nea-register.csv;type=text/csv" \
  -F "source_url=https://www.neaims.go.ke/EmploymentAgencyList.aspx" \
  -F "data_as_of=2026-11-01"
```

Constraints:

- CSV only, UTF-8 (UTF-8 BOM accepted), maximum 5 MB and 5,000 rows.
- Source URL must match one of the approved official NEA register pages over HTTPS with no query or fragment.
- Registration numbers must match the published RA/NA pattern.
- The original CSV is not stored. The importer stores its SHA-256 digest, snapshot metadata, public agency name/number/status/service type, validity dates and public email/website domains. Email local parts and full email addresses are not stored.
- Freshness: 0–7 days `fresh`, 8–30 days `aging`, more than 30 days `stale`.
- A stale snapshot cannot be shown as current valid. A no-match result is explicitly limited to that imported snapshot and is not proof an agency is unregistered.

## 4. Search the imported NEA register

```bash
curl "$TOROKA_API/v1/build3/nea/search?q=RA%2F2025%2F10%2F24"
```

Search accepts an agency name or registration number (3–120 characters). It is rate-limited and returns source URL, `data_as_of`, age/freshness, status and caveats. The official portal link is included for a fresh live confirmation.

## 5. Add a moderator-reviewed BRS result

BRS official searches happen in eCitizen. The moderator should perform the search independently and enter only the minimum facts needed for a registry comparison. The current BRS FAQ describes the official company search (CR12) in eCitizen and notes that it is addressed to the person/business making the application.

Example:

```bash
curl -X POST "$TOROKA_API/v1/admin/build3/brs-records" \
  -H "Authorization: Bearer $TOROKA_MODERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "registration_type": "company_cr12",
    "registration_number": "PVT-EXAMPLE123",
    "registered_name": "Example Business Limited",
    "source_url": "https://brs.ecitizen.go.ke/",
    "evidence_sha256": "<sha256-of-evidence-reviewed-in-your-secure-workflow>",
    "checked_at": "2026-11-04",
    "review_interval_days": 90
  }'
```

Supported `registration_type` values: `company_cr12`, `business_name`, `llp`, `foreign_company`.

Do not upload or paste a full CR12 into this endpoint. Do not store shareholder/director IDs, personal addresses, phone numbers or beneficial-owner details in the registry record. Keep any underlying official proof in an independently secured and access-controlled evidence store; this API stores only the hash/fingerprint supplied by the moderator.

## 6. Review digital associations

A website association must:
- use a business-controlled domain (not a shared platform domain such as `*.myshopify.com`, `*.wixsite.com`, `*.vercel.app` or a public suffix such as `co.ke` alone);
- cite an HTTPS evidence page hosted on that same domain; and
- have `control_review_confirmed: true` set by the moderator after an independent review.

A social profile or contact email domain can be associated only when its evidence page is hosted on a previously reviewed official website domain. This creates a separately reviewed relationship. It is not proof of legal ownership or authorization beyond the reviewed evidence and date.

Example website association:

```bash
curl -X POST "$TOROKA_API/v1/admin/build3/brs-records/$RECORD_ID/associations" \
  -H "Authorization: Bearer $TOROKA_MODERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "association_type": "website_domain",
    "value": "examplebusiness.co.ke",
    "source_url": "https://examplebusiness.co.ke/contact",
    "evidence_sha256": "<sha256-of-reviewed-evidence>",
    "reviewed_at": "2026-11-04",
    "review_interval_days": 90,
    "control_review_confirmed": true
  }'
```

To associate a social profile, use `association_type: "social_profile"`, provide the full supported public profile URL, and cite a page on the already reviewed official website that links to that profile. For an email domain use `association_type: "contact_email_domain"` and cite the official website page where it is published. The original email local part is not stored.

## 7. Revoke or correct a BRS record

```bash
curl -X POST "$TOROKA_API/v1/admin/build3/brs-records/$RECORD_ID/revoke" \
  -H "Authorization: Bearer $TOROKA_MODERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason_code":"official_record_corrected"}'
```

Revocation disables the BRS record and all its associations. Audit events record the actor, action and minimal metadata. For corrections, the moderator can re-submit the official reviewed information and re-review each digital link.

## 8. Verify an entity through the public API

```bash
curl -X POST "$TOROKA_API/v1/build3/entities/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "business_name": "Example Business Limited",
    "brs_registration_number": "PVT-EXAMPLE123",
    "domain": "examplebusiness.co.ke",
    "social_profile": "https://www.instagram.com/examplebusiness/",
    "contact_email": "info@examplebusiness.co.ke",
    "employment_agency": false
  }'
```

`employment_agency` should be true or an NEA registration number supplied when an NEA registry comparison is intended. General business names do not automatically trigger unrelated NEA searches.

## 9. Main chat integration

The normal `/v1/checks` route attaches `assessment.investigation_intelligence.entity_verification` when it detects recruitment/NEA identifiers or business/BRS context. It can compare:

- the submitted NEA registration number or agency name against the imported snapshot;
- the submitted BRS number against moderator-reviewed records;
- submitted business domains, contact email domains and public social handles against separately reviewed BRS associations.

This is additive context only. The Build 3 code does not alter the deterministic risk label, and it does not claim that a registry match validates a vacancy, payment request, individual recruiter or seller conduct.

## 10. Production checklist

- [ ] Run `alembic upgrade head` against the production database.
- [ ] Preserve the existing stable `HMAC_KEY` and encryption key.
- [ ] Create moderator roles only for trained reviewers; protect bearer tokens.
- [ ] Obtain the NEA CSV from the official portal and set its real `data_as_of` date.
- [ ] Define an operational cadence for NEA snapshot refresh and stale alerts.
- [ ] Store underlying moderator evidence outside this registry table with strict retention/access controls.
- [ ] Train moderators to distinguish registered entity identity from a person claiming to represent it.
- [ ] Provide a correction and revocation route to respond to inaccurate records.
- [ ] Verify backup/restore of the new four tables.
- [ ] Run browser end-to-end and mobile UI checks after deployment.

## Sources

- NEA public recruitment agency register: <https://www.diaspora.go.ke/verify>
- NEAIMS published agency list: <https://www.neaims.go.ke/EmploymentAgencyList.aspx>
- BRS official portal: <https://brs.ecitizen.go.ke/>
- BRS FAQs: <https://brs.go.ke/wp-content/uploads/2024/05/FAQs.pdf>
