# Toroka Build 3 — API Contract

All `/v1` responses use `Cache-Control: no-store`. Moderator endpoints require a bearer session for a user with role `admin` or `moderator`.

## 1. Import NEA register snapshot

`POST /v1/admin/build3/nea/import` — `multipart/form-data`

| Field | Type | Rule |
|---|---|---|
| `file` | file | `.csv`, UTF-8, max 5 MB / 5,000 data rows |
| `source_url` | string | Exact allowlisted official NEA public-register HTTPS URL |
| `data_as_of` | string | ISO date representing source data date; cannot be future |

Returns snapshot ID, count, invalid rows skipped, content SHA-256, retrieval time, source URL and freshness.

## 2. Search NEA snapshot

`GET /v1/build3/nea/search?q=...`

Search term: 3–120 characters. Public rate-limited route. Returns `snapshot_unavailable`, `checked` or `no_match_in_snapshot`; results include licence status as captured by that snapshot, validity dates, source URL, data date and freshness. `no_match_in_snapshot` is never equivalent to unregistered.

## 3. Verify entity details

`POST /v1/build3/entities/verify` — JSON

```json
{
  "business_name": "Example Business Limited",
  "nea_registration_number": "RA/2025/10/24",
  "brs_registration_number": "PVT-EXAMPLE123",
  "domain": "examplebusiness.co.ke",
  "contact_email": "info@examplebusiness.co.ke",
  "social_profile": "https://www.instagram.com/examplebusiness/",
  "employment_agency": false
}
```

All fields are optional, but at least one useful claim is required. `employment_agency` requests an NEA search when no NEA registration number is available. BRS matching is attempted by registration HMAC and, where applicable, by reviewed domain/social/email-domain association. Public rate-limited route.

## 4. Add reviewed BRS record

`POST /v1/admin/build3/brs-records` — moderator/admin JSON

```json
{
  "registration_type": "company_cr12",
  "registration_number": "PVT-EXAMPLE123",
  "registered_name": "Example Business Limited",
  "source_url": "https://brs.ecitizen.go.ke/",
  "evidence_sha256": "<64-hex-digest>",
  "checked_at": "2026-11-04",
  "review_interval_days": 90
}
```

Registration type: `company_cr12`, `business_name`, `llp`, `foreign_company`. The service stores HMAC, masked registration number, normalized/legal name, official source URL, evidence digest and review metadata. It never stores full CR12 document bytes or director/shareholder information.

## 5. Add digital association

`POST /v1/admin/build3/brs-records/{record_id}/associations` — moderator/admin JSON

Fields:
- `association_type`: `website_domain`, `social_profile`, `contact_email_domain`
- `value`: domain or full supported profile URL
- `source_url`: HTTPS evidence page
- `evidence_sha256`: 64-character digest of reviewed evidence
- `reviewed_at`: ISO date
- `review_interval_days`: 7–180, default 90
- `control_review_confirmed`: must be `true`

For website association, evidence page must be on the claimed business domain. For social profile or email domain, evidence must be published on a previously reviewed website association.

## 6. Revoke BRS record and associations

`POST /v1/admin/build3/brs-records/{record_id}/revoke`

```json
{"reason_code":"official_record_corrected"}
```

## 7. Normal checks

`POST /v1/checks` may include:

```json
{
  "assessment": {
    "investigation_intelligence": {
      "entity_verification": {
        "status": "review_required",
        "nea": {},
        "brs": {},
        "limitations": []
      }
    }
  }
}
```

Actual NEA/BRS objects depend on the submitted identifiers and available reviewed records. Build 3 is additive and does not override the main assessment result.

## Error behaviour

- `401`: no valid session for moderator route.
- `403`: signed-in user lacks the required role.
- `413`: uploaded file exceeds size limit.
- `415`: importer file extension is not CSV.
- `422`: malformed fields, unsupported source URL, future dates, invalid registry content or unreviewed association.
- `429`: public endpoint rate limit reached.
- `409`: conflicting snapshot/record constraint.
