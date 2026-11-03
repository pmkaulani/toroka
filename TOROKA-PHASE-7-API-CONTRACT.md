# Toroka Phase 7 — API Contract (Host Application)

**Status:** Contract proposal for the existing Toroka API. The Python package does not create HTTP routes by itself.

All routes below are backend-only or authenticated. Operations routes require an operator/admin role; correction and memory routes require case- or record-level authorisation. Enforce request-size limits, rate limits, CSRF controls where applicable, audit logging and consistent error envelopes.

## 1. Investigation signal analysis

`POST /api/v1/phase7/language/analyze`

Request:

```json
{"text":"Umepewa grant, lipa registration fee kwanza"}
```

Response (illustrative):

```json
{
  "language":"sw",
  "language_confidence":0.82,
  "categories":["fake_government_benefit","advance_fee"],
  "signals":[{"pattern_id":"sw.fake_benefit_fee","category":"fake_government_benefit","severity":"high","language":"sw","confidence":0.78,"excerpt":"..."}],
  "limitations":["Rule-based signal; code-switching and slang may be missed."],
  "verdict":null
}
```

No raw text is persisted by the analysis helper. Host API request logging must also avoid recording the message body. The returned signals are passed to the existing evidence-fusion pipeline; this endpoint never returns a seller verdict.

## 2. Operations and feed status

- `GET /api/v1/phase7/ops/status` — admin/operator only; returns feed state, freshness, open alerts and last successful update.
- `GET /api/v1/phase7/ops/metrics` — admin/operator only; aggregate-only counts. Never use case IDs, URLs, phone numbers or customer identifiers as metric labels.
- `GET /api/v1/phase7/ops/alerts` — admin/operator only; return only permitted provider metadata and operational error classes.
- `POST /api/v1/phase7/ops/alerts/{alert_id}/acknowledge` — admin/operator only.
- `POST /api/v1/phase7/ops/feeds/{source_id}/run` — internal worker identity only; do not expose a public arbitrary feed-trigger endpoint.

The API must suppress provider labels/references when policy `display_allowed` is false. Feed activation and terms changes are configuration management operations, not user-chat actions.

## 3. Case memory

- `POST /api/v1/phase7/cases/{case_ref}/memory-observations` — authenticated backend workflow. The service derives entity type/value, evidence reference and provenance from validated investigation outputs. The browser must not set `source_family`, `authoritative_source`, `actor_role` or review state.
- `GET /api/v1/phase7/entities/{entity_type}/memory` — return only reviewed and unexpired `corroborated_indicator` observations, plus limitations. Require access policy and abuse/rate controls. Do not disclose reporter identity or pending reports.
- `POST /api/v1/phase7/memory/{record_id}/correction-requests` — authenticated requester; backend verifies access/identity and records a request code, not arbitrary personal narrative.
- `POST /api/v1/phase7/admin/memory/{record_id}/moderate` — moderator/admin only; server derives role from authentication.
- `POST /api/v1/phase7/admin/corrections/{request_id}/resolve` — privacy officer/moderator role as organisational policy allows.

The package exposes storage primitives; the host API must implement authentication, authorisation, audit context, request validation, data-subject verification and anti-enumeration protections.

## 4. National advisory citations

`POST /api/v1/phase7/admin/ke-cirt-advisories` — operator only; accepts title, an HTTPS URL on an allowlisted official KE-CIRT/Communications Authority host, publication/retrieval timestamps, opaque reviewer ID and redacted short summary. This creates a cited contextual advisory record only. It does not make an IOC and does not change a seller verdict.

## 5. Error model

Use standard HTTP status codes:

- `400` invalid request/indicator/URL.
- `401` unauthenticated.
- `403` insufficient role, provider rights or record access.
- `404` unknown or deliberately undisclosed record.
- `409` lease conflict, duplicate correction workflow or invalid state transition.
- `413` payload too large.
- `422` semantic validation failure.
- `429` rate limit.
- `503` operational service unavailable.

Never return SQL errors, credentials, raw internal stack traces, secret hashes or private memory records.
