# Toroka Phase 2 — integration guide

This pack is an additive evidence-intelligence module. It is intentionally not a replacement for Toroka's current chat, classifier, or URL-investigation pipeline.

## 1. Copy the package

Copy the `toroka_evidence/` directory into the existing backend Python package. Keep the existing chat endpoint and UI in place.

The optional FastAPI example is in `toroka_evidence/api_contract.py`. Install `requirements-optional.txt` only if the existing backend does not already have compatible FastAPI/Pydantic versions.

## 2. Mount the route

In the existing FastAPI app startup module:

```python
from toroka_evidence.api_contract import router as evidence_router
app.include_router(evidence_router)
```

This provides `POST /v2/investigations`. Do not instantiate a second `FastAPI()` app. If Toroka already has an investigation endpoint, import `EvidenceEngine` and map its result into the existing response schema instead of adding a duplicate route.

## 3. Configure server-only credentials

Set the required provider keys in the backend environment. Never put them in frontend variables, HTML, mobile bundles, or API responses. See `.env.example` and the provider notes in `README.md`.

The default providers are deliberately conservative:

- PhishTank checks only the normalized domain root, not a user's URL path or token.
- urlscan searches existing scans; it does not submit a user's URL.
- RDAP checks domain registration metadata.
- Google Places returns candidate listings only.
- VirusTotal remains disabled unless a commercial and downstream-display licence has been confirmed.

## 4. Connect chat without letting the LLM invent evidence

The existing chat orchestrator should:

1. Detect whether the user supplied a shop URL, seller website, social handle, business name/location, phone, or payment detail.
2. Build an `InvestigationRequest` using only fields actually supplied or independently extracted with high confidence.
3. Run `EvidenceEngine.investigate()` server-side.
4. Pass the structured result to the response composer as untrusted source evidence.
5. Require the model to explain only the supplied evidence items. If the evidence array is empty, it must say that checks were unavailable or insufficient.
6. Render source cards and location candidates from structured JSON, not from model-generated prose.

A social-media profile URL is not the seller's domain. Put an independently supplied shop website in `claimed_website`. Do not infer an offline address from a username or image.

## 5. Frontend evidence card contract

For each evidence card render:

- Source name and a clickable source URL.
- The exact observed finding, not an LLM paraphrase that strengthens it.
- `observed_at` and `expires_at` where present; visibly mark stale evidence.
- Why the finding matters.
- Strength (1–5) and source-match confidence, with plain-language explanation.
- Limitations / what the signal does not prove.

Render `risk_index` with the exact note in the API payload: **Evidence-weighted signal index, not a probability.** Render qualitative `confidence` with `confidence_note`; do not convert it to a percentage.

Render physical listings in a separate section. Always display their `source`, `checked_at`, and `status` (normally `third_party_listing_unverified`). Display phone/website comparison as `Match`, `Does not match`, or `Not compared`; do not say that the business or seller is verified because a map listing exists.

## 6. Production controls required before public launch

This example router is not a complete public deployment boundary. Before exposing it to the internet:

- Add request rate limiting, bot/abuse controls, sensible per-IP and per-session quotas, and request-size limits.
- Apply the app's existing authentication/session and CSRF policy where relevant; preserve Toroka's zero-account user experience without making the backend an unlimited anonymous scanning proxy.
- Set strict CORS rules and enforce HTTPS.
- Keep API keys and `TOROKA_ENTITY_HASH_SECRET` server-side in a secrets manager.
- Restrict moderation methods to authorized staff; never expose `get_report_for_moderation` on a public endpoint.
- Add retention/deletion controls, a privacy notice for third-party lookups, and an audit log that avoids storing full private URLs or payment credentials.
- Set provider timeouts, retry/backoff and concurrency limits; monitor quota failures separately from clean results.
- Review Google Places attribution, map-display, and caching rules before persisting or rendering its content.
- Validate every provider adapter and scoring threshold against a labelled Kenyan dataset before relying on it for automated decisions.

## 7. Important boundary

This module does not independently verify M-PESA account ownership or payment recipient names. It stores claimed payment identifiers only in the request model so a later, authorized integration can compare them with independently verified data. Until such a source exists, show them as seller-provided claims and advise the user to confirm the recipient in the M-PESA confirmation screen before approving payment.

It also does not claim direct access to BRS/eCitizen, private social-media content, or a seller's fulfilment history. Those checks require official or user-provided evidence and separate integration work.
