# Toroka Intelligence Framework — Merge Report

## Source baseline

This implementation was merged into the user's latest supplied `Toroka(3).zip` source tree. It was not based on the earlier ZIP version. Existing `social_intelligence.py`, URL pipeline, assessment engine, guest-token access, and current UI were retained and extended.

## Main changes

### New module

- `services/api/app/investigation_intelligence.py`
  - Category-aware search planning for public targets.
  - Public web search through the existing Tavily integration.
  - Target-matched extraction of selected pages.
  - Evidence normalisation and provenance labels.
  - Exact-target relevance checks and URL normalisation.
  - Category-aware detection for recruitment and non-delivery patterns.
  - Cross-source complaint correlation with duplicate/author controls.
  - Conservative assessment upgrades: public allegations do not independently produce a `high_risk` verdict.
  - Advice and limitations generated from findings.
  - Bounded in-process cache.

### Existing modules extended

- `services/api/app/social_intelligence.py`
  - Existing Weir X/Reddit and Scrape Creators calls are reused.
  - Domain targets can be searched on X/Reddit.
  - Social provider evidence is normalised by the orchestrator without duplicate provider calls.

- `services/api/app/routes_core.py`
  - First-check `/v1/checks` now invokes the same intelligence framework.
  - Direct URL/profile investigations combine URL-pipeline findings, social evidence and selected extracted web pages.
  - Normal `/v1/chat` investigations use the shared evidence bundle.
  - Follow-up chat for a saved check can reuse the assessment's stored intelligence context.
  - The no-account/guest access path is unchanged.

- `services/api/app/ai_agent.py`
  - Investigation response composition uses the structured evidence summary.
  - Search leads, inspected pages, profile observations, allegations, historical threat reports and unavailable checks are distinguished.
  - Tavily search coverage and extract operations are rendered as separate checks.
  - Advice is tailored to the detected investigation category.

- `services/api/app/config.py`
  - Adds bounded `intelligence_cache_ttl_seconds` configuration.

- `services/api/app/schemas.py`
  - Preserves `investigation_intelligence` in assessment responses and localisation.

- `services/api/tests/test_investigation_quality.py`
  - Adds regression coverage for direct URL chat and the first-check/follow-up-chat path, including a historical recruitment-phishing report on the same domain but a different path.

## Configuration

The `.env.example` includes:

```dotenv
TAVILY_API_KEY=
WEIR_API_KEY=
SCRAPE_CREATORS_API_KEY=
INTELLIGENCE_CACHE_TTL_SECONDS=900
```

These providers are optional. Missing keys must appear as `not_configured` / not checked, never as a clean result. Keep real credentials in a private `.env` or deployment secret store; do not commit or share it.

## Social coverage actually implemented

- Weir: bounded public X and Reddit post search.
- Scrape Creators: public Instagram profile plus bounded popular/topic results; public TikTok profile plus keyword results; public Facebook Page profile plus Page posts where available.
- Exact handle/name matching filters unrelated results.

**Not implemented in this merge:** direct retrieval of Instagram/TikTok/Facebook comments or universal Facebook group/Marketplace search. The current module does not claim comment-level inspection. Provider availability and region-specific coverage still require live tests with configured credentials.

## Security and privacy

- Raw conversation text is not sent to the social provider adapter. Only extracted public identifiers/search terms are used.
- URL normalisation removes common tracking/session/token-like query parameters before evidence persistence.
- Provider output is treated as unverified evidence; user allegations and public posts are not verified facts.
- Existing URL fetch SSRF protections and provider configuration gates remain in place.
- No account registration or social login is introduced.

## Validation

Command:

```bash
PYTHONPATH=packages/rules:packages/connectors:services/api pytest -q -o filterwarnings=ignore --ignore=packages/rules/tests/test_robustness.py
```

Result: **367 passed** (latest evidence and shop-discovery update).

The optional `packages/rules/tests/test_robustness.py` module was excluded because `hypothesis` is not installed in this environment. Provider calls were mocked in tests; this is not proof of live API connectivity or provider coverage. Live verification requires the user's API credentials and should be run against known test targets.

## Remaining engineering work

1. Add provider-specific comment retrieval only after validating current endpoint contracts, pricing and permitted public access.
2. Add persistent background workers and SSE activity events; this merge still uses request-bound work and bounded provider timeouts.
3. Add shared cache/coordination if running multiple API workers; current caches are in-process.
4. Run live provider integration tests with real credentials and budget limits.
5. Expand labelled evaluation cases for legitimate sellers, false matches, impersonation, job offers, government grants, M-PESA messages and multilingual Kenyan scam language.


## Evidence transparency and shop discovery update (3 November 2026)

The latest update extends the merged intelligence output into the result UI:

- Each verdict has a structured `evidence_explanation` with the verdict, a cautious basis-strength description, reason-by-reason statements, why each issue matters, evidence-strength labels, and linked source cards.
- Direct observations from user-submitted messages now include the relevant text excerpt. This is also rendered in the standard findings list when a check has no external URL or social target.
- Public allegations remain explicitly labelled as allegations; search leads, seller profile observations, retrieved pages, and existing Toroka verified-registry matches are kept distinct.
- Shop checks include `shop_discovery`: public physical-address claims, profile-location claims, delivery areas, source attribution, linked websites and observed storefront URLs.
- Physical address/profile-location claims receive a Google Maps search link. A delivery area does not receive a shop-address map link.
- The UI labels seller-published locations as self-declared and third-party locations as third-party claims. Neither is automatically treated as independently verified. No location is inferred when sources do not state one.
- English and Swahili strings were added for the evidence and shop-presence panels.
- The in-process cache key was versioned so results cached before the new location fields do not shadow updated records.

### Important interpretation

A social profile saying “based in Nairobi” is a seller-published location claim, not proof of a staffed shop or registered business. A Maps link opens a search for the stated place; it is not a Toroka verification or a confirmed map pin. Likewise, a profile-linked website is shown as a link from the profile, not as proof that the website is controlled by the same legal business. Independent business-registry and location verification remains a separate step.

### Latest validation

- Backend test suite: **367 passed**.
- `python -m compileall -q services/api/app`: passed.
- `node --check services/api/app/static/app.js`: passed.
- `node --check services/api/app/static/i18n.js`: passed.
- Browser end-to-end tests were not run in this environment. The optional Hypothesis robustness module remains excluded because Hypothesis is not installed. Provider tests use mocks; live provider connectivity still requires configured credentials.
