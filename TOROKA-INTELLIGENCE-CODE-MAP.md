# Toroka intelligence code map

## Request entry points

- `services/api/app/routes_core.py` — `run_check()` for the first `/v1/checks` assessment.
- `services/api/app/routes_core.py` — `/v1/chat` for standard conversations and direct URL/profile investigations.
- `services/api/app/routes_core.py` — check follow-up chat rehydrates stored `investigation_intelligence` context.

## Orchestration

- `services/api/app/investigation_intelligence.py` — target/query planning, Tavily search, selected-page extraction, evidence normalisation, identity relevance, category flags, cross-source flags, advice and cautious risk upgrade helper.
- `services/api/app/social_intelligence.py` — existing social provider adapter for Weir and Scrape Creators.
- `services/api/app/public_search.py` — existing public identifier extraction, Tavily wrapper, source relevance filtering and manual search URLs.
- `services/api/app/url_pipeline.py` — existing URL-specific pipeline, redirect/URL checks, threat-feed and URL source findings.

## Response and schema

- `services/api/app/ai_agent.py` — evidence-aware AI response formatting and provider-status narration.
- `services/api/app/schemas.py` — `AssessmentOut.investigation_intelligence` field and localisation preservation.
- `services/api/app/config.py` — optional provider API keys and cache TTL.

## Tests

- `services/api/tests/test_investigation_quality.py` — first check, direct URL and follow-up chat regressions.
- Existing API and rules tests continue to cover prior application behaviour.

## Eventual next modules (not part of this merge)

- Persistent task queue / worker.
- SSE or WebSocket progress event stream.
- Durable event store for recoverable long-running investigations.
- Cross-worker cache (e.g. Redis) when the deployment runs multiple API processes.
- Provider comment-level retrieval, subject to API support and terms.
