# Antigravity handoff — integrate the updated Toroka intelligence source

The supplied `toroka-intelligence-updated-project.zip` is a modified copy of the latest Toroka source archive. Treat it as the reference implementation for the intelligence merge.

## Required actions

1. Compare this updated source tree with the current Antigravity workspace.
2. Preserve changes that have been made in the workspace since the supplied source ZIP; do not blindly overwrite newer user work.
3. Port the intelligence changes as a three-way merge, prioritising the updated files and preserving unrelated existing work.
4. Do not change the no-account guest-session model, current Toroka logo, UI/UX, English/Swahili support, existing URL pipeline or deterministic assessment policy.
5. Do not add login, social account connection, OAuth, or require user social-media credentials.
6. Keep all API keys server-side.
7. Add the optional provider keys from `.env.example` to deployment secrets only when configured:
   - `TAVILY_API_KEY`
   - `WEIR_API_KEY`
   - `SCRAPE_CREATORS_API_KEY`
   - `INTELLIGENCE_CACHE_TTL_SECONDS=900`
8. Never copy a real `.env` into source control or into a frontend bundle.

## Files to review carefully

- `services/api/app/investigation_intelligence.py` (new)
- `services/api/app/social_intelligence.py`
- `services/api/app/routes_core.py`
- `services/api/app/ai_agent.py`
- `services/api/app/config.py`
- `services/api/app/schemas.py`
- `services/api/tests/test_investigation_quality.py`
- `.env.example`

## Behaviour requirements

- The first `/v1/checks` result, direct URL/profile investigation and `/v1/chat` must all use the same evidence model.
- Search results are leads; extracted page contents are inspected source material; public social posts are allegations/mentions unless independently verified.
- Same-domain, different-path history must be described as domain-level/historical association, not proof that the submitted path is identical.
- Public allegations alone must not produce a `high_risk` verdict.
- A failed or unconfigured provider must not be shown as checked or safe.
- Category-specific advice must replace irrelevant generic advice (for example, recruitment advice for an overseas job offer, not shop delivery/refund advice).
- Do not count duplicates, syndicated copies or one author repeatedly posting as independent corroboration.
- Do not send full private messages, OTPs, passwords, M-PESA PINs, account recovery codes, private screenshots or raw user conversations to external search providers.
- No-account usage remains immediate. Backend anonymous tokens may protect access, but no registration screen or account profile is introduced.

## Validation

Run:

```bash
PYTHONPATH=packages/rules:packages/connectors:services/api pytest -q -o filterwarnings=ignore --ignore=packages/rules/tests/test_robustness.py
```

The reference merge passed 362 backend tests. Re-run tests in the current workspace and report differences. The optional Hypothesis robustness module was not run in the reference environment because that dependency was unavailable.

Then perform live, manually supervised provider checks only after the owner configures API credentials. Mock-based tests do not verify live account entitlements, regional social coverage, quotas, or current third-party API contracts.

## Report back

List files merged, files with conflicts, test results, live providers actually configured, and all remaining limitations. Do not claim live provider checks passed if only mocks were used. Do not deploy or commit without explicit permission.
