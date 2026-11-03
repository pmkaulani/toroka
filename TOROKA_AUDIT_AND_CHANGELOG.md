# Toroka — Code Audit & Change Log

**Latest update:** 1 November 2026 — Social Intelligence Layer Integration (Weir & Scrape Creators)  
**Previous audit date:** 1 November 2026 — Conversational UI Redesign & Activity Narration  
**Basis:** Implementation of `toroka-intelligence-pack` into `smart-scam-identifier` under non-negotiable no-account, privacy, and deterministic risk policy constraints.

## Changes in this release (1 November 2026 — Social Intelligence Engine)

- **Social Intelligence Orchestration (`services/api/app/social_intelligence.py`):** Added bounded external provider integration for public social media investigations:
  - **Weir:** Bounded public search on X (max 12 posts) and Reddit (max 5 posts, 1-year window) targeting exact shop names and handles.
  - **Scrape Creators:** Direct public profile inspection and keyword/topic searches on Instagram (`/v1/instagram/profile`, `/v1/instagram/search/popular`), TikTok (`/v1/tiktok/profile`, `/v1/tiktok/search/keyword`), and Facebook Pages (`/v1/facebook/profile`, `/v1/facebook/profile/posts`).
- **Exact Identity Matching & False-Positive Elimination:** Token-boundary matching and account-author checks ensure lookalikes (e.g. `baseusclothing` vs `@base_menswear`) are discarded.
- **Evidence Normalisation:** Standardized all returned social leads with provider, platform, normalized URL, excerpt, publication date, author, and verification status (`unverified_public_mention`, `observed_public_profile`, `observed_public_page_post`).
- **Deterministic Red-Flag Pattern Summarisation:** Identifies non-delivery and payment-dispute patterns. Requires at least 2 distinct URLs and 2 distinct authors for `supporting` corroboration; otherwise flagged as `weak`. Crucially, these remain unverified public allegations and never override Toroka's risk classification.
- **AI Agent Context Integration (`services/api/app/ai_agent.py` & `routes_core.py`):** AI responses explicitly distinguish self-published profile claims (`social_profile_observation`) from third-party complaints (`social_intelligence_lead`) and account-scoped posts (`account_scoped_post`).
- **Privacy & Secret Protection:** Only extracted public identifiers (`find_public_identifiers`) are sent to external APIs; conversations, credentials, phone numbers, M-PESA details, and PINs/OTPs are never sent. Provider keys are backend-only.
- **Honest Status Reporting:** Unset or missing provider keys return `not_configured`, never pretending a source is clean or checked.
- **In-Process Cache:** 15-minute TTL cache keyed by target and SHA256 credential fingerprints prevents duplicate billing and rate exhaustion.

## Verification Performed (Social Intelligence Layer)

| Area | Result | Notes |
|---|---|---|
| Social Intelligence Tests (`test_social_intelligence.py`) | **9 passed** | Unconfigured keys, exact token matching, Weir normalization, complaint independence, Scrape Creators profile/video retrieval, and cache hits verified. |
| API Suite (`services/api/tests/`) | **132 passed** | Complete API test suite passed with 0 errors. |
| Full Python Test Suite | **381 passed** | 202 Rules, 20 Connectors, and 159 API tests passed. |
| Evaluation Benchmark (`eval/run_eval.py`) | **35 / 35 passed** | 100% scam flagged, 0% false positives on legit, 0 mismatches. |
| Web Tests (`test_web.py`) | **9 passed** | Zero regressions in web shell, accessibility, and localization. |

- **Conversational UI Redesign:** Modernized the core chat layout to match the Antigravity UI handoff (`toroka-reference.html`), transitioning from boxed card containers to an open, editorial, conversational format.
- **Genuine Brand & Theme Preservation:** Retained the authentic animated SVG Toroka runner logo and `--action: #087F8C` teal token system across both light and dark modes (avoiding the prototype's provisional green shield).
- **Subdued User Bubbles & Centered Content Stream:** Constrained `#thread` and `.composer` using `--content: 790px`, rendered conversational date separators, and styled user prompts with crisp, elevated bubbles.
- **Live Investigation Activity Narration:** Implemented real-time progress narration with cycling investigative activity states (`.activity`, `.activity-head`, `.spinner`) powered by real backend events, showing live checks (text analysis, domain lookup, shop registry, known scam patterns) without simulated data.
- **Open Assessment Structure:** Replaced rigid card wraps with open assessment reports featuring a lead summary, risk pill with distinct semantic icons, open finding text, open evidence rows with status badges, and numbered recommendations.
- **Progressive Disclosure:** Preserved keyboard-accessible `<details>` sections (`.det-why` and `.det-checked`) for deep investigative context and source leads, ensuring immediate clarity for advice and findings.
- **Sidebar Safety & Guest Profile:** Integrated safety context card and guest session indicator into the sidebar footer.
- **Complete Bilingual Coverage:** Added English and Swahili translations for all new UI text, status indicators, and action buttons in `i18n-chat.js`.
- **Zero Accessibility & Security Regressions:** Maintained strict CSP compliance (no inline scripts/styles), WCAG AA text contrast ratios ($\ge 4.5:1$), non-text contrast ratios ($\ge 3.0:1$), touch target minimums ($\ge 44\text{px}$), and `prefers-reduced-motion` compliance. Single checkmark SVG path coordinate restriction maintained exclusively for `verified_official`.

## Verification Performed (1 November 2026)

| Area | Result | Notes |
|---|---|---|
| Web Frontend & Accessibility (`test_web.py`) | **9 passed** | WCAG AA token contrast, non-text contrast, touch targets, reduced motion, single checkmark rule, CSP cleanliness, bilingual dictionary completeness, welcome actions, and safety topics all verified. |
| Full Python Test Suite | **372 passed** | Rules (202), API (150), and Connectors (20) passed with 0 failures (3 expected third-party deprecation warnings). |
| Evaluation Benchmark (`eval/run_eval.py`) | **35 / 35 passed** | Flagged rate 100% on scams, 0% on legit, 0 mismatches, 0 accusatory wording occurrences. |
| JavaScript / CSS Syntax | **Passed** | Clean parse, valid CSS selectors, no CSP breaches. |

---

## Historical Audit (26 October 2026)

- A matched but expired, unreviewed, malformed, or undated verified-entity record is surfaced as unresolved/stale context rather than silently ignored or presented as current verification.
- Unreviewed official-source notes are not allowed to masquerade as authoritative contradictions in the deterministic assessment. Independent high-risk signals, such as a direct request for a PIN or OTP, remain effective.
- URL-investigation coverage explicitly explains when an old record is not current verification and that staleness alone is not proof of fraud.
- Welcome-screen and safety copy are more precise about what Toroka checks and what it cannot guarantee.
- Mobile CSS was adjusted so the welcome area can scroll while the composer stays in normal layout flow; suggestion tiles collapse into a compact two-column layout on narrow screens.
- The shipped model pointer was cleaned so it no longer references the test-only `v-test-temp` rollback artefact. The active champion and shadow candidate are preserved, and the rollback pointer now references a retained, previously accepted candidate artefact.
- `.gitignore` was strengthened for `.env` credentials, local databases, private evidence, virtual environments, caches, and generated ML runtime state.
- Historical UI screenshots were excluded from this archive because they predate the latest responsive-layout changes and are not valid screenshots of the current UI.

## Verification performed

| Area | Result | Notes |
|---|---|---|
| Rules tests | **202 passed** | The property-based `test_robustness.py` module could not be collected because `hypothesis` is not installed in this environment; it is not counted as passed. |
| API tests | **105 passed** | Ran each API test module individually; includes URL investigation, shop-handle lookup, source-review gating, feedback/API, and UI shell tests. |
| Connector tests | **20 passed** | Safe-fetch and connector tests passed. |
| Total observed passing tests | **327 passed** | Sum of the three completed groups above; not a claim that every test in the repository ran. |
| JavaScript syntax | **Passed** | `app.js`, `i18n-chat.js`, and `i18n.js` passed `node --check`. |
| Python compilation | **Passed** | `compileall` passed for rules, API and connector packages. |
| CSS delimiter sanity | **Passed** | Opening and closing brace counts match. |
| Static responsive layout render | **Passed, limited scope** | Inline static render at desktop 1440×900 and mobile 390×844 showed no welcome/composer overlap or horizontal overflow. External scripts were removed for this layout-only render. |
| Full browser navigation / functional E2E | **Not verified** | Chromium navigation to the local server was blocked by the execution environment (`ERR_BLOCKED_BY_ADMINISTRATOR`). Therefore JS interactions were not certified through a real browser session. |
| Live external provider connectivity | **Not independently verified in this audit environment** | External DNS/network fetch attempts failed here. Recheck provider status on the target machine. |

FastAPI emitted deprecation warnings for `on_event` handlers, and Alembic emitted a `path_separator` configuration warning. These did not fail the test groups above but should be cleaned up in a future maintenance pass.

## Important limitations still present

- The currently reported seed dataset has only **63 examples**, and the locked benchmark has only **10 examples** with inadequate coverage in several categories. This cannot establish production generalisation. Newly trained candidates should remain in shadow mode until the independent benchmark is expanded and meets per-category support requirements.
- Direct live BRS business-registration and Safaricom Daraja ledger verification are simulated in the reported architecture; do not represent them as live official checks.
- Web Risk is optional and was not configured in the supplied environment. Other threat feeds and search providers must display their actual availability and retrieval time; a missing blocklist match is not proof of safety.
- A local development server exposed by a tunnel is not a production deployment. Use a persistent, secured host for public access, protect privileged routes, limit abuse, and monitor provider quotas.

## Credentials and private local data

This archive deliberately excludes `.env`, SQLite databases, `evidence_store`, virtual environments, private runtime queues, and telemetry. The submitted local `.env` had non-empty Gemini and Tavily variables, while `WEBRISK_API_KEY` was absent/empty; the **values are not included here**. Recreate your local `.env` from `.env.example` and configure the keys in your own environment. Rotate any API key that may have been included in a previously shared ZIP or committed to a repository.

## Recommended next steps

1. Install the project's development dependencies, including `hypothesis`, and run the complete test suite.
2. Run browser E2E tests in a normal local browser environment and verify the live JS flow at desktop and mobile sizes.
3. Independently validate SSRF protections and live search providers on the target host.
4. Expand the held-out dataset with reviewed, privacy-protected examples from legitimate commerce and diverse scam categories before enabling candidate promotion out of shadow mode.
5. Review retention and consent paths to ensure private investigations do not become shared intelligence records automatically.
