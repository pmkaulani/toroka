# What was verified, and how

Run in the authoring environment on 22 Oct 2026. Re-run everything with `make test`, `make eval`, `make live` and `make browser`.

| Layer | How | Result |
|---|---|---|
| Rules, registry, policy, claims, shop, location, fingerprints, recovery, Swahili copy | Golden cases and false-positive guards in `packages/rules/tests` | passing |
| Fuzzing and worst-case timing | Hypothesis: 550+ random and adversarial inputs (any Unicode, up to 5,000 characters) must never raise, never leak a PIN, return valid offsets and finish in under 1.5 s; 24 pathological strings (regex stress) each under 1 s; a typical message under 20 ms | passing. Found and fixed: excerpt/offset mismatch on two findings |
| Connectors | `packages/connectors/tests` with mock transports and fake resolvers: SSRF and DNS-pinning cases, Web Risk shape, RDAP, geocoder, image sanitiser, real OCR on a generated image, webhook signatures | passing |
| API | `services/api/tests` on in-memory SQLite: checks, evidence, accounts, reports, moderation, appeals, indicators, opportunities, channels, rate limits, encryption at rest, erasure, CLI, migrations vs models, design-token contrast | passing |
| Real server over HTTP | `scripts/live_check.py` starts uvicorn and drives every endpoint family (including multipart upload, moderator workflow, appeals, webhooks, malformed and hostile requests), then 600 mixed requests from 32 concurrent clients | passing; no 5xx, no traceback, no message text in the server log. Found and fixed: "database is locked" under concurrency |
| Real browser | `web-tests/browser.mjs`: Chromium 153 driven by Playwright, 37 tests of the chat interface at desktop (1280px) and phone (360px, touch) sizes: clean console and no CSP violations; the runner animates, rests, and obeys reduced motion; thinking state; five outcomes with five shapes; verified website and shop (site and Instagram handle), revocation, lookalikes; the no-advance-payment warning; keyboard-only use with visible focus; screen-reader structure and announcements; screenshots by file chooser, paste and drop; lookup, report, appeal and recovery by chat; delete and download; Kiswahili; New chat; server error, 429, offline and slow network; hostile text; 200% text size; no sideways scrolling; 44px touch targets; axe-core (WCAG 2.1 A and AA plus best practice, including colour contrast) on every reply type in English, Kiswahili and phone size | 37 of 37. Found and fixed: replies typed before Toroka finished speaking were misrouted; the send box stayed locked after an error; action buttons disabled each other; no landmark or h1 once the welcome screen was gone; small tap targets on source links; shared-link token lingered in the address bar |
| Evaluation | `eval/run_eval.py` on 29 invented labelled messages | pass |
| Screenshots | `docs/screenshots` (taken by the browser suite) | reviewed by eye |

## Not verified here
- **Other browsers.** Only Chromium was available. Firefox, Safari and iOS WebKit were not run. The code avoids regex lookbehind and CSS `:has()` for older browsers, but that is untested.
- **Real devices, screen readers and networks.** No physical phone, TalkBack, VoiceOver or NVDA, and no throttled mobile connection. axe-core finds a large share of accessibility problems, not all of them.
- **Live third-party services:** Google Web Risk, RDAP, Nominatim, WhatsApp Cloud API, Africa's Talking. Mock-tested only.
- **PostgreSQL.** Everything ran on SQLite. The Dockerfile, compose file and CI workflow were not run.
- **Capacity.** The load run shared one CPU core between server and load generator and measured about 21 requests per second with 32 clients and no errors; a single check costs about 12 ms of processing. This is not a capacity claim. With SQLite, writes are serialised (and an OCR upload holds that lock), so use PostgreSQL for real traffic and one process per SQLite file.
- **Real-world accuracy.** Evaluation messages are invented. Numbers on them are a regression check.
- **Swahili:** OCR model not installed; UI and result text are drafts awaiting native review.
- **Security review by a third party**, dependency scanning, and penetration testing.
