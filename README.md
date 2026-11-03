# Toroka

*Toroka* is Swahili for "run away": the logo is a running figure. A Kenya-first, evidence-first scam checker you talk to like a chat assistant. Paste a message, link or seller details (or attach screenshots) and Toroka thinks, then replies with a label, the reasons, dated official sources, and what it could **not** check. It says when a website or shop is **verified** (from a reviewed, dated, revocable record), gives context-specific payment guidance, and never treats the absence of reports as proof of safety. It never accuses a person and is never a guarantee.

## Run it
```bash
make install
make test        # 224 Python tests (rules, fuzzing, connectors, API, web shell)
make eval        # labelled evaluation (29 invented cases)
make live        # starts the real server; every endpoint over HTTP; 600 concurrent requests
(cd web-tests && npm ci) && make browser      # real Chromium: 37 tests, chat flows, keyboard, accessibility (axe), offline
make migrate && make run                      # app at http://localhost:8000, API docs at /docs
make user EMAIL=you@example.com               # create a moderator (SSI_NEW_PASSWORD=... or you are prompted)
make registry-due      make registry-check    # official records due for review / pages that changed
make purge                                    # delete expired checks and files (run it daily)
```
Production-like: `cp .env.example .env`, set the keys, then `docker compose up` (not run in the authoring environment). Use PostgreSQL for real traffic: with SQLite, writes are serialised and it must run as a single process.

## What is built

**Built and tested here**
| Area | What it does |
|---|---|
| Check | Text in, label out (`high_risk`, `suspicious_verify_first`, `inconclusive`, `no_known_threats_found`) with findings, evidence type and strength, excerpts, dated sources, coverage (checked / not_checked / could_not_check / not_found), limitations, next steps. Deterministic policy v0.2; no model decides the label |
| Rules | PIN/OTP requests, advance fees, wrong-transfer reversals, prizes, urgency, shortened links, payment to mobile numbers, lookalike and mismatched domains, guaranteed returns, medical and "government approved" claims, discount framing. English and Swahili cues; false-positive guards for genuine warnings |
| Official sources | Safaricom and KRA statements, official domains and numbers; programme records in the database (admin editable) with review dates; stale sources lose weight; `registry-check` detects changed pages |
| Screenshots | Safe intake (type by content, size and pixel limits, EXIF stripped), OCR, encrypted storage, never served back, multi-piece assessment, location consistency, similar-image leads (weak) |
| Links | Redirect following with per-hop validation, DNS pinning and no body download; reputation provider interface (local blocklist; Web Risk adapter); RDAP age; place existence |
| Shops and claims | Seller profile extraction (platform, handle, prices, location, delivery and returns), safer-buying steps; weak signals are never treated as fraud proof |
| Community | Private reports; independence and duplicate handling; moderator queue; publication thresholds; public indicator search with anti-enumeration limits; urgent takedown; appeals with verification and an "under review" state; campaign clustering and entity edges; business claims that cannot suppress reports |
| Accounts and data | Register/login (scrypt), roles, history, delete, export, retention purge, audit log, rate limits |
| Recovery | Calm triage after paying or sharing, asks only what is missing, never promises recovery |
| Channels | WhatsApp and Africa's Talking SMS webhooks: signature check, parse, reply formatting (tested with sample payloads) |
| Chat interface | One box and one conversation, like talking to an AI: paste text, attach, paste or drop screenshots; Toroka thinks (the running figure animates), then replies in plain language with a verdict, the one warning that matters, next steps, and folded-away evidence, coverage, sources and limits. Quick replies for lookups, recovery, reporting and corrections. Installable PWA, English and Kiswahili (draft), share target, offline shell |
| Verified sites and shops | A fifth outcome, `verified_official`, only from a reviewed record (domain or social handle, basis, source, date, reviewer) that moderators can add, expire or revoke. It vouches for the site, never for an offer; a PIN or fee request in its name is still flagged. Shared hosts, lookalikes, http, punycode, IP and unresolved short links never verify. Shop guidance is contextual: verify the exact seller and recipient, understand written terms and buyer protection, and treat unexplained pressure or fee requests as risk signals rather than automatically labelling every deposit as fraud. |
| Operations | Alembic migrations, CLI (create-user, purge, registry-due, registry-check), evaluation harness, Dockerfile, compose, CI workflow |

**Built, but needs outside accounts or approval to go live (adapters tested with mocks only)**
Google Web Risk (licensed key), RDAP, OpenStreetMap Nominatim, WhatsApp Cloud API (business approval), Africa's Talking (account, and a short code for two-way SMS).

**Not built**
- A delivery worker for the notification outbox. Appeal verification codes and outcome messages are queued, not sent; `DEV_ECHO_CODES=1` exists for local development only.
- A moderator web console (moderation is API-only).
- A native Android app (the PWA share target is the bridge), institutional API, aggregate dashboards, business portal beyond claim records.
- Swahili OCR model, Sheng, other languages.
- Live social-platform checks (platforms restrict this), payment-destination ownership lookups, contacting senders.
- Key rotation, shared rate limiting across workers, a separate worker process for OCR and fetching (the pipeline is synchronous).

## API (see `/docs`)
`POST /v1/checks` · `GET /v1/checks/{id}` · `POST /v1/checks/{id}/evidence` · `GET .../export` · `DELETE /v1/checks/{id}` · `GET /v1/me/checks` · `POST /v1/recovery` · `GET /v1/opportunities` · `GET /v1/reports/search` · `POST /v1/reports` · `POST /v1/appeals` (+ `/verify`) · `POST /v1/business-claims` · `/v1/moderation/*` (queue, action, takedown, campaigns, appeals, claims) · `PUT /v1/admin/opportunities` · `/v1/channels/*` · `/v1/auth/*` · `/v1/health`, `/v1/ready`

## Layout
`design/figma-preview.html` four design frames rendered from the live site (for Figma import) · `packages/rules` pure assessment logic and data · `packages/connectors` I/O adapters · `services/api` FastAPI app, database, migrations, web app (`app/static`) · `eval` labelled cases · `web-tests` real-browser tests · `docs` ADRs, research plan, process, verification · `TASKS.md`, `CLAUDE.md`, `memory/`

## Read before relying on it
- **Registry records are `unreviewed`.** They were drafted from public pages on 20 Oct 2026 and need a human check against the live pages.
- **Rules are heuristic** and cover a small set of patterns; expect misses and false positives. Every miss or false alarm becomes a golden case. The evaluation messages are invented.
- **Not legal advice.** Wording, retention, public indicators and the dispute path need Kenyan counsel and data-protection advice before public launch (ADR-003).
- Verification record, including what was not tested: `docs/verification.md`. Screenshots from the browser tests: `docs/screenshots`.
