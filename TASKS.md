# Tasks

## Active
- [ ] **Review and add verified sites and shops** - only Safaricom and KRA are verified today (from their own pages). Decide the standard of proof for shops (business registration, till name match, owner contact) before verifying anyone; verification is a public promise
- [ ] **Native-speaker review of Toroka's Kiswahili** - including the verified and payment-warning copy
- [ ] **Get Toroka's design into Figma** - the file `Smart Scam Identifier: website design` exists but is empty and shows the old layout: the Figma write step was not approved and the sandbox cannot reach mcp.figma.com. The chat interface is simple enough to redraw natively once approved
- [ ] **Get Kenyan counsel and data-protection advice before real users** - lawful basis, registration, impact assessment, defamation review of public indicators and wording, terms for reports; ADR-003
- [ ] **Run the interviews and the six-message test** - docs/research; the product still has no evidence from real users
- [ ] **Human-review every registry statement and programme record against the live pages** - all marked `unreviewed`; `python -m app.cli registry-due`
- [ ] **Get live credentials and verify the adapters** - Google Web Risk key (licensed), RDAP, Nominatim contact agent; then run each once for real
- [ ] **Apply for WhatsApp Business access and an SMS short code** - needed before forward-to-check can go live
- [ ] **Run on PostgreSQL** - `docker compose up`, `make migrate`, rerun the suite; migrations were only exercised on SQLite
- [ ] **Native-speaker review of the Swahili strings; install the Swahili OCR model** - UI and result copy are drafts
- [ ] **Decide hosting and region (ADR-004)** - cost, latency from Nairobi, data-protection implications
- [ ] **Key management and rotation, backup retention matching the purge** - ADR-003 action 3
- [ ] **Accept or change ADR-001 to ADR-003** - ADR-001 still asks whether Python suits you
- [ ] **Check name, domain and trademark availability** - the working name promises an identification the product avoids
- [ ] **Test on real phones and other browsers** - TalkBack on a low-end Android first, Safari on iPhone, Firefox; slow mobile network. Only Chromium was run (40 browser tests pass)

## Waiting On

## Someday
- [ ] Separate worker process for OCR and link fetching in an egress-restricted network
- [ ] Shared rate limiting (Redis or the gateway) before running several workers
- [ ] Native Android app with share-to-check
- [ ] Institutional API and aggregate dashboards (gated on volume and governance)
- [ ] Evaluation set from consented real messages
- [ ] Sheng and further Swahili rule coverage

## Done
- [x] ~~Social Intelligence Layer Integration (Weir X/Reddit, Scrape Creators IG/TikTok/FB, exact-identity normalization, complaint patterns, and honest provider status)~~ (2026-11-01)
- [x] ~~Conversational UI Redesign & Live Investigation Narration (Antigravity Handoff integration with open assessment reports, real activity narration, WCAG AA compliance, and full EN/SW localization)~~ (2026-11-01)
- [x] ~~Autonomous AI Fraud Investigator agent (multimodal vision, Kenyan fraud intelligence, multi-turn chat)~~ (2026-10-25)
- [x] ~~Build a moderator web console (`services/api/app/static/moderator.html`)~~ (2026-10-25)
- [x] ~~Build notification outbox delivery worker (`python -m app.cli drain-outbox`)~~ (2026-10-25)
- [x] ~~Catch real Kenyan scam vectors (task scams, WhatsApp recruitment bait, price anomalies, M-PESA SMS guidance)~~ (2026-10-25)
- [x] ~~Blueprint review (competitive brief, brainstorm, research synthesis, accessibility, design system)~~ (2026-10-20)
- [x] ~~Rules engine, policy v0.2, claims, shop, location, fingerprints, recovery, Swahili copy~~ (2026-10-20)
- [x] ~~Connectors: safe redirects, reputation, RDAP, geocoder, OCR, image sanitiser, channel adapters~~ (2026-10-20)
- [x] ~~API: checks, evidence, accounts, reports, moderation, indicators, appeals, business claims, opportunities, channels, rate limits~~ (2026-10-20)
- [x] ~~Persistence with encryption, erasure, retention purge, Alembic migrations~~ (2026-10-20)
- [x] ~~Toroka chat interface with animated runner logo, verified sites and shops, no-advance-payment warning; 37 real-browser tests~~ (2026-10-22)
- [x] ~~CLI, evaluation harness, Dockerfile, compose, CI workflow~~ (2026-10-20)
- [x] ~~Design tokens fixed (amber, border) and the unknown-state vocabulary applied~~ (2026-10-20)
- [x] ~~ADR-001 to ADR-003, research plan, interview guide, process optimization~~ (2026-10-20)
