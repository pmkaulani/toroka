# Toroka Build 4 — Fraud Campaign Intelligence

## Summary

Build 4 adds evidence-backed campaign correlation to the existing Build 3 application. It is integrated into the normal `/v1/checks` path and into the moderator console. It does not replace the existing assessment or publish campaign accusations.

## What changed

- Added `services/api/toroka_build4/campaigns.py` for campaign-context generation and moderator candidate clustering.
- Added `CampaignReview` persistence and Alembic migration `0005_build4_campaign_intelligence.py`.
- Added moderator-only campaign queue, campaign disposition and audited private-report detail routes in `app/routes_build4.py`.
- Integrated published-indicator and campaign context into `POST /v1/checks`.
- Added user-facing English/Kiswahili campaign context and explicit image-sharing consent controls.
- Added moderator UI for reviewing evidence candidates, recording a disposition and opening private report details with audit logging.
- Corrected legacy cross-case image matching so both the current and historical upload must explicitly opt in.

## Evidence boundaries

- Shared identifiers, similar advertisement text and reused images are investigative leads, not proof of common ownership or fraud.
- Public case context uses published/moderated indicators only. Pending/private report narratives are not exposed.
- Related identifiers are surfaced only when the co-occurrence meets the configured independent-report threshold.
- Image matching is opt-in for both sides. It returns aggregate counts in consumer context, not case IDs or another user's private report.
- Moderators can inspect underlying report narratives through a role-restricted, rate-limited, audited endpoint.
- Campaign review dispositions are internal moderation records. They do not automatically alter seller or identifier risk labels.

## Database

Migration `0005_build4_campaign_intelligence.py` adds the `campaign_reviews` table. Back up the database before applying migrations.

## Tests and checks

- Build 4 focused tests: 9 passed.
- Main image-consent regression: passed.
- English/Kiswahili UI string parity test: passed.
- Full available regression suite: 757 passed with 2 Alembic deprecation warnings. Pytest printed its complete summary, but the process did not exit before the external execution timeout. The final isolated Build 4 suite passed 9/9, and the extracted-release focused suite passed 11/11.
- Optional Hypothesis robustness test file was excluded because the dependency was unavailable.
- Python compilation, JavaScript syntax checks and clean SQLite migration passed.

No live third-party lookups were needed for these tests.
