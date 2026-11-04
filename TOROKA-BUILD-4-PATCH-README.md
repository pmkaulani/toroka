# Toroka Build 4 Source Patch

This patch upgrades an existing Toroka Build 3 project. It is not a standalone application.

## Install

1. Back up your Toroka source tree, database and evidence storage.
2. Extract this ZIP into the existing `smart-scam-identifier` repository root, preserving the paths and allowing the listed files to be replaced.
3. From `services/api`, apply the migration:

   ```bash
   alembic upgrade head
   ```

4. Restart the backend and reload the frontend. The service-worker cache name changes in this patch so clients should receive the updated shell.
5. Run the focused checks:

   ```bash
   SSI_NO_WORKER=1 PYTHONPATH=../../packages/rules:../../packages/connectors:. pytest -q tests/test_toroka_build4_campaign_intelligence.py
   ```

## Files included

- `services/api/toroka_build4/`
- `services/api/app/db.py`
- `services/api/app/main.py`
- `services/api/app/routes_core.py`
- `services/api/app/pipeline.py`
- `services/api/app/routes_build4.py`
- `services/api/migrations/versions/0005_build4_campaign_intelligence.py`
- `services/api/app/static/` — updated chat, translations, styles, service worker and moderator console
- `services/api/tests/test_toroka_build4_campaign_intelligence.py`
- `services/api/tests/test_api_checks.py`
- Build 4 implementation, integration and product-destination notes

## Preserve

Keep your `.env`, encryption/HMAC keys, database, user data and evidence storage. Do not replace these with files from another environment. Back up first and do not reset production data.

## Security and behaviour

The guest check route stays guest-accessible. Campaign review and raw report detail are moderator/admin-only. Raw report detail is audited. Cross-case image matching is disabled by default and requires explicit consent for both the current and historical upload. Shared identifiers, repeated messages and image similarity are leads for review, not proof of fraud or common ownership.
