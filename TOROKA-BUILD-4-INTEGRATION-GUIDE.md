# Build 4 Integration Guide

## Before deployment

1. Back up the application database and evidence storage.
2. Install the updated source files, preserving `.env`, encryption/HMAC keys, user data and evidence objects.
3. Apply database migrations from `services/api`:

   ```bash
   alembic upgrade head
   ```

4. Restart the API and serve a fresh frontend shell (the service-worker cache version was bumped).
5. Run the focused tests and the existing regression suite.

## User-facing flow

The existing guest chat flow is unchanged. When a user attaches images, a new optional control explains cross-case image matching. It is unchecked by default. Selecting it opts those uploads into matching across cases. A match is only evaluated when the previous upload also explicitly opted in.

Campaign observations appear in an English/Kiswahili panel as context and limitations. They do not replace the existing assessment verdict.

## Moderator flow

Authenticated moderators/admins can:

- Fetch `/v1/moderation/build4/campaigns`.
- Review candidate reports/check references and masked identifiers.
- Fetch an underlying report through `/v1/moderation/build4/reports/{report_id}`; the route returns decrypted narrative only to moderators and records an audit event.
- Save a disposition through `/v1/moderation/build4/campaigns/{campaign_id}/review`.

A disposition is internal. It does not automatically publish a public accusation or modify a seller's risk label.

## Configuration and security

No new provider credentials are required for the Build 4 core. Existing guest access remains enabled for `/v1/checks`. Moderator routes require the existing moderator/admin roles. Keep the application's encryption and HMAC secrets stable across upgrades. Do not expose the moderator API to public clients.

## Test commands

From `services/api`:

```bash
SSI_NO_WORKER=1 PYTHONPATH=../../packages/rules:../../packages/connectors:. pytest -q tests/test_toroka_build4_campaign_intelligence.py
```

The complete project suite can be run from the repository root:

```bash
SSI_NO_WORKER=1 PYTHONPATH=packages/rules:packages/connectors:services/api python -m pytest -q --ignore=packages/rules/tests/test_robustness.py
```

The Hypothesis robustness file needs the optional `hypothesis` dependency.
