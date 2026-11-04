# Toroka Build 3 — source patch installation

This patch targets the Toroka Build 2 project used to produce Build 3.

1. Back up the application source and production database.
2. Extract the patch at the existing project root, preserving paths.
3. Keep `.env`, the production database, evidence storage, HMAC/encryption keys and ML runtime state from your existing installation.
4. Run `cd services/api && alembic upgrade head` using the existing production database URL.
5. From the project root, run `SSI_NO_WORKER=1 pytest -q --ignore=packages/rules/tests/test_robustness.py`.
6. Restart the API and confirm the `/v1/build3/...` routes are available in `/docs`.
7. Import an official NEA register CSV as a moderator. BRS records must be entered only after a moderator has performed the official eCitizen search.

The patch deliberately excludes credentials, databases, private evidence files, runtime queues and model artifacts. Do not replace your `.env` or rotate HMAC/encryption keys during this update; changing the HMAC key breaks continuity with previously stored hashed entity identifiers unless you perform a planned migration.

Rollback: first deploy code that does not use Build 3, then back up any Build 3 records that must be retained and run `cd services/api && alembic downgrade 0003`. This deletes the four Build 3 tables.
