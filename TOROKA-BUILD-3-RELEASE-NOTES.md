# Toroka Build 3 release package

This archive is based on the uploaded Toroka Build 2 project and includes Build 3 source, migrations, tests and documentation.

## Runtime files intentionally excluded

- `.env` and non-example environment files
- Local databases, evidence blobs and application storage
- Git history, caches, virtual environments and compiled Python files
- ML jobs/telemetry and local feedback/staging queues
- Temporary model candidates and the test-only rollback model

The verified champion model is retained. The configured shadow candidate is retained when referenced by `active_model.json`; a test-only rollback pointer is cleared in the release copy. Your original uploaded project is not modified.

## Apply safely

Back up your current source and database. Review `TOROKA-BUILD-3-PATCH-README.md` for patch installation. Apply the Alembic migration with the existing production database URL and keep your current HMAC/encryption secrets unchanged.

## Verification

See `TOROKA-BUILD-3-IMPLEMENTATION-REPORT.md` for test counts, migration verification and known operational limits.
