# Toroka Build 2 — Source Patch

This patch applies Build 2 to the Build 1 project structure supplied by the user.

## Before applying

1. Stop the Toroka API service.
2. Make a complete backup of the project directory and database.
3. Keep the original `.env` outside version control and do not overwrite it.
4. Confirm the project root is the directory containing `services/`, `packages/` and `.env.example`.

## Apply

Extract this ZIP into the project root, preserving folder paths and allowing the listed source files to be overwritten. The archive intentionally contains no `.env`, database, evidence blobs, `.git` history, virtual environment or runtime cache.

Merge these optional settings into the existing backend `.env` manually:

```dotenv
ENABLE_DOMAIN_INTELLIGENCE=0
CERTSPOTTER_API_KEY=
DOMAIN_INTEL_INCLUDE_SUBDOMAINS=0
```

Keep `ENABLE_DOMAIN_INTELLIGENCE=0` until you have reviewed provider terms, network egress, request budgets and privacy implications. Set it to `1` to enable passive domain infrastructure observations. Certificate Transparency lookup remains disabled unless an approved `CERTSPOTTER_API_KEY` is configured. Subdomain expansion remains off unless explicitly enabled.

## Verify

From the project root:

```bash
pytest -q services/api/tests packages/connectors/tests
pytest -q packages/rules/tests --ignore=packages/rules/tests/test_robustness.py
node --check services/api/app/static/app.js
node --check services/api/app/static/i18n.js
```

The uploaded Build 1 `.env` and local data are deliberately not included. Provider requests were mocked during Build 2 tests; this package does not claim that live credentials or live provider lookups have been tested.
