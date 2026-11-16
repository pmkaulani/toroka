.PHONY: install test eval browser run migrate user registry-due registry-check purge live release
PY ?= python3
export DATABASE_URL ?= sqlite:///$(CURDIR)/ssi.db
export STORAGE_DIR ?= $(CURDIR)/evidence_store
PP = packages/core:packages/enterprise:packages/rules:packages/connectors:services/api
CLI = cd services/api && PYTHONPATH=../../packages/core:../../packages/enterprise:../../packages/rules:../../packages/connectors:. $(PY) -m app.cli

install:
	pip install -r requirements.txt
test:                      # Python tests (rules, connectors, API, web shell)
	$(PY) -m pytest -q
eval:                      # labelled evaluation (invented cases)
	PYTHONPATH=packages/rules $(PY) eval/run_eval.py
live:                      # real server over HTTP: every endpoint family, then a concurrent load
	$(PY) scripts/live_check.py
browser:                   # real Chromium: layout, keyboard, accessibility (axe), offline, errors  (cd web-tests && npm ci once)
	cd web-tests && node browser.mjs
run:
	PYTHONPATH=$(PP) $(PY) -m uvicorn app.main:app --app-dir services/api --reload --port 8000
migrate:
	cd services/api && PYTHONPATH=../../packages/core:../../packages/enterprise:../../packages/rules:../../packages/connectors:. $(PY) -m alembic upgrade head
user:                      # make user EMAIL=you@example.com [ROLE=moderator|admin]   (password: env SSI_NEW_PASSWORD, or prompted)
	$(CLI) create-user --email $(EMAIL) --role $(or $(ROLE),moderator)
registry-due:
	$(CLI) registry-due --days $(or $(DAYS),14)
registry-check:
	$(CLI) registry-check
purge:
	$(CLI) purge
release:                      # package clean release zip excluding secrets, db, venv, and stores
	$(PY) -c "import zipfile, os; exclude_dirs = {'.venv', 'node_modules', 'evidence_store', '.git', '__pycache__', '.pytest_cache', '.hypothesis'}; exclude_files = {'.env', 'ssi.db'}; out = 'Toroka_release.zip'; zf = zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED); [zf.write(os.path.join(r, f), os.path.join(r, f)) for r, d, fs in os.walk('.') for f in fs if not any(x in r.split(os.sep) for x in exclude_dirs) and f not in exclude_files and not f.startswith(('ssi.db', '.env.')) and not f.endswith(('.pyc', '.pyo', '.db', '.db-shm', '.db-wal')) and f != out and (f != '.env' and not f.endswith('.env'))]; zf.close(); print(f'Created {out} safely.')"

