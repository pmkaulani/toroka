import os
from datetime import date

import httpx
import pytest
from app import cli
from app import db as m
from app.config import Settings
from sqlalchemy import select

PUBLIC = lambda host: ["93.184.216.34"]


@pytest.fixture
def cctx(tmp_path):
    return cli.build_ctx(Settings(database_url="sqlite://", storage_dir=str(tmp_path / "ev")))


def test_create_user_and_role_rules(cctx):
    uid = cli.create_user(cctx, "Mod@Example.com", "moderator", "a long enough password")
    with cctx.sessionmaker() as db:
        assert db.get(m.User, uid).role == "moderator"
    with pytest.raises(SystemExit):
        cli.create_user(cctx, "mod@example.com", "moderator", "a long enough password")      # duplicate
    with pytest.raises(SystemExit):
        cli.create_user(cctx, "x@example.com", "superuser", "a long enough password")
    with pytest.raises(SystemExit):
        cli.create_user(cctx, "y@example.com", "admin", "short")


def test_registry_due_lists_stale_and_upcoming_items(cctx):
    from app.seed import seed_opportunities
    with cctx.sessionmaker() as db:
        seed_opportunities(db)
    soon = cli.registry_due(cctx, days=14, today=date(2027, 1, 10))
    assert {r["kind"] for r in soon} == {"statement", "opportunity"} and all(not r["stale"] for r in soon)
    late = cli.registry_due(cctx, days=14, today=date(2027, 3, 1))
    assert late and all(r["stale"] for r in late)
    assert cli.registry_due(cctx, days=14, today=date(2026, 10, 25)) == []


def test_registry_check_detects_changes_never_edits_records(cctx):
    from app.seed import seed_opportunities
    with cctx.sessionmaker() as db:
        seed_opportunities(db)
    page = {"text": "<html><body><script>var x=1</script><h1>Recruitment fraud</h1><p>We charge no fee.</p></body></html>"}
    t = httpx.MockTransport(lambda r: httpx.Response(200, text=page["text"]))
    first = cli.registry_check(cctx, transport=t, resolver=PUBLIC)
    assert {r["result"] for r in first} == {"first_snapshot"}
    assert {r["result"] for r in cli.registry_check(cctx, transport=t, resolver=PUBLIC)} == {"unchanged"}
    page["text"] = page["text"].replace("no fee", "a small fee")
    assert {r["result"] for r in cli.registry_check(cctx, transport=t, resolver=PUBLIC)} == {"CHANGED: review needed"}
    with cctx.sessionmaker() as db:
        assert db.get(m.Opportunity, "kra-careers").last_verified_at == "2026-10-20"                     # humans re-verify; the tool does not
    down = httpx.MockTransport(lambda r: httpx.Response(503))
    assert {r["result"] for r in cli.registry_check(cctx, transport=down, resolver=PUBLIC)} == {"could_not_check"}


def test_fetch_text_blocks_private_hosts_and_strips_scripts():
    from ssi_connectors import safe_fetch
    seen = []
    t = httpx.MockTransport(lambda r: (seen.append(r), httpx.Response(200, text="<p>Hello</p><style>x{}</style><script>evil()</script>"))[1])
    assert safe_fetch.fetch_text("http://10.0.0.1/", transport=t, resolver=PUBLIC).reason.startswith("blocked") and not seen
    p = safe_fetch.fetch_text("http://example.com/", transport=t, resolver=PUBLIC)
    assert p.text == "Hello" and p.status.value == "checked"
    big = httpx.MockTransport(lambda r: httpx.Response(200, text="<p>" + "a" * 3_000_000 + "</p>"))
    assert len(safe_fetch.fetch_text("http://example.com/", transport=big, resolver=PUBLIC, max_bytes=1000).text) <= 1000


def test_migrations_match_the_models(tmp_path, monkeypatch):
    from alembic import command
    from alembic.config import Config
    api = os.path.dirname(os.path.dirname(__file__))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/mig.db")
    cfg = Config(os.path.join(api, "alembic.ini")); cfg.set_main_option("script_location", os.path.join(api, "migrations"))
    command.upgrade(cfg, "head")
    command.check(cfg)                            # raises if the models have drifted from the migrations
