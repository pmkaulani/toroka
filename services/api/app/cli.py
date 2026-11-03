"""Operations commands:  python -m app.cli <command>   (run from services/api with PYTHONPATH set as in the Makefile)

  create-user --email E --role moderator|admin   (password is read from SSI_NEW_PASSWORD or prompted)
  purge                                         delete expired checks, evidence files and sessions
  registry-due [--days 14]                      official statements and programme records due for review
  registry-check                                fetch each official source and report which pages changed since last time
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
import sys
from datetime import date, timedelta

from sqlalchemy import select
from ssi_connectors import safe_fetch
from ssi_rules import load_registry

from . import db as m
from .config import Settings
from .deps import Ctx
from .pipeline import Deps
from .ratelimit import RateLimiter
from .routes_core import purge_expired
from .security import Crypto, hash_password
from .seed import seed_opportunities, seed_verified


def build_ctx(settings: Settings | None = None) -> Ctx:
    s = (settings or Settings.from_env()).with_dev_keys()
    engine = m.make_engine(s.database_url)
    m.Base.metadata.create_all(engine)
    return Ctx(s, Crypto(s.encryption_key, s.hmac_key), RateLimiter(), Deps(), m.make_sessionmaker(engine), {})


def create_user(c: Ctx, email: str, role: str, password: str) -> str:
    if role not in ("user", "moderator", "admin") or len(password) < 10:
        raise SystemExit("role must be user|moderator|admin and the password at least 10 characters")
    with c.sessionmaker() as db:
        h = c.crypto.lookup("email", email.strip().lower())
        if db.execute(select(m.User).where(m.User.email_hmac == h)).scalar_one_or_none():
            raise SystemExit("that email already has an account")
        u = m.User(email_hmac=h, email_encrypted=c.crypto.enc(email.strip().lower()), password_hash=hash_password(password), role=role)
        db.add(u)
        db.add(m.AuditEvent(actor_id=None, action="user.create_cli", target_type="user", target_id=u.id, safe_metadata={"role": role}))
        db.commit()
        return u.id


def registry_due(c: Ctx, days: int = 14, today: date | None = None) -> list[dict]:
    today = today or date.today()
    horizon = today + timedelta(days=days)
    out = [{"kind": "statement", "id": s.id, "source_url": s.source_url, "review_due": s.review_due().isoformat(), "stale": s.is_stale(today), "reviewer": s.reviewer}
           for s in load_registry().statements.values() if s.review_due() <= horizon]
    with c.sessionmaker() as db:
        out += [{"kind": "opportunity", "id": o.id, "source_url": o.source_url, "review_due": o.review_due, "stale": date.fromisoformat(o.review_due) < today, "reviewer": o.reviewer}
                for o in db.execute(select(m.Opportunity)).scalars() if date.fromisoformat(o.review_due) <= horizon]
    return sorted(out, key=lambda r: r["review_due"])


def registry_check(c: Ctx, transport=None, resolver=None) -> list[dict]:
    """Change detection only: it never edits a record or its verification date. A human re-verifies and updates."""
    urls = {s.source_url for s in load_registry().statements.values()}
    with c.sessionmaker() as db:
        urls |= {o.source_url for o in db.execute(select(m.Opportunity)).scalars()}
        results = []
        for u in sorted(urls):
            kw = {"transport": transport}
            if resolver:
                kw["resolver"] = resolver
            page = safe_fetch.fetch_text(u, **kw)
            if page.status.value != "checked":
                results.append({"url": u, "result": "could_not_check", "reason": page.reason})
                continue
            digest = hashlib.sha256(page.text.encode()).hexdigest()
            snap = db.get(m.SourceSnapshot, u)
            if not snap:
                db.add(m.SourceSnapshot(url=u, text_sha256=digest, text_length=len(page.text)))
                results.append({"url": u, "result": "first_snapshot"})
            elif snap.text_sha256 != digest:
                snap.text_sha256, snap.text_length, snap.fetched_at = digest, len(page.text), m.now_iso()
                results.append({"url": u, "result": "CHANGED: review needed"})
            else:
                snap.fetched_at = m.now_iso()
                results.append({"url": u, "result": "unchanged"})
        db.commit()
    return results


def drain_outbox(c: Ctx) -> int:
    """Send queued notifications via configured channel senders or development echo."""
    sent_count = 0
    with c.sessionmaker() as db:
        pending = db.execute(select(m.Notification).where(m.Notification.status == "queued")).scalars().all()
        for n in pending:
            to = c.crypto.dec(n.to_encrypted)
            payload = json.loads(c.crypto.dec(n.payload_encrypted))
            sender = c.senders.get(n.channel)
            success = False
            if sender:
                body = payload.get("body") or payload.get("code") or json.dumps(payload)
                success = sender.send_text(to, body)
            else:
                # Local development or fallback console dispatch
                print(f"[OUTBOX DISPATCH] id={n.id} channel={n.channel} to={to} payload={payload}")
                success = True

            if success:
                n.status = "sent"
                n.sent_at = m.now_iso()
                sent_count += 1
        db.commit()
    return sent_count


def main(argv=None):
    ap = argparse.ArgumentParser(prog="app.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    cu = sub.add_parser("create-user"); cu.add_argument("--email", required=True); cu.add_argument("--role", default="moderator")
    sub.add_parser("purge")
    rd = sub.add_parser("registry-due"); rd.add_argument("--days", type=int, default=14)
    sub.add_parser("registry-check")
    sub.add_parser("drain-outbox")
    a = ap.parse_args(argv)
    c = build_ctx()
    with c.sessionmaker() as db:
        seed_opportunities(db)
        seed_verified(db)
    if a.cmd == "create-user":
        pw = os.environ.get("SSI_NEW_PASSWORD") or getpass.getpass("Password (10+ characters): ")
        print("created", create_user(c, a.email, a.role, pw))
    elif a.cmd == "purge":
        with c.sessionmaker() as db:
            print("purged checks:", purge_expired(db, c))
    elif a.cmd == "registry-due":
        for r in registry_due(c, a.days):
            print(("STALE " if r["stale"] else "due   ") + f"{r['review_due']}  {r['kind']:<11} {r['id']:<28} {r['reviewer']:<12} {r['source_url']}")
    elif a.cmd == "registry-check":
        for r in registry_check(c):
            print(f"{r['result']:<24} {r['url']}" + (f"  ({r['reason']})" if r.get("reason") else ""))
    elif a.cmd == "drain-outbox":
        count = drain_outbox(c)
        print(f"dispatched {count} queued notification(s)")


if __name__ == "__main__":
    sys.exit(main())
