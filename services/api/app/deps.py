from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db as m
from .config import Settings
from .pipeline import Deps
from .ratelimit import RateLimiter
from .security import Crypto, sha256


@dataclass
class Ctx:
    settings: Settings
    crypto: Crypto
    limiter: RateLimiter
    deps: Deps
    sessionmaker: object
    senders: dict


def ctx(request: Request) -> Ctx:
    return request.app.state.ctx


_SQLITE_WRITES = threading.Lock()


def get_db(request: Request):
    """One session per request. With SQLite (development and small pilots) write requests are serialised in this process,
    because concurrent writers otherwise fail with 'database is locked'. PostgreSQL needs no such lock."""
    c = request.app.state.ctx
    serialise = c.settings.database_url.startswith("sqlite") and request.method not in ("GET", "HEAD", "OPTIONS")
    if serialise:
        _SQLITE_WRITES.acquire()
    db = c.sessionmaker()
    try:
        yield db
    finally:
        db.close()
        if serialise:
            _SQLITE_WRITES.release()


def client_key(request: Request, c: Ctx) -> str:
    ip = request.client.host if request.client else "unknown"
    if c.settings.trust_proxy_headers and request.headers.get("x-forwarded-for"):
        ip = request.headers["x-forwarded-for"].split(",")[0].strip()
    return c.crypto.lookup("client", ip)


def current_user(request: Request, db: Session = Depends(get_db), authorization: str | None = Header(default=None)) -> m.User | None:
    if not authorization or not authorization.lower().startswith("bearer "):
        return None
    s = db.get(m.SessionToken, sha256(authorization[7:].strip()))
    if not s or s.expires_at < m.now_iso():
        return None
    u = db.get(m.User, s.user_id)
    return u if u and u.status == "active" else None


def require_user(u: m.User | None = Depends(current_user)) -> m.User:
    if not u:
        raise HTTPException(401, "Sign in to do this.")
    return u


def require_role(*roles: str):
    def dep(u: m.User = Depends(require_user)) -> m.User:
        if u.role not in roles:
            raise HTTPException(403, "You do not have permission to do this.")
        return u
    return dep


def throttle(request: Request, c: Ctx, name: str, limit: tuple, key: str | None = None):
    wait = c.limiter.hit(f"{name}:{key or client_key(request, c)}", limit[0], limit[1])
    if wait:
        raise HTTPException(429, f"Too many requests. Please try again in {int(wait // 60) + 1} minute(s).", headers={"Retry-After": str(int(wait) + 1)})


def audit(db: Session, request: Request, actor: str | None, action: str, target_type: str, target_id: str | None, meta: dict | None = None):
    db.add(m.AuditEvent(actor_id=actor, action=action, target_type=target_type, target_id=target_id,
                        request_id=getattr(request.state, "request_id", None), safe_metadata=meta or {}))


def expiry(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(timespec="seconds")
