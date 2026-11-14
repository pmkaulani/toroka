"""Append-only, hash-chained audit log. Tamper-evident, not tamper-proof.

Each entry commits to the previous entry's hash. SQLite triggers block UPDATE/DELETE through normal access,
and verify() detects edits, deletions and reordering even if someone bypasses the triggers. To make deletion of
the TAIL detectable too, periodically copy head_hash to a system the database administrator does not control.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

GENESIS = "0" * 64


@dataclass
class VerifyResult:
    ok: bool
    checked: int
    head_hash: str
    problems: list[str] = field(default_factory=list)


def _digest(prev: str, seq: int, ts: str, actor: str, role: str, action: str, target: str, detail: str) -> str:
    payload = json.dumps([prev, seq, ts, actor, role, action, target, detail], separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path, clock: Callable[[], datetime] | None = None):
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS audit(
              seq INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL, role TEXT NOT NULL, action TEXT NOT NULL,
              target TEXT NOT NULL, detail TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
        """)

    def append(self, actor: str, role: str, action: str, target: str = "", detail: dict | None = None) -> str:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._db.execute("SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
                seq, prev = (row[0] + 1, row[1]) if row else (1, GENESIS)
                ts = self._clock().astimezone(timezone.utc).isoformat()
                body = json.dumps(detail or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                h = _digest(prev, seq, ts, actor, role, action, target, body)
                self._db.execute("INSERT INTO audit VALUES (?,?,?,?,?,?,?,?,?)", (seq, ts, actor, role, action, target, body, prev, h))
                self._db.execute("COMMIT")
                return h
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def entries(self, action: str | None = None) -> list[dict]:
        q, args = "SELECT seq, ts, actor, role, action, target, detail, hash FROM audit", ()
        if action:
            q, args = q + " WHERE action = ?", (action,)
        cols = ("seq", "ts", "actor", "role", "action", "target", "detail", "hash")
        return [dict(zip(cols, r)) for r in self._db.execute(q + " ORDER BY seq", args)]

    def verify(self) -> VerifyResult:
        prev, expected, problems, count = GENESIS, 1, [], 0
        for seq, ts, actor, role, action, target, detail, prev_hash, h in self._db.execute(
                "SELECT seq, ts, actor, role, action, target, detail, prev_hash, hash FROM audit ORDER BY seq"):
            count += 1
            if seq != expected:
                problems.append(f"sequence gap before entry {seq} (expected {expected}): entries were deleted or reordered")
                expected = seq
            if prev_hash != prev:
                problems.append(f"entry {seq}: previous-hash link is broken")
            if _digest(prev_hash, seq, ts, actor, role, action, target, detail) != h:
                problems.append(f"entry {seq}: content does not match its hash")
            prev, expected = h, expected + 1
        return VerifyResult(not problems, count, prev, problems)
