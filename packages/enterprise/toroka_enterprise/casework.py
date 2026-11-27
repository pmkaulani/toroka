"""Pseudonymised case workspace: RBAC, dual-approval identity reveal, closing discipline, everything audited.

Authentication/SSO is out of scope here: callers pass a Principal. In a bank deployment the Principal comes from the
bank's identity provider; this module only enforces what each role may do and records that it happened.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from cryptography.fernet import Fernet

from .audit import AuditLog

ROLES = {"investigator", "authoriser", "auditor", "system"}
DISPOSITIONS = {"substantiated_referral", "not_substantiated", "data_gap_or_control_weakness"}
REVEAL_TTL = timedelta(hours=24)


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: str
    role: str

    def __post_init__(self):
        if self.role not in ROLES:
            raise ValueError(f"unknown role {self.role}")


def generate_key() -> bytes:
    return Fernet.generate_key()


class CaseStore:
    def __init__(self, path: str | Path, audit: AuditLog, vault_key: bytes, clock: Callable[[], datetime] | None = None):
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self.audit, self._fernet = audit, Fernet(vault_key)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY AUTOINCREMENT, focus TEXT NOT NULL, label TEXT NOT NULL,
              snapshot TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL,
              disposition TEXT, closing_note TEXT, alternatives TEXT);
            CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL, ts TEXT NOT NULL, author TEXT NOT NULL, text TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS vault(pseudonym TEXT PRIMARY KEY, sealed BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS reveals(id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL, pseudonym TEXT NOT NULL,
              requested_by TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL, approved_by TEXT, approved_at TEXT, created_at TEXT NOT NULL);
        """)

    # ---- guards ----
    def _require(self, p: Principal, *roles: str, action: str, target: str = "") -> None:
        if p.role not in roles:
            self.audit.append(p.user_id, p.role, "authz.denied", target, {"attempted": action})
            raise PermissionError(f"role {p.role} may not {action}")

    def _now(self) -> str:
        return self._clock().astimezone(timezone.utc).isoformat()

    # ---- vault ----
    def store_vault(self, p: Principal, mapping: dict[str, str]) -> None:
        self._require(p, "system", action="store identity vault")
        with self._lock:
            with self._db:
                for pseudo, raw in mapping.items():
                    existing = self._db.execute("SELECT sealed FROM vault WHERE pseudonym=?", (pseudo,)).fetchone()
                    if existing is not None:
                        existing_raw = self._fernet.decrypt(existing["sealed"]).decode()
                        if existing_raw.casefold() != raw.casefold():
                            raise ValueError(f"vault collision: pseudonym '{pseudo}' is already bound to a different identity")
                        continue
                    self._db.execute("INSERT INTO vault(pseudonym, sealed) VALUES (?,?)", (pseudo, self._fernet.encrypt(raw.encode())))
            self.audit.append(p.user_id, p.role, "vault.store", "", {"entries": len(mapping)})

    # ---- cases ----
    def open_from_lead(self, p: Principal, lead: dict) -> int:
        self._require(p, "system", "investigator", action="open case")
        with self._lock:
            existing = self._db.execute("SELECT id FROM cases WHERE focus=? AND status='open'", (lead["focus"],)).fetchone()
            if existing:
                self.audit.append(p.user_id, p.role, "case.open_deduplicated", str(existing["id"]), {"focus": lead["focus"]})
                return existing["id"]
            with self._db:
                cur = self._db.execute("INSERT INTO cases(focus,label,snapshot,created_at) VALUES (?,?,?,?)",
                                       (lead["focus"], lead["label"], json.dumps(lead, sort_keys=True, default=str), self._now()))
            self.audit.append(p.user_id, p.role, "case.open", str(cur.lastrowid), {"focus": lead["focus"], "label": lead["label"]})
            return cur.lastrowid

    def list_cases(self, p: Principal, status: str | None = None) -> list[dict]:
        self._require(p, "investigator", "authoriser", "auditor", action="list cases")
        q = "SELECT id, focus, label, status, created_at, disposition FROM cases" + (" WHERE status=?" if status else "") + " ORDER BY id"
        with self._lock:
            return [dict(r) for r in self._db.execute(q, (status,) if status else ())]

    def view_case(self, p: Principal, case_id: int) -> dict:
        self._require(p, "investigator", "authoriser", "auditor", action="view case", target=str(case_id))
        with self._lock:
            row = self._db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not row:
                raise KeyError(case_id)
            self.audit.append(p.user_id, p.role, "case.view", str(case_id))
            out = dict(row)
            out["snapshot"] = json.loads(out["snapshot"])
            out["notes"] = [dict(n) for n in self._db.execute("SELECT ts, author, text FROM notes WHERE case_id=? ORDER BY id", (case_id,))]
            return out

    def add_note(self, p: Principal, case_id: int, text: str) -> None:
        self._require(p, "investigator", action="add note", target=str(case_id))
        if len(text.strip()) < 3:
            raise ValueError("note is empty")
        with self._lock:
            with self._db:
                self._db.execute("INSERT INTO notes(case_id,ts,author,text) VALUES (?,?,?,?)", (case_id, self._now(), p.user_id, text.strip()))
            self.audit.append(p.user_id, p.role, "case.note", str(case_id))

    # ---- dual-approval identity reveal ----
    def request_reveal(self, p: Principal, case_id: int, pseudonym: str, reason: str) -> int:
        self._require(p, "investigator", action="request identity reveal", target=str(case_id))
        with self._lock:
            row = self._db.execute("SELECT snapshot, status FROM cases WHERE id=?", (case_id,)).fetchone()
            if not row or row["status"] != "open":
                raise ValueError("case is not open")
            snap = json.loads(row["snapshot"])
            allowed = {snap.get("staff_ref"), snap.get("customer_ref"), snap.get("focus")}
            for ev in snap.get("result", {}).get("risk_evidence", []) + snap.get("result", {}).get("supporting_evidence", []):
                if isinstance(ev, dict) and ev.get("subject"):
                    allowed.add(ev["subject"])
            if pseudonym not in allowed and not any(pseudonym in (s or "").split("/") for s in allowed if s):
                raise ValueError("pseudonym does not appear in this case")
            if len(reason.strip()) < 20:
                raise ValueError("a reveal needs a written reason of at least 20 characters")
            with self._db:
                cur = self._db.execute("INSERT INTO reveals(case_id,pseudonym,requested_by,reason,status,created_at) VALUES (?,?,?,?, 'pending', ?)",
                                       (case_id, pseudonym, p.user_id, reason.strip(), self._now()))
            self.audit.append(p.user_id, p.role, "reveal.request", str(cur.lastrowid), {"case": case_id, "pseudonym": pseudonym})
            return cur.lastrowid

    def approve_reveal(self, p: Principal, request_id: int) -> None:
        self._require(p, "authoriser", action="approve identity reveal", target=str(request_id))
        with self._lock:
            r = self._db.execute("SELECT * FROM reveals WHERE id=?", (request_id,)).fetchone()
            if not r or r["status"] != "pending":
                raise ValueError("request is not pending")
            if r["requested_by"] == p.user_id:
                self.audit.append(p.user_id, p.role, "authz.denied", str(request_id), {"attempted": "self-approval of reveal"})
                raise PermissionError("a reveal cannot be approved by the person who requested it")
            with self._db:
                cur = self._db.execute("UPDATE reveals SET status='approved', approved_by=?, approved_at=? WHERE id=? AND status='pending'",
                                       (p.user_id, self._now(), request_id))
                if cur.rowcount != 1:     # lost a race with another decision on the same request
                    raise ValueError("request is not pending")
            self.audit.append(p.user_id, p.role, "reveal.approve", str(request_id), {"requested_by": r["requested_by"]})

    def reveal(self, p: Principal, request_id: int) -> str:
        self._require(p, "investigator", action="use identity reveal", target=str(request_id))
        with self._lock:
            r = self._db.execute("SELECT * FROM reveals WHERE id=?", (request_id,)).fetchone()
            if not r or r["requested_by"] != p.user_id:
                raise PermissionError("only the requester can use an approved reveal")
            if r["status"] != "approved":
                raise PermissionError(f"reveal is {r['status']}, not approved")
            if self._clock() - datetime.fromisoformat(r["approved_at"]) > REVEAL_TTL:
                with self._db:
                    self._db.execute("UPDATE reveals SET status='expired' WHERE id=?", (request_id,))
                self.audit.append(p.user_id, p.role, "reveal.expired", str(request_id))
                raise PermissionError("approval has expired")
            sealed = self._db.execute("SELECT sealed FROM vault WHERE pseudonym=?", (r["pseudonym"],)).fetchone()
            if not sealed:
                raise KeyError("no vault entry for this pseudonym")
            with self._db:
                cur = self._db.execute("UPDATE reveals SET status='used' WHERE id=? AND status='approved'", (request_id,))
                if cur.rowcount != 1:     # single use: a concurrent consumer got there first
                    raise PermissionError("reveal is no longer approved")
            self.audit.append(p.user_id, p.role, "reveal.use", str(request_id), {"case": r["case_id"], "pseudonym": r["pseudonym"], "approved_by": r["approved_by"]})
            return self._fernet.decrypt(sealed["sealed"]).decode()

    # ---- closing discipline ----
    def close_case(self, p: Principal, case_id: int, disposition: str, note: str, alternatives_considered: str) -> None:
        self._require(p, "investigator", action="close case", target=str(case_id))
        if disposition not in DISPOSITIONS:
            raise ValueError(f"disposition must be one of {sorted(DISPOSITIONS)}")
        if len(note.strip()) < 10 or len(alternatives_considered.strip()) < 20:
            raise ValueError("closing needs a note and a written account of the alternative explanations considered")
        with self._lock:
            row = self._db.execute("SELECT status FROM cases WHERE id=?", (case_id,)).fetchone()
            if not row or row["status"] != "open":
                raise ValueError("case is not open")
            with self._db:
                self._db.execute("UPDATE cases SET status='closed', disposition=?, closing_note=?, alternatives=? WHERE id=?",
                                 (disposition, note.strip(), alternatives_considered.strip(), case_id))
            self.audit.append(p.user_id, p.role, "case.close", str(case_id), {"disposition": disposition})
