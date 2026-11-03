from __future__ import annotations

import contextlib
import hashlib
import hmac
import ipaddress
import os
import re
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Literal
from urllib.parse import urlsplit, urlunsplit

IdentifierType = Literal[
    "seller", "domain", "social_handle", "phone", "mpesa_till", "mpesa_paybill",
    "payment_account_ref", "business_registration", "email", "location", "other"
]
Relationship = Literal[
    "claims_website", "listed_at_location", "uses_contact", "requests_payment_to",
    "claims_registration", "shares_identifier", "document_names_entity", "other"
]
Basis = Literal[
    "seller_claim", "user_supplied_receipt", "public_listing", "public_page",
    "official_document_user_supplied", "official_record_operator_checked",
    "authenticated_merchant_callback", "moderated_report"
]
AssertionStatus = Literal["unverified", "corroborated", "verified", "rejected"]

_ALLOWED_IDENTIFIER_TYPES = {
    "seller", "domain", "social_handle", "phone", "mpesa_till", "mpesa_paybill",
    "payment_account_ref", "business_registration", "email", "location", "other"
}
_ALLOWED_RELATIONSHIPS = {
    "claims_website", "listed_at_location", "uses_contact", "requests_payment_to",
    "claims_registration", "shares_identifier", "document_names_entity", "other"
}
_ALLOWED_BASES = {
    "seller_claim", "user_supplied_receipt", "public_listing", "public_page",
    "official_document_user_supplied", "official_record_operator_checked",
    "authenticated_merchant_callback", "moderated_report"
}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_source_url(url: str | None) -> str | None:
    if not url or len(url) > 4096:
        return None
    try:
        p = urlsplit(url.strip())
        host = (p.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        if p.scheme.lower() not in {"https", "http"} or not host:
            return None
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            return None
        try:
            if not ipaddress.ip_address(host).is_global:
                return None
        except ValueError:
            pass
        # Strip credentials, query parameters and fragments. Drop token-like/opaque paths.
        path = p.path[:500]
        parts = [segment for segment in path.split("/") if segment]
        suspicious = any(
            re.search(r"(?i)(token|session|auth|secret|password|invite|reset|api.?key|otp)", segment)
            or len(segment) > 48
            for segment in parts
        )
        if suspicious:
            path = "/"
        netloc = host + (f":{p.port}" if p.port else "")
        return urlunsplit((p.scheme.lower(), netloc, path, "", ""))
    except (ValueError, UnicodeError):
        return None


def _normalise(kind: str, value: str) -> str:
    raw_value = " ".join((value or "").strip().split())
    raw = raw_value.lower()
    if kind == "social_handle":
        if raw.startswith(("https://", "http://")):
            try:
                parsed = urlsplit(raw)
                host = (parsed.hostname or "").lower()
                if host.endswith("instagram.com") or host.endswith("tiktok.com") or host.endswith("facebook.com"):
                    raw = next((x for x in parsed.path.split("/") if x), "")
            except ValueError:
                pass
        raw = raw.lstrip("@").rstrip("/")
    elif kind == "domain":
        candidate = raw if "://" in raw else f"https://{raw}"
        try:
            parsed = urlsplit(candidate)
            raw = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
        except (ValueError, UnicodeError):
            raw = ""
    elif kind == "phone":
        digits = re.sub(r"\D", "", raw)
        if digits.startswith("0") and len(digits) == 10:
            raw = "+254" + digits[1:]
        elif digits.startswith("254") and len(digits) == 12:
            raw = "+" + digits
        elif digits.startswith("7") and len(digits) == 9:
            raw = "+254" + digits
        elif len(digits) >= 9:
            raw = "+" + digits
        else:
            raw = digits
    elif kind in {"mpesa_till", "mpesa_paybill"}:
        raw = re.sub(r"\D", "", raw)
    elif kind in {"payment_account_ref", "business_registration"}:
        raw = re.sub(r"\s+", "", raw).upper()
    elif kind == "email":
        raw = raw.lower()
    if not raw:
        raise ValueError("identifier value must not be empty or could not be normalized")
    return raw


@dataclass(slots=True)
class LinkAssertion:
    assertion_id: str
    left_type: str
    right_type: str
    relationship: str
    basis: str
    source_label: str
    source_url: str | None
    evidence_id: str | None
    match_confidence: float
    status: str
    observed_at: str
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        result = asdict(self)
        # Pseudonymous IDs are useful for graph navigation without disclosing raw identifiers.
        result["left_node"] = None
        result["right_node"] = None
        result["risk_propagation"] = "never_automatic"
        return result


class EntityLinkGraph:
    """A privacy-minimal graph of sourced relationships.

    Raw identifiers are never persisted. Each node key is a keyed HMAC scoped by
    identifier type. Edges are assertions, not proof that two sellers are the same.
    The graph deliberately does not merge seller records or propagate fraud verdicts.
    """

    def __init__(self, db_path: str = "toroka_relationships.sqlite3", secret: str | None = None):
        secret_value = secret or os.getenv("TOROKA_ENTITY_HASH_SECRET") or ""
        if len(secret_value.encode("utf-8")) < 32:
            raise ValueError("TOROKA_ENTITY_HASH_SECRET must contain at least 32 bytes")
        self._secret = secret_value.encode("utf-8")
        self.db_path = db_path
        parent = Path(db_path).parent
        if str(parent) not in {"", "."}:
            parent.mkdir(parents=True, exist_ok=True)
        self._initialise()

    @contextlib.contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _node_key(self, kind: str, value: str) -> str:
        if kind not in _ALLOWED_IDENTIFIER_TYPES:
            raise ValueError(f"unsupported identifier type: {kind}")
        normalized = _normalise(kind, value)
        return hmac.new(self._secret, f"toroka-v3:{kind}:{normalized}".encode("utf-8"), hashlib.sha256).hexdigest()

    def identifier_digest(self, kind: str, value: str) -> str:
        """Return a backend-only, type-scoped HMAC for in-memory pattern analysis.

        Do not send this digest to the frontend or treat it as a reversible identifier.
        """
        return self._node_key(kind, value)

    def _initialise(self):
        with self._connect() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS graph_nodes (
                node_key TEXT PRIMARY KEY,
                node_type TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS link_assertions (
                assertion_id TEXT PRIMARY KEY,
                left_node TEXT NOT NULL REFERENCES graph_nodes(node_key),
                right_node TEXT NOT NULL REFERENCES graph_nodes(node_key),
                relationship TEXT NOT NULL,
                basis TEXT NOT NULL,
                source_label TEXT NOT NULL,
                source_url TEXT,
                evidence_id TEXT,
                match_confidence REAL NOT NULL,
                status TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                limitations TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_links_left ON link_assertions(left_node, observed_at);
            CREATE INDEX IF NOT EXISTS idx_links_right ON link_assertions(right_node, observed_at);
            CREATE INDEX IF NOT EXISTS idx_links_evidence ON link_assertions(evidence_id);
            """)

    def add_link(
        self,
        left: tuple[str, str],
        right: tuple[str, str],
        *,
        relationship: str,
        basis: str,
        source_label: str,
        match_confidence: float,
        status: str = "unverified",
        source_url: str | None = None,
        evidence_id: str | None = None,
        limitations: Iterable[str] = (),
        observed_at: datetime | None = None,
    ) -> str:
        left_type, left_value = left
        right_type, right_value = right
        if relationship not in _ALLOWED_RELATIONSHIPS:
            raise ValueError("unsupported relationship")
        if basis not in _ALLOWED_BASES:
            raise ValueError("unsupported evidence basis")
        if status not in {"unverified", "corroborated", "verified", "rejected"}:
            raise ValueError("unsupported assertion status")
        if not source_label.strip() or len(source_label) > 160:
            raise ValueError("source_label must be 1-160 characters")
        if not 0 <= match_confidence <= 1:
            raise ValueError("match_confidence must be between 0 and 1")
        if status == "verified" and basis not in {
            "official_record_operator_checked", "authenticated_merchant_callback"
        }:
            raise ValueError("verified status requires an operator-checked official record or authenticated merchant callback")
        left_key = self._node_key(left_type, left_value)
        right_key = self._node_key(right_type, right_value)
        if left_key == right_key:
            raise ValueError("a relationship cannot connect an identifier to itself")
        at = (observed_at or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()
        assertion_id = str(uuid.uuid4())
        cleaned_limitations = [str(x)[:300] for x in limitations][:12]
        with self._connect() as conn:
            conn.execute("INSERT OR IGNORE INTO graph_nodes(node_key,node_type,created_at) VALUES(?,?,?)", (left_key, left_type, _utc_now()))
            conn.execute("INSERT OR IGNORE INTO graph_nodes(node_key,node_type,created_at) VALUES(?,?,?)", (right_key, right_type, _utc_now()))
            conn.execute("""INSERT INTO link_assertions(
                assertion_id,left_node,right_node,relationship,basis,source_label,source_url,
                evidence_id,match_confidence,status,observed_at,limitations
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (
                assertion_id, left_key, right_key, relationship, basis, source_label.strip(),
                _safe_source_url(source_url), evidence_id, float(match_confidence), status,
                at, " | ".join(cleaned_limitations)
            ))
        return assertion_id

    def get_links(self, identifier: tuple[str, str], *, include_rejected: bool = False) -> list[dict]:
        node_key = self._node_key(*identifier)
        with self._connect() as conn:
            sql = """SELECT l.*, a.node_type AS left_type, b.node_type AS right_type
                     FROM link_assertions l
                     JOIN graph_nodes a ON a.node_key=l.left_node
                     JOIN graph_nodes b ON b.node_key=l.right_node
                     WHERE (l.left_node=? OR l.right_node=?)"""
            params: list[object] = [node_key, node_key]
            if not include_rejected:
                sql += " AND l.status != 'rejected'"
            sql += " ORDER BY l.observed_at DESC"
            rows = conn.execute(sql, params).fetchall()
        results = []
        for row in rows:
            connected_key = row["right_node"] if row["left_node"] == node_key else row["left_node"]
            connected_type = row["right_type"] if row["left_node"] == node_key else row["left_type"]
            results.append({
                "assertion_id": row["assertion_id"],
                "connected_identifier_type": connected_type,
                "connected_node_ref": connected_key[:12],
                "relationship": row["relationship"],
                "basis": row["basis"],
                "source_label": row["source_label"],
                "source_url": row["source_url"],
                "evidence_id": row["evidence_id"],
                "match_confidence": row["match_confidence"],
                "status": row["status"],
                "observed_at": row["observed_at"],
                "limitations": row["limitations"].split(" | ") if row["limitations"] else [],
                "risk_propagation": "never_automatic",
            })
        return results

    def delete_links_for_identifier(self, identifier: tuple[str, str]) -> int:
        """Delete graph assertions touching one identifier (privacy/deletion workflow)."""
        node_key = self._node_key(*identifier)
        with self._connect() as conn:
            count = conn.execute("DELETE FROM link_assertions WHERE left_node=? OR right_node=?", (node_key, node_key)).rowcount
            # Remove isolated node records after edge deletion.
            conn.execute("""DELETE FROM graph_nodes WHERE node_key=?
                         AND NOT EXISTS (SELECT 1 FROM link_assertions WHERE left_node=? OR right_node=?)""",
                         (node_key, node_key, node_key))
        return count
