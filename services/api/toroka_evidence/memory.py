"""Privacy-conscious persistent evidence/report memory for self-hosted Toroka deployments.

Raw seller identifiers and reporter tokens are never stored; only keyed HMAC digests are.
Community reports stay pending/unverified and are intentionally not converted into verdict evidence.
"""
from __future__ import annotations
import contextlib
import hashlib
import hmac
import json
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit
from .models import Evidence
from .normalize import normalize_phone, normalize_domain


def _redact_report_text(value: str) -> str:
    # Keep reports useful while removing common direct identifiers before persistence.
    value = re.sub(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", "[EMAIL REDACTED]", value, flags=re.IGNORECASE)
    value = re.sub(r"(?<!\w)(?:\+?254|0)?[ .()-]*\d(?:[ .()-]*\d){8,11}(?!\w)", "[PHONE/ACCOUNT REDACTED]", value)
    return value


class EvidenceMemory:
    def __init__(self, db_path: str = "toroka_evidence.sqlite3", secret: str | None = None):
        self.db_path = db_path
        self.secret = (secret or os.getenv("TOROKA_ENTITY_HASH_SECRET") or "").encode("utf-8")
        if len(self.secret) < 32:
            raise ValueError("Set TOROKA_ENTITY_HASH_SECRET to a random secret of at least 32 characters")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True) if Path(db_path).parent != Path(".") else None
        self._initialize()

    @contextlib.contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _hash(self, namespace: str, value: str) -> str:
        normalized = " ".join((value or "").strip().lower().split())
        if namespace in {"phone", "mpesa_number"}:
            normalized = normalize_phone(value) or normalized
        elif namespace == "domain":
            normalized = normalize_domain(value) or normalized
        elif namespace in {"social_handle", "instagram", "tiktok", "facebook"}:
            normalized = normalized.lstrip("@").rstrip("/")
        return hmac.new(self.secret, f"{namespace}:{normalized}".encode(), hashlib.sha256).hexdigest()

    def entity_key(self, identifiers: Iterable[tuple[str, str]]) -> str:
        digests = sorted(self._hash(kind, value) for kind, value in identifiers if value)
        if not digests:
            raise ValueError("At least one non-empty seller identifier is required")
        # Stable canonical key supports lookups by any supplied identifier through the identifier table.
        return digests[0]

    @staticmethod
    def _safe_url(url: str | None) -> str | None:
        if not url:
            return None
        try:
            parts = urlsplit(url)
            host = parts.hostname or ""
            if parts.scheme not in {"http", "https"} or not host:
                return None
            port = f":{parts.port}" if parts.port else ""
            netloc = host + port  # drops any embedded username/password
            return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
        except ValueError:
            return None

    def _scrub_metadata(self, value):
        if isinstance(value, dict):
            return {k: self._scrub_metadata(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._scrub_metadata(v) for v in value]
        if isinstance(value, str):
            if value.startswith(("http://", "https://")):
                return self._safe_url(value) or "[URL REDACTED]"
            return _redact_report_text(value)
        return value

    def _initialize(self):
        with self._connect() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS seller_entities (
                entity_key TEXT PRIMARY KEY,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS seller_identifiers (
                identifier_hash TEXT PRIMARY KEY,
                identifier_type TEXT NOT NULL,
                entity_key TEXT NOT NULL REFERENCES seller_entities(entity_key) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_seller_identifiers_entity ON seller_identifiers(entity_key);
            CREATE TABLE IF NOT EXISTS evidence_items (
                evidence_id TEXT PRIMARY KEY,
                entity_key TEXT NOT NULL REFERENCES seller_entities(entity_key) ON DELETE CASCADE,
                source TEXT NOT NULL,
                source_group TEXT NOT NULL,
                category TEXT NOT NULL,
                polarity TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_evidence_entity ON evidence_items(entity_key);
            CREATE TABLE IF NOT EXISTS community_reports (
                report_id TEXT PRIMARY KEY,
                entity_key TEXT NOT NULL REFERENCES seller_entities(entity_key) ON DELETE CASCADE,
                reporter_hash TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                source_url TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                moderator_note TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_reports_entity ON community_reports(entity_key, created_at);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_report_dedupe ON community_reports(entity_key, reporter_hash, category, substr(created_at, 1, 10));
            """)

    def _resolve_entity(self, conn, identifiers: Iterable[tuple[str, str]]) -> str:
        pairs = [(kind, self._hash(kind, value)) for kind, value in identifiers if value]
        if not pairs:
            raise ValueError("At least one non-empty seller identifier is required")
        existing = None
        for _, digest in pairs:
            row = conn.execute("SELECT entity_key FROM seller_identifiers WHERE identifier_hash=?", (digest,)).fetchone()
            if row:
                existing = row["entity_key"]
                break
        entity = existing or pairs[0][1]
        conn.execute("INSERT OR IGNORE INTO seller_entities(entity_key, created_at) VALUES (?, ?)", (entity, datetime.now(timezone.utc).isoformat()))
        for kind, digest in pairs:
            # If a second identifier is already linked to a different entity, do not merge automatically.
            row = conn.execute("SELECT entity_key FROM seller_identifiers WHERE identifier_hash=?", (digest,)).fetchone()
            if row and row["entity_key"] != entity:
                raise ValueError("Identifier is already linked to a different seller record; manual entity resolution is required")
            conn.execute("INSERT OR IGNORE INTO seller_identifiers(identifier_hash, identifier_type, entity_key) VALUES (?, ?, ?)", (digest, kind, entity))
        return entity

    def add_evidence(self, identifiers: Iterable[tuple[str, str]], evidence: Evidence) -> str:
        with self._connect() as conn:
            entity = self._resolve_entity(conn, identifiers)
            evidence_data = evidence.to_dict()
            raw_subject = evidence_data.get("subject") or ""
            evidence_data["subject"] = self._safe_url(raw_subject) or (self._hash("evidence_subject", raw_subject) if raw_subject else "")
            evidence_data["source_url"] = self._safe_url(evidence_data.get("source_url"))
            evidence_data["summary"] = _redact_report_text(evidence_data.get("summary", ""))
            evidence_data["why_it_matters"] = _redact_report_text(evidence_data.get("why_it_matters", ""))
            evidence_data["metadata"] = self._scrub_metadata(evidence_data.get("metadata", {}))
            conn.execute("INSERT OR REPLACE INTO evidence_items(evidence_id, entity_key, source, source_group, category, polarity, summary, evidence_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (
                evidence.evidence_id, entity, evidence.source, evidence.source_group, evidence.category,
                evidence.polarity, evidence_data["summary"], json.dumps(evidence_data, ensure_ascii=False), datetime.now(timezone.utc).isoformat()
            ))
        return entity

    def submit_community_report(self, identifiers: Iterable[tuple[str, str]], reporter_token: str, category: str, description: str, source_url: str | None = None) -> str:
        if not reporter_token or len(description.strip()) < 12:
            raise ValueError("A reporter session token and a useful description (at least 12 characters) are required")
        if len(description) > 3000:
            raise ValueError("Report description is too long")
        reporter_hash = self._hash("reporter", reporter_token)
        safe_url = self._safe_url(source_url)
        description = _redact_report_text(description.strip())
        with self._connect() as conn:
            entity = self._resolve_entity(conn, identifiers)
            # Same session + seller + category is deduplicated for one calendar day.
            day = datetime.now(timezone.utc).date().isoformat()
            existing = conn.execute("SELECT report_id FROM community_reports WHERE entity_key=? AND reporter_hash=? AND category=? AND substr(created_at,1,10)=?", (entity, reporter_hash, category, day)).fetchone()
            if existing:
                return existing["report_id"]
            report_id = str(uuid.uuid4())
            conn.execute("INSERT INTO community_reports(report_id, entity_key, reporter_hash, category, description, source_url, status, created_at) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)", (
                report_id, entity, reporter_hash, category, description.strip(), safe_url, datetime.now(timezone.utc).isoformat()
            ))
        return report_id

    def moderate_report(self, report_id: str, status: str, moderator_note: str = "") -> None:
        if status not in {"reviewed_unverified", "rejected", "corroborated"}:
            raise ValueError("status must be reviewed_unverified, rejected, or corroborated")
        with self._connect() as conn:
            result = conn.execute("UPDATE community_reports SET status=?, moderator_note=? WHERE report_id=?", (status, moderator_note[:1000], report_id))
            if result.rowcount != 1:
                raise KeyError("Report not found")

    def get_entity_memory(self, identifiers: Iterable[tuple[str, str]]) -> dict:
        pairs = [(kind, self._hash(kind, value)) for kind, value in identifiers if value]
        if not pairs:
            return {"found": False, "evidence": [], "community_reports": []}
        with self._connect() as conn:
            entity = None
            for _, digest in pairs:
                row = conn.execute("SELECT entity_key FROM seller_identifiers WHERE identifier_hash=?", (digest,)).fetchone()
                if row:
                    entity = row["entity_key"]
                    break
            if not entity:
                return {"found": False, "evidence": [], "community_reports": []}
            evidence = [json.loads(r["evidence_json"]) for r in conn.execute("SELECT evidence_json FROM evidence_items WHERE entity_key=? ORDER BY created_at DESC", (entity,)).fetchall()]
            reports = [dict(r) for r in conn.execute("SELECT report_id, category, status, created_at FROM community_reports WHERE entity_key=? ORDER BY created_at DESC", (entity,)).fetchall()]
            return {
                "found": True,
                "evidence": evidence,
                "community_reports": reports,
                "report_counts": {
                    "pending": sum(1 for r in reports if r["status"] == "pending"),
                    "reviewed_unverified": sum(1 for r in reports if r["status"] == "reviewed_unverified"),
                    "corroborated": sum(1 for r in reports if r["status"] == "corroborated"),
                    "rejected": sum(1 for r in reports if r["status"] == "rejected"),
                },
                "privacy_note": "Seller identifiers and reporter session tokens are stored as keyed hashes; report text is visible to authorized investigators and requires moderation before public display."
            }

    def get_report_for_moderation(self, report_id: str) -> dict | None:
        """Return report text for a restricted moderation service; never expose this to the public chat API."""
        with self._connect() as conn:
            row = conn.execute("SELECT report_id, category, description, source_url, status, created_at, moderator_note FROM community_reports WHERE report_id=?", (report_id,)).fetchone()
            return dict(row) if row else None
