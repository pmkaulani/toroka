from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import sqlite3
import uuid
from typing import Any


ALLOWED_REVIEW_LABELS = {"scam_confirmed", "legitimate", "inconclusive", "false_positive"}
ALLOWED_CLAIMS = {"suspected_scam", "looks_legitimate", "incorrect_finding", "report", "other"}
ALLOWED_STATES = {"pending", "approved", "rejected", "needs_more_evidence"}
FEATURE_SCHEMA = {
    "tactics": "labels", "signal_categories": "labels",
    "channel": {"sms", "whatsapp", "social_dm", "email", "web", "screenshot", "call", "message", "unknown"},
    "language": {"en", "sw", "en-sw", "undetermined"},
    "domain_age_band": {"unknown", "under_30d", "30_90d", "90_365d", "over_365d"},
    "url_count": "count", "phone_count": "count", "feed_match_count": "count",
    "payment_request_present": "bool", "otp_request_present": "bool",
    "urgent_language_present": "bool",
    "campaign_similarity_band": {"none", "low", "medium", "high"},
}
FEATURE_LABELS = {
    "tactics": {"prize_or_betting_bait", "advance_fee_for_benefit", "job_or_recruitment_fee",
                "government_or_grant_fee", "credential_or_otp_request", "account_pressure",
                "guaranteed_investment_return", "delivery_or_customs_fee"},
    "signal_categories": {"prize_or_betting_bait", "advance_fee_for_benefit", "job_or_recruitment_fee",
                          "government_or_grant_fee", "credential_or_otp_request", "account_pressure",
                          "guaranteed_investment_return", "delivery_or_customs_fee",
                          "payment_instruction_present", "brand_or_public_service_mentioned"},
}
REVIEW_REASON_CODES = {"confirmed_by_independent_source", "insufficient_provenance",
                       "conflicting_evidence", "false_positive_corrected",
                       "privacy_request", "other"}


class FeedbackLedger:
    """Reviewed feedback ledger. User reports never enter training automatically."""
    def __init__(self, db_path: str = ":memory:", *, secret: str | bytes, retention_days: int = 365):
        if not secret or len(secret) < 32:
            raise ValueError("secret must contain at least 32 characters")
        self.secret = secret.encode() if isinstance(secret, str) else secret
        self.retention_days = retention_days
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("""CREATE TABLE IF NOT EXISTS feedback (
            feedback_id TEXT PRIMARY KEY, case_hash TEXT NOT NULL, claim_type TEXT NOT NULL,
            reviewed_label TEXT, state TEXT NOT NULL, features_json TEXT NOT NULL, opt_in INTEGER NOT NULL,
            campaign_hash TEXT NOT NULL, created_at TEXT NOT NULL, reviewed_at TEXT,
            reviewer_hash TEXT, review_note TEXT)""")
        self.conn.execute("""CREATE TABLE IF NOT EXISTS feedback_events (
            event_id TEXT PRIMARY KEY, feedback_id TEXT NOT NULL, event_type TEXT NOT NULL,
            event_at TEXT NOT NULL, actor_hash TEXT, details_json TEXT NOT NULL)""")
        self.conn.commit()

    def _hash(self, kind: str, value: str) -> str:
        return hmac.new(self.secret, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def _safe_features(features: dict[str, Any]) -> dict[str, Any]:
        """Accept only typed, low-cardinality model features; never arbitrary text."""
        safe: dict[str, Any] = {}
        for key, value in features.items():
            spec = FEATURE_SCHEMA.get(key)
            if spec is None:
                continue
            if spec == "labels":
                if isinstance(value, (list, tuple)):
                    labels = []
                    allowed = FEATURE_LABELS[key]
                    for item in value[:30]:
                        if isinstance(item, str) and item in allowed:
                            labels.append(item)
                    safe[key] = sorted(set(labels))
            elif spec == "count":
                if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 1000:
                    safe[key] = value
            elif spec == "bool":
                if isinstance(value, bool):
                    safe[key] = value
            elif isinstance(spec, set) and isinstance(value, str) and value in spec:
                safe[key] = value
        return safe

    def submit(self, *, case_id: str, claim_type: str = "report", features: dict[str, Any],
               opt_in_to_training: bool, campaign_id: str, report_id: str | None = None) -> str:
        if claim_type not in ALLOWED_CLAIMS:
            raise ValueError("invalid user claim type")
        if not isinstance(opt_in_to_training, bool):
            raise ValueError("opt_in_to_training must be explicitly true or false")
        if report_id is not None:
            try:
                feedback_id = str(uuid.UUID(report_id))
            except (ValueError, TypeError, AttributeError) as exc:
                raise ValueError("report_id must be an opaque UUID") from exc
        else:
            feedback_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute("""INSERT INTO feedback
            (feedback_id,case_hash,claim_type,reviewed_label,state,features_json,opt_in,campaign_hash,created_at)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (feedback_id, self._hash("case", case_id), claim_type, None, "pending",
             json.dumps(self._safe_features(features)), int(opt_in_to_training),
             self._hash("campaign", campaign_id), now))
        self._event(feedback_id, "submitted", None, {"claim_type": claim_type, "training_opt_in": opt_in_to_training})
        self.conn.commit()
        return feedback_id

    def _event(self, feedback_id: str, event_type: str, actor_hash: str | None, details: dict[str, Any]):
        self.conn.execute("INSERT INTO feedback_events VALUES (?,?,?,?,?,?)",
                          (str(uuid.uuid4()), feedback_id, event_type, datetime.now(timezone.utc).isoformat(),
                           actor_hash, json.dumps(details)))

    def review(self, feedback_id: str, *, state: str, reviewer_id: str,
               reviewer_authorized: bool, reason_code: str = "other",
               reviewed_label: str | None = None) -> None:
        if not reviewer_authorized:
            raise PermissionError("authorized moderator role is required")
        if state not in ALLOWED_STATES - {"pending"}:
            raise ValueError("invalid review state")
        if reason_code not in REVIEW_REASON_CODES:
            raise ValueError("invalid moderation reason code")
        if state == "approved" and reviewed_label not in ALLOWED_REVIEW_LABELS:
            raise ValueError("an approved case requires a moderator-assigned reviewed_label")
        if state != "approved" and reviewed_label is not None:
            raise ValueError("only approved cases may receive a reviewed_label")
        row = self.conn.execute("SELECT state FROM feedback WHERE feedback_id=?", (feedback_id,)).fetchone()
        if not row:
            raise KeyError("feedback record not found")
        if row["state"] != "pending":
            raise ValueError("feedback has already been reviewed")
        reviewer_hash = self._hash("reviewer", reviewer_id)
        self.conn.execute("UPDATE feedback SET state=?,reviewed_label=?,reviewed_at=?,reviewer_hash=?,review_note=? WHERE feedback_id=?",
                          (state, reviewed_label, datetime.now(timezone.utc).isoformat(), reviewer_hash, reason_code, feedback_id))
        self._event(feedback_id, "reviewed", reviewer_hash,
                    {"state": state, "reason_code": reason_code, "reviewed_label": reviewed_label})
        self.conn.commit()

    def training_rows(self, *, minimum_campaigns: int = 10) -> list[dict[str, Any]]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat()
        rows = self.conn.execute("""SELECT * FROM feedback WHERE state='approved' AND opt_in=1
            AND reviewed_label IN ('scam_confirmed','legitimate') AND created_at>=?""", (cutoff,)).fetchall()
        distinct = {r["campaign_hash"] for r in rows}
        labels = {r["reviewed_label"] for r in rows}
        if len(distinct) < minimum_campaigns or labels != {"scam_confirmed", "legitimate"}:
            return []
        output = []
        for row in rows:
            output.append({
                "label": row["reviewed_label"], "features": json.loads(row["features_json"]),
                "campaign_ref": row["campaign_hash"][:12],
            })
        return output

    def retention_purge(self, *, now: datetime | None = None) -> int:
        cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=self.retention_days)).isoformat()
        ids = [r[0] for r in self.conn.execute("SELECT feedback_id FROM feedback WHERE created_at<?", (cutoff,))]
        for fid in ids:
            self.conn.execute("DELETE FROM feedback_events WHERE feedback_id=?", (fid,))
        cur = self.conn.execute("DELETE FROM feedback WHERE created_at<?", (cutoff,))
        self.conn.commit()
        return cur.rowcount

    def event_count(self, feedback_id: str) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM feedback_events WHERE feedback_id=?", (feedback_id,)).fetchone()[0])

    def close(self):
        self.conn.close()
