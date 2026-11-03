from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
import hashlib
import hmac
import json
import re
import sqlite3
from typing import Iterable


@dataclass(slots=True)
class CampaignCase:
    case_id: str
    extracted_text: str
    indicators: dict[str, list[str]]
    tactics: list[str]
    source_group: str
    moderation_state: str = "pending"
    observed_at: str | None = None


@dataclass(slots=True)
class CampaignLink:
    related_case_ref: str
    relation_basis: list[str]
    text_similarity: float
    observed_at: str
    moderation_state: str
    warning: str = "Similarity is an investigation lead, not proof of common ownership or fraud."

    def to_dict(self):
        return asdict(self)


def _tokens(text: str) -> set[str]:
    # Keep short token fingerprints only; raw content is not persisted.
    words = re.findall(r"[a-z0-9]{3,}", text.casefold())
    if len(words) < 3:
        return set()
    grams = {" ".join(words[i:i + 3]) for i in range(len(words) - 2)}
    return grams or set(words)


class CampaignCorrelator:
    """Privacy-minimal similarity store; never propagates a verdict between cases."""
    ALLOWED_MODERATION = {"pending", "reviewed_unverified", "corroborated", "rejected"}
    ALLOWED_SOURCE_GROUPS = {"sms", "whatsapp", "instagram", "facebook", "tiktok", "telegram",
                             "email", "website", "social_media", "message", "screenshot",
                             "call", "user-submitted", "unknown"}
    ALLOWED_INDICATOR_TYPES = {"domain", "phone", "email", "mpesa_till", "mpesa_paybill",
                               "payment_account_ref", "business_registration", "social_handle"}
    ALLOWED_TACTICS = {"prize_or_betting_bait", "advance_fee_for_benefit", "job_or_recruitment_fee",
                       "government_or_grant_fee", "credential_or_otp_request", "account_pressure",
                       "guaranteed_investment_return", "delivery_or_customs_fee"}

    def __init__(self, db_path: str = ":memory:", *, secret: str | bytes, window_days: int = 45,
                 minimum_text_similarity: float = 0.72):
        if not secret or len(secret) < 32:
            raise ValueError("secret must contain at least 32 characters")
        if not 0 <= minimum_text_similarity <= 1:
            raise ValueError("minimum_text_similarity must be between 0 and 1")
        self.secret = secret.encode() if isinstance(secret, str) else secret
        self.window_days = window_days
        self.minimum_text_similarity = minimum_text_similarity
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("""CREATE TABLE IF NOT EXISTS campaign_cases (
            case_hash TEXT PRIMARY KEY, case_ref TEXT NOT NULL, observed_at TEXT NOT NULL,
            token_hashes TEXT NOT NULL, indicator_hashes TEXT NOT NULL, tactics_json TEXT NOT NULL,
            source_group TEXT NOT NULL, moderation_state TEXT NOT NULL)""")
        self.conn.commit()

    def _hash(self, kind: str, value: str) -> str:
        return hmac.new(self.secret, f"{kind}:{value.casefold().strip()}".encode(), hashlib.sha256).hexdigest()

    def identifier_digest(self, kind: str, value: str) -> str:
        """Return the Phase 3-compatible type-scoped digest for supported identifiers."""
        raw = " ".join((value or "").strip().split()).lower()
        if kind == "domain":
            from urllib.parse import urlsplit
            parts = urlsplit(raw if "://" in raw else "https://" + raw)
            raw = (parts.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
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
        elif kind == "email":
            raw = raw.lower()
        elif kind in {"mpesa_till", "mpesa_paybill"}:
            raw = re.sub(r"\D", "", raw)
        elif kind in {"payment_account_ref", "business_registration"}:
            raw = re.sub(r"\s+", "", raw).upper()
        elif kind == "social_handle":
            if raw.startswith(("https://", "http://")):
                from urllib.parse import urlsplit
                parts = urlsplit(raw)
                host = (parts.hostname or "").lower()
                if host.endswith(("instagram.com", "tiktok.com", "facebook.com")):
                    raw = next((x for x in parts.path.split("/") if x), "")
            raw = raw.lstrip("@").rstrip("/")
        else:
            raise ValueError("unsupported Phase 3 identifier type")
        if not raw:
            raise ValueError("identifier cannot be normalized")
        return hmac.new(self.secret, f"toroka-v3:{kind}:{raw}".encode("utf-8"), hashlib.sha256).hexdigest()

    def add_case(self, case: CampaignCase) -> list[CampaignLink]:
        if case.moderation_state not in self.ALLOWED_MODERATION:
            raise ValueError("unsupported moderation state")
        if case.source_group not in self.ALLOWED_SOURCE_GROUPS:
            raise ValueError("source_group must be a predefined channel; do not store contributor names")
        if not isinstance(case.case_id, str) or not case.case_id or len(case.case_id) > 512:
            raise ValueError("case_id must be a non-empty string up to 512 characters")
        if any(kind not in self.ALLOWED_INDICATOR_TYPES for kind in case.indicators):
            raise ValueError("unsupported indicator type")
        if any(t not in self.ALLOWED_TACTICS for t in case.tactics):
            raise ValueError("unsupported tactic code")
        observed = case.observed_at or datetime.now(timezone.utc).isoformat()
        try:
            dt = datetime.fromisoformat(observed.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            observed = dt.astimezone(timezone.utc).isoformat()
        except ValueError as exc:
            raise ValueError("invalid observed_at timestamp") from exc
        case_hash = self._hash("case", case.case_id)
        case_ref = "case-" + case_hash[:10]
        token_hashes = sorted(self._hash("token", token) for token in _tokens(case.extracted_text[:20_000]))
        indicator_hashes: dict[str, list[str]] = {}
        for kind, values in case.indicators.items():
            indicator_hashes[kind] = sorted({self.identifier_digest(kind, value) for value in values if value.strip()})
        now = datetime.fromisoformat(observed)
        cutoff = (now - timedelta(days=self.window_days)).isoformat()
        rows = self.conn.execute("SELECT * FROM campaign_cases WHERE observed_at >= ? AND case_hash != ?", (cutoff, case_hash)).fetchall()
        links: list[CampaignLink] = []
        for row in rows:
            prior_tokens = set(json.loads(row["token_hashes"]))
            current_tokens = set(token_hashes)
            union = prior_tokens | current_tokens
            similarity = len(prior_tokens & current_tokens) / len(union) if union else 0.0
            prior_indicators = json.loads(row["indicator_hashes"])
            matched_types = [kind for kind, current in indicator_hashes.items()
                             if set(current) & set(prior_indicators.get(kind, []))]
            reasons = [f"shared_{kind}" for kind in matched_types]
            if similarity >= self.minimum_text_similarity and len(current_tokens) >= 2 and len(prior_tokens) >= 2:
                reasons.append("similar_message_template")
            if reasons:
                links.append(CampaignLink(
                    related_case_ref=row["case_ref"], relation_basis=reasons,
                    text_similarity=round(similarity, 3), observed_at=row["observed_at"],
                    moderation_state=row["moderation_state"],
                ))
        self.conn.execute("""INSERT INTO campaign_cases
            (case_hash,case_ref,observed_at,token_hashes,indicator_hashes,tactics_json,source_group,moderation_state)
            VALUES (?,?,?,?,?,?,?,?) ON CONFLICT(case_hash) DO UPDATE SET
            observed_at=excluded.observed_at,token_hashes=excluded.token_hashes,
            indicator_hashes=excluded.indicator_hashes,tactics_json=excluded.tactics_json,
            source_group=excluded.source_group,moderation_state=excluded.moderation_state""",
            (case_hash, case_ref, observed, json.dumps(token_hashes), json.dumps(indicator_hashes),
             json.dumps(sorted(set(case.tactics))), case.source_group, case.moderation_state))
        self.conn.commit()
        return links

    def case_count(self) -> int:
        return int(self.conn.execute("SELECT COUNT(*) FROM campaign_cases").fetchone()[0])

    def purge_expired(self, *, now: datetime | None = None) -> int:
        cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=self.window_days)).isoformat()
        cur = self.conn.execute("DELETE FROM campaign_cases WHERE observed_at < ?", (cutoff,))
        self.conn.commit()
        return cur.rowcount

    def purge_case(self, case_id: str) -> bool:
        cur = self.conn.execute("DELETE FROM campaign_cases WHERE case_hash=?", (self._hash("case", case_id),))
        self.conn.commit()
        return cur.rowcount > 0

    def close(self) -> None:
        self.conn.close()
