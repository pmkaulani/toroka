"""Exact Identity Matching & Entity Resolution for Toroka.

Implements Section 11:
1. Platform-aware identity separation:
   - Instagram, TikTok, Facebook, X, Website Domain, Phone, and Till/Paybill are isolated channels.
   - Handles on different platforms with identical names (e.g. Instagram @clothing.ctrl vs TikTok @clothing.ctrl)
     remain distinct entities unless explicitly linked by verified evidence.
2. Match outcomes:
   - EXACT_MATCH, STRONG_MATCH, POSSIBLE_MATCH, NO_MATCH
3. Report integrity & deduplication:
   - Distinguishes independent reports from duplicate submissions or coordinated campaigns.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Platform(StrEnum):
    INSTAGRAM = "instagram"
    TIKTOK = "tiktok"
    FACEBOOK = "facebook"
    X = "x"
    WHATSAPP = "whatsapp"
    WEBSITE_DOMAIN = "domain"
    PHONE = "phone"
    TILL = "till"
    PAYBILL = "paybill"
    OTHER = "other"


class MatchOutcome(StrEnum):
    EXACT_MATCH = "exact_match"
    STRONG_MATCH = "strong_match"
    POSSIBLE_MATCH = "possible_match"
    NO_MATCH = "no_match"


@dataclass(frozen=True)
class EntityIdentifier:
    platform: Platform
    raw_value: str
    normalized_value: str

    @property
    def composite_key(self) -> str:
        """Globally unique, platform-namespaced identifier key."""
        return f"{self.platform.value}:{self.normalized_value}"


def normalize_identifier(platform: Platform, value: str) -> EntityIdentifier:
    """Normalize raw handle, domain, phone, or till with platform-specific rules."""
    raw = value.strip()
    val = raw.lower()

    if platform in (Platform.INSTAGRAM, Platform.TIKTOK, Platform.FACEBOOK, Platform.X):
        # Strip leading @ and any trailing slashes/query parameters
        val = re.sub(r"^@+", "", val)
        val = val.split("?")[0].split("/")[0].strip()
    elif platform == Platform.WEBSITE_DOMAIN:
        # Strip protocol, www, port, and paths
        val = re.sub(r"^https?://", "", val)
        val = re.sub(r"^www\.", "", val)
        val = val.split("/")[0].split(":")[0].strip()
    elif platform in (Platform.PHONE, Platform.WHATSAPP):
        # Normalize Kenyan phone numbers to standard 254XXXXXXXXX
        digits = re.sub(r"\D", "", val)
        if digits.startswith("0") and len(digits) == 10:
            val = "254" + digits[1:]
        elif digits.startswith("254") and len(digits) == 12:
            val = digits
        elif digits.startswith("+254") and len(digits) == 13:
            val = digits[1:]
        elif len(digits) == 9 and (digits.startswith("7") or digits.startswith("1")):
            val = "254" + digits
    elif platform in (Platform.TILL, Platform.PAYBILL):
        val = re.sub(r"\D", "", val)

    return EntityIdentifier(platform=platform, raw_value=raw, normalized_value=val)


def resolve_entity_match(
    query_id: EntityIdentifier,
    target_id: EntityIdentifier,
    verified_cross_links: set[tuple[str, str]] | None = None,
) -> tuple[MatchOutcome, str]:
    """Determine match outcome between two identifiers with strict platform isolation."""
    # 1. Exact platform and exact normalized value
    if query_id.platform == target_id.platform:
        if query_id.normalized_value == target_id.normalized_value:
            return MatchOutcome.EXACT_MATCH, f"Exact match on {query_id.platform.value} ('{query_id.normalized_value}')."
        # Subdomain match on domain platform
        if query_id.platform == Platform.WEBSITE_DOMAIN:
            if query_id.normalized_value.endswith("." + target_id.normalized_value) or target_id.normalized_value.endswith("." + query_id.normalized_value):
                return MatchOutcome.STRONG_MATCH, f"Domain/subdomain relationship between '{query_id.normalized_value}' and '{target_id.normalized_value}'."
        return MatchOutcome.NO_MATCH, "Same platform but different identifiers."

    # 2. Cross-platform comparison:
    # Rule: Same username on Instagram and TikTok are NOT the same entity without verified cross-links!
    if verified_cross_links:
        link_pair = (query_id.composite_key, target_id.composite_key)
        reverse_pair = (target_id.composite_key, query_id.composite_key)
        if link_pair in verified_cross_links or reverse_pair in verified_cross_links:
            return MatchOutcome.STRONG_MATCH, f"Verified relationship established between {query_id.composite_key} and {target_id.composite_key}."

    # If same username across different platforms without verified link:
    if query_id.normalized_value == target_id.normalized_value:
        return (
            MatchOutcome.POSSIBLE_MATCH,
            f"Matching handle name '{query_id.normalized_value}' across different platforms ({query_id.platform.value} vs {target_id.platform.value}). Unconfirmed without independent verification.",
        )

    return MatchOutcome.NO_MATCH, f"Different entities on {query_id.platform.value} and {target_id.platform.value}."


@dataclass
class ReportDeduplicationRecord:
    report_id: str
    incident_hash: str
    reporter_key: str
    text_minhash: list[int]
    created_at: str


def check_report_independence(
    new_text: str,
    new_reporter_key: str,
    existing_reports: list[ReportDeduplicationRecord],
) -> tuple[bool, str | None]:
    """Check if a new report represents an independent incident or a duplicate submission.
    
    Returns (is_independent: bool, duplicate_of_report_id: str | None).
    """
    clean = " ".join(re.sub(r"\d+", "<NUM>", new_text.lower()).split())
    new_hash = hashlib.sha256(clean.encode("utf-8")).hexdigest()[:16]

    for existing in existing_reports:
        # Same reporter submitting again
        if existing.reporter_key == new_reporter_key:
            return False, existing.report_id
        # Exact same narrative script hash submitted
        if existing.incident_hash == new_hash:
            return False, existing.report_id

    return True, None
