"""Single vocabulary shared by UI, API and copy (see docs/adr/ADR-002).

The four "we don't know" meanings are deliberately distinct:
  not_checked      we did not run this check
  could_not_check  we tried; the source failed or was blocked
  not_found        we checked the source and found no record (not proof of anything)
  inconclusive     the overall verdict when evidence is too thin either way
"""
from enum import StrEnum

POLICY_VERSION = "assessment-policy-v0.3"


class Label(StrEnum):
    HIGH_RISK = "high_risk"
    SUSPICIOUS_VERIFY_FIRST = "suspicious_verify_first"
    INCONCLUSIVE = "inconclusive"
    NO_KNOWN_THREATS_FOUND = "no_known_threats_found"
    VERIFIED_OFFICIAL = "verified_official"


class CoverageStatus(StrEnum):
    CHECKED = "checked"
    NOT_CHECKED = "not_checked"
    COULD_NOT_CHECK = "could_not_check"
    NOT_FOUND = "not_found"
    # Granular investigation statuses (Quality Standard ADR-002 / Spec 7)
    CHECKED_MATCH = "checked_match"
    CHECKED_NO_MATCH = "checked_no_match"
    FAILED = "failed"
    NOT_CONFIGURED = "not_configured"
    NOT_APPLICABLE = "not_applicable"
    INACCESSIBLE = "inaccessible"
    PARTIALLY_CHECKED = "partially_checked"


class VerificationStatus(StrEnum):
    """Evidence separation: status of a finding relative to verified facts."""
    CONFIRMED = "confirmed"
    OBSERVED = "observed"
    REPORTED = "reported"
    UNVERIFIED = "unverified"
    CONTRADICTORY = "contradictory"
    UNAVAILABLE = "unavailable"


class ReliabilityClassification(StrEnum):
    """Reliability classification for evidence separation (Spec 5)."""
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    UNVERIFIED = "unverified"


class EvidenceType(StrEnum):
    VERIFIED_SOURCE = "verified_source"
    MODERATED_REPORT = "moderated_report"
    AUTOMATED_OBSERVATION = "automated_observation"
    UNRESOLVED_CLAIM = "unresolved_claim"


class Strength(StrEnum):
    STRONG = "strong"
    SUPPORTING = "supporting"
    WEAK = "weak"


STRENGTH_ORDER = {Strength.STRONG: 3, Strength.SUPPORTING: 2, Strength.WEAK: 1}


class ClaimStatus(StrEnum):
    """Claim-level status (blueprint 4.9). A claim is never called false without a cited source."""
    VERIFIED_FALSE = "verified_false"
    CONTRADICTED_BY_SOURCE = "contradicted_by_source"
    UNSUPPORTED = "unsupported"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    NOT_ASSESSED = "not_assessed"
