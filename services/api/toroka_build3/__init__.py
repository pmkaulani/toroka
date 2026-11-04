"""Build 3: Kenyan registry and cross-platform entity verification."""
from .normalization import extract_claims, normalize_name, normalize_registration_number, normalize_domain, normalize_social_profile, email_domain
from .nea_registry import parse_nea_csv, snapshot_freshness, public_entry
from .entity_resolution import resolve_nea_claim, verify_brs_claim

__all__ = [
    "extract_claims", "normalize_name", "normalize_registration_number", "normalize_domain", "normalize_social_profile", "email_domain",
    "parse_nea_csv", "snapshot_freshness", "public_entry",
    "resolve_nea_claim", "verify_brs_claim",
]
