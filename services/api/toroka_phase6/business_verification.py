from __future__ import annotations
from math import radians, sin, cos, sqrt, atan2
import re
import unicodedata

SOURCE_AUTHORITY = {"verified_brs_official_search": "official_record", "authorized_registry_response": "official_record",
                    "user_uploaded_registry_document": "user_submitted_artifact", "maps_place_listing": "public_web_observation",
                    "merchant_claim": "user_submitted_artifact"}


def normalize_business_name(value: str) -> str:
    value = unicodedata.normalize("NFKD", str(value or "")).encode("ascii", "ignore").decode("ascii").lower()
    value = re.sub(r"\b(limited|ltd|plc|company|co)\b", " ", value)
    return " ".join(re.sub(r"[^a-z0-9]+", " ", value).split())


def normalize_ke_phone(value: str) -> str | None:
    digits = re.sub(r"\D", "", str(value or ""))
    if digits.startswith("+254"):
        digits = digits[1:]
    if digits.startswith(("2547", "2541")) and len(digits) == 12:
        return digits
    if digits.startswith(("07", "01")) and len(digits) == 10:
        return "254" + digits[1:]
    if len(digits) == 9 and digits.startswith(("7", "1")):
        return "254" + digits
    return None


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1 = a
    lat2, lon2 = b
    if not (-90 <= lat1 <= 90 and -90 <= lat2 <= 90 and -180 <= lon1 <= 180 and -180 <= lon2 <= 180):
        raise ValueError("invalid coordinates")
    r = 6371.0088
    dlat, dlon = radians(lat2-lat1), radians(lon2-lon1)
    h = sin(dlat/2)**2 + cos(radians(lat1))*cos(radians(lat2))*sin(dlon/2)**2
    return 2*r*atan2(sqrt(h), sqrt(1-h))


def compare_business_records(claim: dict, record: dict) -> dict:
    """Compare a seller claim against a source-classified record, without overclaiming.

    Only verified_brs_official_search and authorized_registry_response become
    official_record. A Maps listing is a candidate location, never BRS proof.
    """
    source = record.get("source_type")
    if source not in SOURCE_AUTHORITY:
        raise ValueError("unsupported business record source_type")
    group = SOURCE_AUTHORITY[source]
    official = group == "official_record"
    name_a = normalize_business_name(claim.get("business_name", ""))
    name_b = normalize_business_name(record.get("registered_name", record.get("business_name", "")))
    name_match = bool(name_a and name_b and (name_a == name_b or name_a in name_b or name_b in name_a))
    reg_a = re.sub(r"\s+", "", str(claim.get("registration_number", "")).upper())
    reg_b = re.sub(r"\s+", "", str(record.get("registration_number", "")).upper())
    reg_match = bool(reg_a and reg_b and reg_a == reg_b)
    phone_a = normalize_ke_phone(claim.get("public_business_phone", ""))
    phone_b = normalize_ke_phone(record.get("public_business_phone", ""))
    phone_match = bool(phone_a and phone_b and phone_a == phone_b)
    location_distance_km = None
    location_consistent = None
    claim_coords = claim.get("coordinates")
    record_coords = record.get("coordinates")
    if isinstance(claim_coords, (list, tuple)) and isinstance(record_coords, (list, tuple)) and len(claim_coords) == 2 and len(record_coords) == 2:
        location_distance_km = round(haversine_km(tuple(claim_coords), tuple(record_coords)), 3)
        # Address geocoding can be imprecise; 1.5 km is a review threshold, not an identity verdict.
        location_consistent = location_distance_km <= 1.5
    mismatches = []
    if reg_a and reg_b and not reg_match:
        mismatches.append("registration_number")
    if name_a and name_b and not name_match:
        mismatches.append("business_name")
    if phone_a and phone_b and not phone_match:
        mismatches.append("public_business_phone")
    if official and reg_match and name_match:
        status = "registry_identity_match"
    elif official and mismatches:
        status = "registry_record_mismatch"
    elif official and (name_match or reg_match):
        status = "partial_registry_match"
    elif source == "maps_place_listing" and location_consistent is False:
        status = "location_candidate_discrepancy"
    elif source == "maps_place_listing":
        status = "location_candidate_only"
    elif source in {"user_uploaded_registry_document", "merchant_claim"}:
        status = "unverified_claim_or_document"
    else:
        status = "insufficient_record_data"
    return {"status": status, "source_group": group, "official_record": official,
            "comparisons": {"business_name_match": name_match, "registration_number_match": reg_match, "public_phone_match": phone_match,
                            "location_consistent_within_1_5km": location_consistent},
            "location_distance_km": location_distance_km,
            "mismatches": mismatches,
            "limitations": ["A registry identity match does not prove the social account is controlled by the registered entity.",
                            "A registered business can still engage in poor fulfilment or fraud.",
                            "A map listing is a location candidate and is not an official business-registration record."]}
