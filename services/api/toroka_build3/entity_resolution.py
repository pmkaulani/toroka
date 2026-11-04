from __future__ import annotations

from difflib import SequenceMatcher
from datetime import date

from .normalization import normalize_name, normalize_registration_number, normalize_domain, email_domain, GENERIC_EMAIL_DOMAINS
from .nea_registry import public_entry


def _similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    ta, tb = set(a.split()), set(b.split())
    jaccard = len(ta & tb) / max(1, len(ta | tb))
    seq = SequenceMatcher(None, a, b).ratio()
    return max(jaccard, seq)


def resolve_nea_claim(claim: dict, entries: list, snapshot, *, today: date | None = None) -> dict:
    reg = normalize_registration_number(claim.get("nea_registration_number"))
    name = normalize_name(claim.get("business_name"))
    domain = normalize_domain(claim.get("domain"))
    e_domain = email_domain(claim.get("contact_email"))
    candidates = []
    exact_registration = next((x for x in entries if reg and x.registration_number == reg), None)
    if exact_registration:
        candidates = [(exact_registration, 1.0, "exact_nea_registration_number")]
    elif name:
        scored = [(x, _similarity(name, x.normalized_name), "name_similarity_candidate") for x in entries]
        candidates = [(x, score, basis) for x, score, basis in scored if score >= 0.74]
        candidates.sort(key=lambda item: (-item[1], item[0].agency_name.casefold()))
        candidates = candidates[:5]

    snapshot_data = {
        "source_url": snapshot.source_url,
        "data_as_of": snapshot.data_as_of,
        "retrieved_at": snapshot.retrieved_at,
    }
    result = {
        "registry": "National Employment Authority (NEA)",
        "automated_lookup_performed": True,
        "snapshot": {**snapshot_data},
        "candidates": [],
        "status": "no_match_in_snapshot",
        "identity_links": [],
        "limitations": [
            "The agency register verifies a licence record, not the identity of an individual recruiter or a specific job advertisement.",
            "A name-only match is a candidate and may refer to a different entity.",
            "A matching website or email domain is a listed contact detail, not proof that a social account is controlled by the agency.",
        ],
    }
    for row, score, basis in candidates:
        pub = public_entry(row, snapshot, today=today)
        name_match = bool(name and name == row.normalized_name)
        domain_match = bool(domain and domain in (row.website_domains or []))
        email_match = bool(e_domain and e_domain not in GENERIC_EMAIL_DOMAINS and e_domain in (row.email_domains or []))
        registration_match = bool(reg and reg == row.registration_number)
        links = []
        if registration_match:
            links.append({"relation": "exact_nea_registration_number", "match": True, "strength": "strong", "source_url": snapshot.source_url})
        if domain_match:
            links.append({"relation": "registry_lists_claimed_website_domain", "match": True, "strength": "supporting", "source_url": snapshot.source_url})
        if email_match:
            links.append({"relation": "registry_lists_claimed_business_email_domain", "match": True, "strength": "supporting", "source_url": snapshot.source_url})
        if name_match:
            links.append({"relation": "exact_registered_agency_name", "match": True, "strength": "supporting", "source_url": snapshot.source_url})
        result["candidates"].append({
            **pub,
            "match_basis": basis,
            "match_score": round(score, 3),
            "comparisons": {
                "registration_number_match": registration_match,
                "business_name_exact_match": name_match,
                "listed_website_domain_match": domain_match,
                "listed_email_domain_match": email_match,
            },
            "identity_links": links,
        })
    if result["candidates"]:
        top = result["candidates"][0]
        exact = top["comparisons"]["registration_number_match"]
        if top.get("freshness") == "stale":
            result["status"] = "historical_record_only"
        elif exact and top["display_status"] == "valid":
            result["status"] = "listed_valid_in_snapshot"
        elif exact and top["display_status"] in {"expired", "expired_by_record_date", "suspended", "revoked"}:
            result["status"] = "listed_not_current_or_not_valid"
        elif exact:
            result["status"] = "registration_found_status_unclear"
        elif top["comparisons"]["business_name_exact_match"]:
            result["status"] = "name_match_registration_not_confirmed"
        else:
            result["status"] = "possible_name_match_only"
        result["identity_links"] = top["identity_links"]
    return result


def verify_brs_claim(claim: dict, record, associations: list, *, today: date | None = None) -> dict:
    today = today or date.today()
    name = normalize_name(claim.get("business_name"))
    domain = normalize_domain(claim.get("domain"))
    social = str(claim.get("social_profile") or "").strip().casefold()
    email_domain_value = email_domain(claim.get("contact_email"))
    if email_domain_value in GENERIC_EMAIL_DOMAINS:
        email_domain_value = None
    if not record:
        return {
            "registry": "Business Registration Service (BRS)",
            "status": "manual_official_search_required",
            "automated_lookup_performed": False,
            "official_portal_url": "https://brs.ecitizen.go.ke/",
            "comparisons": {},
            "verified_associations": [],
            "what_to_verify": [
                "Sign in to the official BRS/eCitizen portal and search the exact legal or registered name/number.",
                "For a private limited company, request the appropriate official company search (CR12) where needed.",
                "Compare the registration number and registered entity name; do not rely on a similar trading name.",
                "Do not share full shareholder/director details with Toroka. A redacted document or the minimum relevant fields are sufficient for review.",
            ],
            "interpretation_note": "BRS searches require the official eCitizen workflow. Toroka has no public BRS API and has not queried a private account.",
        }
    fresh = bool(record.review_due and record.review_due >= today.isoformat() and record.status == "active")
    exact_name = bool(name and name == record.normalized_name)
    active_associations = [a for a in associations if a.status == "active" and a.review_due >= today.isoformat()]
    domain_match = next((a for a in active_associations if a.association_type == "website_domain" and a.normalized_value == domain and domain), None)
    social_match = next((a for a in active_associations if a.association_type == "social_profile" and a.normalized_value == social and social), None)
    email_domain_match = next((a for a in active_associations if a.association_type == "contact_email_domain" and a.normalized_value == email_domain_value and email_domain_value), None)
    status = "record_match_current" if fresh and exact_name else "registration_match_name_not_compared" if fresh and not name else "record_name_mismatch" if fresh else "record_review_stale"
    verified_associations = []
    for association in (domain_match, social_match, email_domain_match):
        if association:
            verified_associations.append({
                "type": association.association_type,
                "value": association.value,
                "source_url": association.source_url,
                "reviewed_at": association.reviewed_at,
                "review_due": association.review_due,
            })
    return {
        "registry": "Business Registration Service (BRS)",
        "status": status,
        "automated_lookup_performed": True,
        "record": {
            "registered_name": record.registered_name,
            "registration_type": record.registration_type,
            "registration_number_masked": record.registration_masked,
            "source_url": record.source_url,
            "source_checked_at": record.checked_at,
            "review_due": record.review_due,
            "evidence_sha256": record.evidence_sha256,
        },
        "comparisons": {
            "registered_name_exact_match": exact_name,
            "website_domain_association_match": bool(domain_match),
            "social_profile_association_match": bool(social_match),
            "business_email_domain_association_match": bool(email_domain_match),
        },
        "verified_associations": verified_associations,
        "interpretation_note": "A BRS record confirms the registered entity information reviewed by Toroka moderators. A website or social profile is associated only where a separate, reviewed linkage observation exists. Registration does not guarantee the conduct or legitimacy of a specific offer.",
    }
