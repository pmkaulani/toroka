from __future__ import annotations

import re
from datetime import date

from sqlalchemy import select

from .entity_resolution import resolve_nea_claim, verify_brs_claim
from .nea_registry import snapshot_freshness
from .normalization import extract_claims, normalize_registration_number, email_domain, GENERIC_EMAIL_DOMAINS

RECRUITMENT_CONTEXT = re.compile(r"(?i)\b(recruitment agency|employment agency|job agency|job placement|work abroad|overseas recruitment|recruiter|employment agent|nea reg(?:istration)?|nea licence|nea license)\b")
BRS_CONTEXT = re.compile(r"(?i)\b(brs|business registration|company registration|registered business|cr12|cr 12)\b")
ENTITY_CONTEXT = re.compile(r"(?i)\b(shop|seller|store|business|company|merchant|vendor|brand|agency)\b")


def _labelled_value(text: str, labels: str) -> str | None:
    match = re.search(rf"(?im)^\s*(?:{labels})\s*[:#-]\s*([^\n\r]{{2,180}})", text)
    return match.group(1).strip(" .;,") if match else None


def build3_case_entity_context(db, crypto, text: str) -> dict | None:
    """Append a narrowly triggered, registry-only context block to a normal check.

    No network calls occur here. An NEA result is possible only from a moderator-imported
    snapshot; a BRS result is possible only from a moderator-reviewed record.
    """
    text = str(text or "")[:50000]
    claims = extract_claims(text)
    is_job = bool(RECRUITMENT_CONTEXT.search(text))
    is_brs = bool(BRS_CONTEXT.search(text))
    is_entity = bool(ENTITY_CONTEXT.search(text))
    agency_name = _labelled_value(text, r"agency\s+name|recruitment\s+agency|employment\s+agency|recruiter")
    business_name = _labelled_value(text, r"business\s+name|company\s+name|registered\s+name|legal\s+name")
    domain = claims["domains"][0] if claims["domains"] else None
    email = claims["emails"][0] if claims["emails"] else None
    social = claims["social_profiles"][0] if claims["social_profiles"] else None
    has_digital_presence = bool(domain or social or email)
    if not (is_job or is_brs or agency_name or business_name or claims["nea_registration_numbers"] or claims["brs_registration_numbers"] or (is_entity and has_digital_presence)):
        return None
    result: dict = {
        "status": "review_required",
        "triggered_by": "recruitment_or_business_registry_context",
        "nea": None,
        "brs": None,
        "interpretation_note": "Registry checks establish records and separately reviewed links; they do not authenticate the person contacting you or validate a particular offer.",
        "limitations": [
            "No private government registry credentials were used.",
            "No registry match is not proof that an organisation does not exist; the source snapshot may be incomplete or stale.",
        ],
    }

    nea_no = claims["nea_registration_numbers"][0] if claims["nea_registration_numbers"] else None
    if is_job or nea_no:
        from app import db as models
        snapshot = db.execute(select(models.NEARegistrySnapshot).where(models.NEARegistrySnapshot.status == "active")
                              .order_by(models.NEARegistrySnapshot.data_as_of.desc(), models.NEARegistrySnapshot.retrieved_at.desc()).limit(1)).scalar_one_or_none()
        if snapshot and nea_no:
            entries = list(db.execute(select(models.NEARegistryEntry).where(models.NEARegistryEntry.snapshot_id == snapshot.id)).scalars())
            result["nea"] = resolve_nea_claim({
                "nea_registration_number": nea_no,
                "business_name": agency_name,
                "domain": domain,
                "contact_email": email,
            }, entries, snapshot)
        elif snapshot:
            result["nea"] = {
                "registry": "National Employment Authority (NEA)",
                "status": "agency_identifier_not_supplied",
                "automated_lookup_performed": False,
                "snapshot": {"data_as_of": snapshot.data_as_of, **snapshot_freshness(snapshot.data_as_of)},
                "official_portal_url": "https://www.diaspora.go.ke/verify",
                "what_to_verify": ["Search the exact agency name or NEA registration number on the official register.", "Check licence status and expiry on the day you perform the lookup."],
            }
        else:
            result["nea"] = {
                "registry": "National Employment Authority (NEA)",
                "status": "official_snapshot_not_available",
                "automated_lookup_performed": False,
                "official_portal_url": "https://www.diaspora.go.ke/verify",
                "what_to_verify": ["Search the exact agency name or licence number on the official NEA register.", "Check the displayed status and expiry date directly before paying or sharing documents."],
                "interpretation_note": "Toroka has not performed a live NEA lookup. No imported official snapshot is available in this deployment.",
            }

    brs_no = claims["brs_registration_numbers"][0] if claims["brs_registration_numbers"] else None
    if is_brs or brs_no or business_name or (is_entity and has_digital_presence):
        from app.db import BRSBusinessRecord, BRSBusinessAssociation
        brs_claim = {"business_name": business_name or "", "domain": domain, "social_profile": social, "contact_email": email}
        record = None
        if brs_no:
            digest = crypto.lookup("brs_registration", normalize_registration_number(brs_no))
            record = db.execute(select(BRSBusinessRecord).where(
                BRSBusinessRecord.registration_hmac == digest,
                BRSBusinessRecord.status == "active")).scalars().first()
        matched_records = [record] if record else []
        if not matched_records:
            lookup_values = [x for x in [domain, social, (email_domain(email) if email else None)] if x and x not in GENERIC_EMAIL_DOMAINS]
            if lookup_values:
                matches = list(db.execute(select(BRSBusinessAssociation).where(
                    BRSBusinessAssociation.normalized_value.in_(set(lookup_values)),
                    BRSBusinessAssociation.status == "active",
                    BRSBusinessAssociation.review_due >= date.today().isoformat(),
                )).scalars())
                record_ids = {a.business_record_id for a in matches}
                if record_ids:
                    matched_records = list(db.execute(select(BRSBusinessRecord).where(
                        BRSBusinessRecord.id.in_(record_ids), BRSBusinessRecord.status == "active").limit(5)).scalars())
        if matched_records:
            brs_candidates = []
            for matched in matched_records:
                associations = list(db.execute(select(BRSBusinessAssociation).where(BRSBusinessAssociation.business_record_id == matched.id)).scalars())
                brs_candidates.append(verify_brs_claim(brs_claim, matched, associations))
            result["brs"] = brs_candidates[0]
            result["brs"]["match_method"] = "registration_number" if brs_no else "reviewed_digital_association"
            if len(brs_candidates) > 1:
                result["brs"]["additional_candidates"] = [x.get("record") for x in brs_candidates[1:]]
        else:
            result["brs"] = verify_brs_claim(brs_claim, None, [])
    return result
