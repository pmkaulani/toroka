"""Build 3 registry and cross-platform entity-verification endpoints.

The NEA connector consumes a moderator-imported CSV snapshot from the official public
register. BRS records are entered only after a moderator performs the private official
search. No BRS/eCitizen credentials are requested or automated.
"""
from __future__ import annotations

import hashlib
from datetime import date, timedelta
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import db as m
from .deps import Ctx, audit, ctx, current_user, get_db, require_role, throttle
from toroka_build3 import normalize_domain, normalize_name, normalize_registration_number, parse_nea_csv, resolve_nea_claim, verify_brs_claim
from toroka_build3.normalization import normalize_social_profile
from toroka_build3.nea_registry import MAX_CSV_BYTES, snapshot_freshness

router = APIRouter(tags=["build-3-entity-verification"])

BRS_HOSTS = {"brs.go.ke", "www.brs.go.ke", "brs.ecitizen.go.ke", "brsv2.ecitizen.go.ke"}
SHARED_PLATFORM_DOMAINS = {"facebook.com", "instagram.com", "tiktok.com", "x.com", "twitter.com", "linkedin.com", "google.com", "wixsite.com", "blogspot.com", "wordpress.com", "myshopify.com", "vercel.app", "netlify.app", "pages.dev", "github.io"}
PUBLIC_SUFFIX_DOMAINS = {"co.ke", "or.ke", "go.ke", "ac.ke", "sc.ke", "me.ke", "com.ke", "org.ke", "net.ke", "gov.ke"}


class EntityVerifyIn(BaseModel):
    business_name: str | None = Field(None, max_length=180)
    nea_registration_number: str | None = Field(None, max_length=50)
    brs_registration_number: str | None = Field(None, max_length=60)
    domain: str | None = Field(None, max_length=253)
    contact_email: str | None = Field(None, max_length=180)
    social_profile: str | None = Field(None, max_length=500)
    employment_agency: bool = False


class BRSRecordIn(BaseModel):
    registration_type: str = Field(pattern=r"^(company_cr12|business_name|llp|foreign_company)$")
    registration_number: str = Field(min_length=4, max_length=60)
    registered_name: str = Field(min_length=2, max_length=180)
    source_url: str = Field(min_length=12, max_length=300)
    evidence_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    checked_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    review_interval_days: int = Field(default=90, ge=7, le=180)


class AssociationIn(BaseModel):
    association_type: str = Field(pattern=r"^(website_domain|social_profile|contact_email_domain)$")
    value: str = Field(min_length=3, max_length=255)
    source_url: str = Field(min_length=12, max_length=500)
    evidence_sha256: str = Field(pattern=r"^[a-fA-F0-9]{64}$")
    reviewed_at: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    review_interval_days: int = Field(default=90, ge=7, le=180)
    control_review_confirmed: bool = False


def _latest_snapshot(db: Session):
    return db.execute(
        select(m.NEARegistrySnapshot)
        .where(m.NEARegistrySnapshot.status == "active")
        .order_by(m.NEARegistrySnapshot.data_as_of.desc(), m.NEARegistrySnapshot.retrieved_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def _load_nea_entries(db: Session, snapshot):
    if not snapshot:
        return []
    return list(db.execute(
        select(m.NEARegistryEntry)
        .where(m.NEARegistryEntry.snapshot_id == snapshot.id)
        .order_by(m.NEARegistryEntry.agency_name)
    ).scalars())


def _mask_registration(value: str) -> str:
    value = normalize_registration_number(value)
    if len(value) <= 6:
        return "••••"
    return value[:3] + "••••" + value[-3:]


def _validate_brs_url(value: str) -> str:
    try:
        parsed = urlsplit(str(value or ""))
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(422, "source_url is malformed.") from exc
    if parsed.scheme != "https" or host not in BRS_HOSTS or parsed.username or parsed.password or port not in (None, 443) or parsed.query or parsed.fragment:
        raise HTTPException(422, "source_url must be an HTTPS BRS/eCitizen official source URL.")
    return parsed._replace(netloc=host).geturl()[:300]


def _checked_date(value: str) -> date:
    try:
        parsed = date.fromisoformat(value)
    except Exception as exc:
        raise HTTPException(422, "Date must be a valid YYYY-MM-DD date.") from exc
    if parsed > date.today():
        raise HTTPException(422, "Verification dates cannot be in the future.")
    return parsed


def _is_under(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _is_shared_platform_domain(domain: str) -> bool:
    return domain in PUBLIC_SUFFIX_DOMAINS or any(domain == root or domain.endswith("." + root) for root in SHARED_PLATFORM_DOMAINS)


@router.post("/v1/admin/build3/nea/import", tags=["build-3-admin"])
async def import_nea_register(
    request: Request,
    file: UploadFile = File(...),
    source_url: str = Form(...),
    data_as_of: str = Form(...),
    db: Session = Depends(get_db),
    moderator: m.User = Depends(require_role("admin", "moderator")),
):
    """Import the CSV export from the official NEA register; no unofficial scraping."""
    filename = (file.filename or "").lower()
    if not filename.endswith(".csv"):
        raise HTTPException(415, "Upload the CSV export from the official NEA register.")
    raw = await file.read(MAX_CSV_BYTES + 1)
    await file.close()
    if len(raw) > MAX_CSV_BYTES:
        raise HTTPException(413, "NEA register CSV must not exceed 5 MB.")
    try:
        parsed = parse_nea_csv(raw, source_url=source_url, data_as_of=data_as_of)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    for old in db.execute(select(m.NEARegistrySnapshot).where(m.NEARegistrySnapshot.status == "active")).scalars():
        old.status = "superseded"
    snapshot = m.NEARegistrySnapshot(
        source_url=parsed["source_url"], data_as_of=parsed["data_as_of"], retrieved_at=parsed["retrieved_at"],
        content_sha256=parsed["content_sha256"], record_count=parsed["record_count"],
        invalid_rows=parsed["invalid_rows"], imported_by=moderator.id, status="active",
    )
    db.add(snapshot)
    db.flush()
    for row in parsed["rows"]:
        db.add(m.NEARegistryEntry(snapshot_id=snapshot.id, **row))
    audit(db, request, moderator.id, "build3.nea_snapshot.import", "nea_registry_snapshot", snapshot.id,
          {"record_count": parsed["record_count"], "invalid_rows": parsed["invalid_rows"], "data_as_of": parsed["data_as_of"], "source_host": urlsplit(parsed["source_url"]).hostname})
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "This NEA snapshot contains duplicate or conflicting records.") from exc
    return {
        "status": "imported",
        "snapshot_id": snapshot.id,
        "source_url": snapshot.source_url,
        "data_as_of": snapshot.data_as_of,
        "retrieved_at": snapshot.retrieved_at,
        "record_count": snapshot.record_count,
        "invalid_rows_skipped": snapshot.invalid_rows,
        "content_sha256": snapshot.content_sha256,
        **snapshot_freshness(snapshot.data_as_of),
        "note": "Only public register fields and email domains were imported. The CSV itself and full contact email addresses were not retained.",
    }


@router.get("/v1/build3/nea/search", tags=["build-3-registries"])
def search_nea_register(
    request: Request,
    q: str,
    db: Session = Depends(get_db),
    c: Ctx = Depends(ctx),
    user: m.User | None = Depends(current_user),
):
    throttle(request, c, "build3_nea_search", (30, 3600), user.id if user else None)
    query = str(q or "").strip()
    if len(query) < 3 or len(query) > 120:
        raise HTTPException(422, "Search with at least 3 and at most 120 characters.")
    snapshot = _latest_snapshot(db)
    if not snapshot:
        return {
            "status": "snapshot_unavailable",
            "results": [],
            "official_portal_url": "https://www.diaspora.go.ke/verify",
            "interpretation_note": "Toroka has no imported NEA public-register snapshot. Use the official register for a current live check.",
        }
    normalized = normalize_registration_number(query)
    needle = normalize_name(query)
    entries = _load_nea_entries(db, snapshot)
    matched = [e for e in entries if e.registration_number == normalized or needle in e.normalized_name or query.casefold() in e.agency_name.casefold()][:20]
    from toroka_build3.nea_registry import public_entry
    return {
        "status": "checked" if matched else "no_match_in_snapshot",
        "snapshot": {"source_url": snapshot.source_url, "data_as_of": snapshot.data_as_of, "retrieved_at": snapshot.retrieved_at, **snapshot_freshness(snapshot.data_as_of)},
        "results": [public_entry(entry, snapshot) for entry in matched],
        "official_portal_url": "https://www.diaspora.go.ke/verify",
        "interpretation_note": "A no-match result is limited to the imported snapshot and is not proof that an agency is unregistered.",
    }


@router.post("/v1/build3/entities/verify", tags=["build-3-registries"])
def verify_entity(
    body: EntityVerifyIn,
    request: Request,
    db: Session = Depends(get_db),
    c: Ctx = Depends(ctx),
    user: m.User | None = Depends(current_user),
):
    throttle(request, c, "build3_entity_verify", (20, 3600), user.id if user else None)
    claim = body.model_dump(exclude_none=True)
    if not body.employment_agency and not any(claim.get(k) for k in ("business_name", "nea_registration_number", "brs_registration_number", "domain", "contact_email", "social_profile")):
        raise HTTPException(422, "Provide at least one business identity detail to compare.")
    domain = normalize_domain(body.domain) if body.domain else None
    social = normalize_social_profile(body.social_profile) if body.social_profile else None
    if body.domain and not domain:
        raise HTTPException(422, "Provide a valid public website domain.")
    if body.social_profile and not social:
        raise HTTPException(422, "Provide a supported public social profile URL.")
    claim["domain"] = domain
    claim["social_profile"] = social

    nea_result = None
    if body.nea_registration_number or body.employment_agency:
        snapshot = _latest_snapshot(db)
        if snapshot:
            entries = _load_nea_entries(db, snapshot)
            nea_result = resolve_nea_claim(claim, entries, snapshot)
        else:
            nea_result = {
                "registry": "National Employment Authority (NEA)",
                "status": "manual_live_verification_required",
                "automated_lookup_performed": False,
                "official_portal_url": "https://www.diaspora.go.ke/verify",
                "interpretation_note": "No official register snapshot has been imported. Toroka has not queried NEAIMS directly.",
            }

    brs_result = None
    record = None
    if body.brs_registration_number:
        reg = normalize_registration_number(body.brs_registration_number)
        if len(reg) < 4:
            raise HTTPException(422, "BRS registration number is too short after normalization.")
        digest = c.crypto.lookup("brs_registration", reg)
        record = db.execute(select(m.BRSBusinessRecord).where(
            m.BRSBusinessRecord.registration_hmac == digest,
            m.BRSBusinessRecord.status == "active",
        )).scalars().first()

    matched_records = []
    if record:
        matched_records = [record]
    else:
        lookup_values = []
        if domain:
            lookup_values.append(domain)
        if social:
            lookup_values.append(social)
        if body.contact_email:
            from toroka_build3.normalization import email_domain, GENERIC_EMAIL_DOMAINS
            email_domain_value = email_domain(body.contact_email)
            if email_domain_value and email_domain_value not in GENERIC_EMAIL_DOMAINS:
                lookup_values.append(email_domain_value)
        if lookup_values:
            associations = list(db.execute(select(m.BRSBusinessAssociation).where(
                m.BRSBusinessAssociation.normalized_value.in_(set(lookup_values)),
                m.BRSBusinessAssociation.association_type.in_(["website_domain", "social_profile", "contact_email_domain"]),
                m.BRSBusinessAssociation.status == "active",
                m.BRSBusinessAssociation.review_due >= date.today().isoformat(),
            )).scalars())
            ids = {a.business_record_id for a in associations}
            if ids:
                matched_records = list(db.execute(select(m.BRSBusinessRecord).where(
                    m.BRSBusinessRecord.id.in_(ids),
                    m.BRSBusinessRecord.status == "active",
                ).limit(5)).scalars())

    if matched_records:
        candidates = []
        for matched_record in matched_records:
            associations = list(db.execute(select(m.BRSBusinessAssociation).where(m.BRSBusinessAssociation.business_record_id == matched_record.id)).scalars())
            candidates.append(verify_brs_claim(claim, matched_record, associations))
        brs_result = candidates[0]
        if len(candidates) > 1:
            brs_result["additional_candidates"] = [
                {"record": item.get("record"), "comparisons": item.get("comparisons"), "verified_associations": item.get("verified_associations")} 
                for item in candidates[1:]
            ]
        brs_result["match_method"] = "registration_number" if body.brs_registration_number else "reviewed_digital_association"
    elif body.brs_registration_number or body.business_name or domain or social:
        brs_result = verify_brs_claim(claim, None, [])
        if body.business_name:
            normalized = normalize_name(body.business_name)
            possible = list(db.execute(select(m.BRSBusinessRecord).where(
                m.BRSBusinessRecord.normalized_name == normalized,
                m.BRSBusinessRecord.status == "active",
                m.BRSBusinessRecord.review_due >= date.today().isoformat(),
            ).limit(5)).scalars())
            if possible:
                brs_result["name_candidates"] = [{"registered_name": x.registered_name, "registration_number_masked": x.registration_masked,
                                                   "source_url": x.source_url, "checked_at": x.checked_at}
                                                  for x in possible]
                brs_result["status"] = "name_candidate_requires_registration_confirmation"

    result = {
        "status": "review_required",
        "claim_summary": {
            "business_name_supplied": bool(body.business_name),
            "domain_supplied": bool(domain),
            "social_profile_supplied": bool(social),
            "registration_number_supplied": bool(body.nea_registration_number or body.brs_registration_number),
        },
        "nea": nea_result,
        "brs": brs_result,
        "overall_interpretation": "Registry matching helps establish whether an entity record exists. Separate evidence is required to link that entity to a website, social account, recruiter or specific offer.",
        "limitations": [
            "A register entry does not prove that the person contacting you is authorized by the registered entity.",
            "A company registration does not establish that a specific offer, payment request or vacancy is legitimate.",
            "No BRS private account was accessed; BRS records appear here only after moderator review of an official result.",
        ],
    }
    return result


@router.post("/v1/admin/build3/brs-records", tags=["build-3-admin"])
def create_brs_record(
    body: BRSRecordIn,
    request: Request,
    db: Session = Depends(get_db),
    c: Ctx = Depends(ctx),
    moderator: m.User = Depends(require_role("admin", "moderator")),
):
    source_url = _validate_brs_url(body.source_url)
    checked = _checked_date(body.checked_at)
    reg = normalize_registration_number(body.registration_number)
    if not 4 <= len(reg) <= 60:
        raise HTTPException(422, "Registration number is invalid after normalization.")
    normalized_name = normalize_name(body.registered_name)
    if len(normalized_name) < 2:
        raise HTTPException(422, "Registered entity name is invalid.")
    digest = c.crypto.lookup("brs_registration", reg)
    due = (checked + timedelta(days=body.review_interval_days)).isoformat()
    row = db.execute(select(m.BRSBusinessRecord).where(
        m.BRSBusinessRecord.registration_type == body.registration_type,
        m.BRSBusinessRecord.registration_hmac == digest,
    )).scalar_one_or_none()
    if row is None:
        row = m.BRSBusinessRecord(registration_type=body.registration_type, registration_hmac=digest)
    row.registration_masked = _mask_registration(reg)
    row.registered_name = body.registered_name.strip()
    row.normalized_name = normalized_name
    row.source_url = source_url
    row.evidence_sha256 = body.evidence_sha256.lower()
    row.checked_at = checked.isoformat()
    row.review_due = due
    row.reviewer_id = moderator.id
    row.status = "active"
    db.add(row)
    db.flush()
    audit(db, request, moderator.id, "build3.brs_record.reviewed", "brs_business_record", row.id,
          {"registration_type": body.registration_type, "registration_masked": row.registration_masked, "evidence_sha256": row.evidence_sha256, "checked_at": row.checked_at})
    db.commit()
    return {"id": row.id, "status": "reviewed_record_saved", "registered_name": row.registered_name,
            "registration_number_masked": row.registration_masked, "registration_type": row.registration_type,
            "source_url": row.source_url, "checked_at": row.checked_at, "review_due": row.review_due,
            "note": "Only the SHA-256 digest and minimum business fields were retained. No CR12 director/shareholder details or document bytes were stored."}


def _validate_association(body: AssociationIn, record, db: Session) -> tuple[str, str, str]:
    reviewed = _checked_date(body.reviewed_at)
    if not body.control_review_confirmed:
        raise HTTPException(422, "A moderator must explicitly confirm that the digital association was independently reviewed.")
    parsed = urlsplit(body.source_url)
    source_host = (parsed.hostname or "").lower().removeprefix("www.").rstrip(".")
    if parsed.scheme != "https" or not source_host or parsed.username or parsed.password:
        raise HTTPException(422, "Association evidence must be an HTTPS source without embedded credentials.")
    if body.association_type == "website_domain":
        value = normalize_domain(body.value)
        if not value or _is_shared_platform_domain(value):
            raise HTTPException(422, "Provide a business-controlled registrable website domain, not a shared platform.")
        if not _is_under(source_host, value):
            raise HTTPException(422, "For a website association, the evidence URL must be on the domain being reviewed.")
        normalized = value
    elif body.association_type == "social_profile":
        value = normalize_social_profile(body.value)
        if not value:
            raise HTTPException(422, "Social profile must be a supported full profile URL.")
        websites = list(db.execute(select(m.BRSBusinessAssociation).where(
            m.BRSBusinessAssociation.business_record_id == record.id,
            m.BRSBusinessAssociation.association_type == "website_domain",
            m.BRSBusinessAssociation.status == "active",
            m.BRSBusinessAssociation.review_due >= date.today().isoformat(),
        )).scalars())
        if not any(_is_under(source_host, x.normalized_value) for x in websites):
            raise HTTPException(422, "Social profile evidence must be a link from a previously reviewed official business website.")
        normalized = value
    else:
        domain = normalize_domain(body.value)
        if not domain:
            raise HTTPException(422, "Provide a valid email domain, not an email address.")
        websites = list(db.execute(select(m.BRSBusinessAssociation).where(
            m.BRSBusinessAssociation.business_record_id == record.id,
            m.BRSBusinessAssociation.association_type == "website_domain",
            m.BRSBusinessAssociation.status == "active",
            m.BRSBusinessAssociation.review_due >= date.today().isoformat(),
        )).scalars())
        if not any(_is_under(source_host, x.normalized_value) for x in websites):
            raise HTTPException(422, "Email-domain evidence must come from a previously reviewed official business website.")
        value = domain
        normalized = domain
    return value, normalized, parsed.geturl()[:500]


@router.post("/v1/admin/build3/brs-records/{record_id}/associations", tags=["build-3-admin"])
def add_brs_association(
    record_id: str,
    body: AssociationIn,
    request: Request,
    db: Session = Depends(get_db),
    moderator: m.User = Depends(require_role("admin", "moderator")),
):
    record = db.get(m.BRSBusinessRecord, record_id)
    if not record or record.status != "active":
        raise HTTPException(404, "Reviewed BRS record not found.")
    value, normalized, source_url = _validate_association(body, record, db)
    reviewed = _checked_date(body.reviewed_at)
    due = (reviewed + timedelta(days=body.review_interval_days)).isoformat()
    row = db.execute(select(m.BRSBusinessAssociation).where(
        m.BRSBusinessAssociation.business_record_id == record.id,
        m.BRSBusinessAssociation.association_type == body.association_type,
        m.BRSBusinessAssociation.normalized_value == normalized,
    )).scalar_one_or_none()
    if row is None:
        row = m.BRSBusinessAssociation(business_record_id=record.id, association_type=body.association_type, normalized_value=normalized)
    row.value = value
    row.source_url = source_url
    row.evidence_sha256 = body.evidence_sha256.lower()
    row.reviewed_at = reviewed.isoformat()
    row.review_due = due
    row.reviewer_id = moderator.id
    row.status = "active"
    db.add(row)
    db.flush()
    audit(db, request, moderator.id, "build3.brs_association.reviewed", "brs_business_association", row.id,
          {"record_id": record.id, "association_type": body.association_type, "value": value, "evidence_sha256": row.evidence_sha256})
    db.commit()
    return {"id": row.id, "status": "association_reviewed", "association_type": row.association_type,
            "value": row.value, "source_url": row.source_url, "reviewed_at": row.reviewed_at, "review_due": row.review_due,
            "note": "This association is a separate moderator-reviewed relationship, not a fact supplied by the BRS register itself."}


@router.post("/v1/admin/build3/brs-records/{record_id}/revoke", tags=["build-3-admin"])
def revoke_brs_record(
    record_id: str,
    body: dict,
    request: Request,
    db: Session = Depends(get_db),
    moderator: m.User = Depends(require_role("admin", "moderator")),
):
    row = db.get(m.BRSBusinessRecord, record_id)
    reason = str(body.get("reason_code") or "").strip()[:60]
    if not row or not reason:
        raise HTTPException(422, "An existing BRS record and reason_code are required.")
    row.status = "revoked"
    for association in db.execute(select(m.BRSBusinessAssociation).where(m.BRSBusinessAssociation.business_record_id == row.id)).scalars():
        association.status = "revoked"
    audit(db, request, moderator.id, "build3.brs_record.revoked", "brs_business_record", row.id, {"reason_code": reason})
    db.commit()
    return {"id": row.id, "status": "revoked"}
