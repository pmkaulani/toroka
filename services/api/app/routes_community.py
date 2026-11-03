"""Community reports, public indicators, moderation, appeals and business claims (blueprint 4.11, section 12.2).

Reports are private. Only a moderated indicator (identifier + count + month) is ever searchable, never a narrative.
"""
from __future__ import annotations

import itertools
import json
import random
import re
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session
from ssi_rules import normalize as nz
from ssi_rules.fingerprint import minhash, script_hash, similarity
from ssi_rules.signals import mask_credential_values

from . import db as m
from .deps import Ctx, audit, client_key, ctx, current_user, get_db, require_role, require_user, throttle
from .schemas import AdjudicationIn, AppealIn, BusinessClaimIn, FeedbackIn, IdentifierIn, ModerationActionIn, ReportIn
from .security import new_token, same, sha256

router = APIRouter()
MOD = require_role("moderator", "admin")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


_HANDLE_PLATFORMS = {"instagram", "tiktok", "facebook", "x", "twitter", "whatsapp", "threads"}
_SOCIAL_PROFILE_URL = re.compile(
    r"(?i)^(?:https?://)?(?:www\.)?(instagram\.com|tiktok\.com|facebook\.com|x\.com|twitter\.com|threads\.net)/@?([A-Za-z0-9_.-]{2,50})/?(?:[?#].*)?$"
)
_HANDLE_RESERVED = {"p", "reel", "reels", "stories", "explore", "accounts", "login", "about", "share", "intent", "hashtag", "search"}


def norm_identifier(kind: str, value: str) -> tuple[str, str]:
    """-> (canonical value, masked display). Raises 422 for values we cannot validate."""
    v = value.strip()
    if kind == "phone":
        n = nz.normalize_ke_phone(v)
        if n:
            return n, nz.mask_phone(n)
    elif kind in ("till", "paybill"):
        if re.fullmatch(r"\d{5,7}", v):
            return v, f"{kind} ••{v[-3:]}"
    elif kind == "domain":
        p = nz.parse_url(v)
        if p and not p.is_ip and "." in p.host:
            return p.registered_domain, p.registered_domain
    elif kind == "handle":
        # A full profile URL preserves its platform, avoiding collisions between
        # unrelated accounts that happen to share the same username.
        m = _SOCIAL_PROFILE_URL.fullmatch(v)
        if m:
            platform = m.group(1).lower().split(".")[0]
            if platform == "twitter":
                platform = "x"
            handle = m.group(2).lstrip("@").lower()
            if handle not in _HANDLE_RESERVED and re.fullmatch(r"[a-z0-9][a-z0-9_.-]{1,49}", handle):
                return f"{platform}:{handle}", f"@{handle} ({platform.title()})"
        # The UI may explicitly provide platform:handle after parsing a URL.
        m = re.fullmatch(r"(?i)(instagram|tiktok|facebook|x|twitter|whatsapp|threads):@?([a-z0-9][a-z0-9_.-]{1,49})", v)
        if m:
            platform, handle = m.group(1).lower(), m.group(2).lower()
            if platform == "twitter":
                platform = "x"
            if handle not in _HANDLE_RESERVED:
                return f"{platform}:{handle}", f"@{handle} ({platform.title()})"
        # A bare @handle is intentionally platform-agnostic. Lookup will search
        # each supported platform independently and preserve ambiguous matches.
        m = re.fullmatch(r"@([a-zA-Z0-9][a-zA-Z0-9_.-]{1,49})", v)
        if m and m.group(1).lower() not in _HANDLE_RESERVED:
            handle = m.group(1).lower()
            return f"social:{handle}", f"@{handle} (platform not specified)"
    raise HTTPException(422, f"That {kind} is not in a format we can use.")


def upsert_subject(db: Session, c: Ctx, kind: str, value: str, masked: str) -> m.Subject:
    h = c.crypto.lookup(kind, value)
    s = db.execute(select(m.Subject).where(m.Subject.subject_type == kind, m.Subject.lookup_hmac == h)).scalar_one_or_none()
    if s:
        s.last_seen_at = m.now_iso()
        return s
    s = m.Subject(subject_type=kind, lookup_hmac=h, display_masked=masked, value_encrypted=c.crypto.enc(value))
    db.add(s)
    db.flush()
    return s


def queue_notification(db: Session, c: Ctx, channel: str, to: str, template: str, payload: dict, consent: str, user_id: str | None = None):
    db.add(m.Notification(user_id=user_id, channel=channel, template=template, to_encrypted=c.crypto.enc(to), payload_encrypted=c.crypto.enc(json.dumps(payload)), consent_context=consent))


# ------------------------------------------------------------------ reports
@router.post("/v1/reports", status_code=201, tags=["reports"])
def create_report(body: ReportIn, request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx), user=Depends(current_user)):
    throttle(request, c, "reports", c.settings.rl_reports, user.id if user else None)
    key = c.crypto.lookup("reporter", user.id) if user else client_key(request, c)
    ids = [(i.type, *norm_identifier(i.type, i.value)) for i in body.identifiers]
    narrative, had_cred = mask_credential_values(body.narrative)
    token = new_token()
    r = m.Report(reporter_user_id=user.id if user else None, reporter_key=key, token_hash=sha256(token), category=body.category,
                 narrative_encrypted=c.crypto.enc(narrative), script_hash=script_hash(narrative), minhash=minhash(narrative), incident_date=body.incident_date,
                 amount_band=body.amount_band, contact_encrypted=c.crypto.enc(body.contact) if (body.contact and body.consent_to_contact) else None)
    db.add(r)
    db.flush()
    subjects = []
    for kind, val, masked in ids:
        s = upsert_subject(db, c, kind, val, masked)
        if s.id not in {x.id for x in subjects}:
            subjects.append(s)
            db.add(m.ReportSubject(report_id=r.id, subject_id=s.id))
    db.flush()
    # duplicate detection and case linking
    sub_ids = [s.id for s in subjects]
    others = db.execute(select(m.Report).join(m.ReportSubject, m.ReportSubject.report_id == m.Report.id)
                        .where(m.ReportSubject.subject_id.in_(sub_ids), m.Report.id != r.id, m.Report.moderation_status != "rejected")).scalars().unique().all()
    def _recent(o):          # same person, same identifier, within a day: one report, however it is worded
        return (datetime.fromisoformat(r.created_at) - datetime.fromisoformat(o.created_at)).total_seconds() < 86400
    dup = next((o for o in others if o.reporter_key == key and (_recent(o) or o.script_hash == r.script_hash or similarity(o.minhash, r.minhash) >= 0.9)), None)
    if dup:
        r.moderation_status, r.duplicate_of, r.public_outcome = "duplicate", dup.id, "duplicate_merged"
    r.possible_coordinated = any(o.reporter_key != key and similarity(o.minhash, r.minhash) >= 0.95 and o.created_at[:13] == r.created_at[:13] for o in others)
    for a, b in itertools.combinations(sorted(sub_ids), 2):
        _edge(db, a, b, "co_reported", r.id)
    if not dup:
        for o in db.execute(select(m.Report).where(m.Report.script_hash == r.script_hash, m.Report.id != r.id).limit(20)).scalars():
            osub = [x.subject_id for x in db.execute(select(m.ReportSubject).where(m.ReportSubject.report_id == o.id)).scalars()]
            for a in sub_ids:
                for b in osub:
                    if a != b:
                        _edge(db, *sorted((a, b)), "same_script", r.script_hash[:16])
    audit(db, request, user.id if user else None, "report.create", "report", r.id)
    db.commit()
    return {"report_id": r.id, "status": r.moderation_status, "report_token": token, "duplicate_of": r.duplicate_of,
            "message": ("This looks like a report you already sent, so it was merged with it." if dup else
                        "Thank you. Your report is private and will be reviewed by a moderator before anything is published. Nothing is public yet."),
            "credential_values_hidden": had_cred}


def _edge(db: Session, a: str, b: str, rel: str, ref: str):
    e = db.execute(select(m.EntityEdge).where(m.EntityEdge.subject_a == a, m.EntityEdge.subject_b == b, m.EntityEdge.relation_type == rel)).scalar_one_or_none()
    if e:
        e.last_seen_at = m.now_iso()
        e.strength_band = "medium"
    else:
        db.add(m.EntityEdge(subject_a=a, subject_b=b, relation_type=rel, evidence_ref=ref))
    db.flush()


@router.get("/v1/reports/search", tags=["reports"])
def search_indicators(request: Request, type: str = Query(..., pattern="^(phone|till|paybill|domain|handle)$"), value: str = Query(..., max_length=120),
                      db: Session = Depends(get_db), c: Ctx = Depends(ctx)):
    key = client_key(request, c)
    throttle(request, c, "search", c.settings.rl_search, key)
    wait = c.limiter.distinct(f"enum:{key}", f"{type}:{value}", c.settings.rl_search_distinct, 3600)
    if wait:
        raise HTTPException(429, "You have looked up several different identifiers. Please wait before looking up more.", headers={"Retry-After": str(int(wait))})
    val, _masked = norm_identifier(type, value)
    candidates = [val]
    if type == "handle" and val.startswith("social:"):
        handle = val.split(":", 1)[1]
        candidates = [f"{platform}:{handle}" for platform in ("instagram", "tiktok", "facebook", "x", "whatsapp", "threads")] + [val]
    rows = db.execute(select(m.Indicator, m.Subject).join(m.Subject, m.Subject.id == m.Indicator.subject_id)
                      .where(m.Subject.subject_type == type,
                             m.Subject.lookup_hmac.in_([c.crypto.lookup(type, candidate) for candidate in candidates]),
                             m.Indicator.status.in_(["published", "under_review"]))).all()
    # Never merge reports across platforms. A bare @handle can match different accounts;
    # return separate records and make the ambiguity explicit to the client.
    if not rows:
        return {"found": False, "message": "No published reports. That is not proof of anything: most problems are never reported."}

    def _public_indicator(ind, subj):
        return {"id": ind.id, "identifier": subj.display_masked, "kind": subj.subject_type, "status": ind.status,
                "independent_reports": ind.independent_reports, "last_reported": (ind.last_reported or "")[:7], "basis": ind.basis,
                "summary": f"{ind.independent_reports} independent {'report' if ind.independent_reports == 1 else 'reports'} reviewed by moderators.",
                "disclaimer": "These are user reports, not a court finding. If you own this identifier and think the entry is wrong, you can ask for a correction.",
                "correction_path": f"/v1/appeals (indicator_id={ind.id})",
                **({"note": "This entry is under review after a correction or appeal request."} if ind.status == "under_review" else {})}
    matches = [_public_indicator(ind, subj) for ind, subj in rows]
    if type == "handle" and val.startswith("social:"):
        return {"found": True, "matches": matches, "ambiguous_platform": True,
                "message": "This is a handle-only match, not an exact profile match. Confirm the platform and full profile URL; matching names do not prove the accounts belong to the same seller."}
    if len(matches) == 1:
        return {"found": True, "indicator": matches[0]}
    return {"found": True, "matches": matches, "ambiguous_platform": False,
            "message": "Separate platform-specific records are shown separately. Confirm the exact profile URL before treating them as the same seller."}


@router.get("/v1/reports/{report_id}", tags=["reports"])
def report_status(report_id: str, db: Session = Depends(get_db), user=Depends(current_user), x_report_token: str | None = Header(default=None)):
    r = db.get(m.Report, report_id)
    if not r or not ((user and r.reporter_user_id == user.id) or (x_report_token and same(r.token_hash, sha256(x_report_token)))):
        raise HTTPException(404, "Report not found.")
    return {"report_id": r.id, "status": r.moderation_status, "outcome": r.public_outcome, "created_at": r.created_at}


# ------------------------------------------------------------------ indicators
def recompute_indicator(db: Session, c: Ctx, subject_id: str, publish: bool = False, verified_by_source: str | None = None) -> m.Indicator | None:
    rows = db.execute(select(m.Report).join(m.ReportSubject, m.ReportSubject.report_id == m.Report.id)
                      .where(m.ReportSubject.subject_id == subject_id, m.Report.moderation_status == "approved")).scalars().unique().all()
    independent = len({r.reporter_key for r in rows})
    last = max([(r.incident_date or r.created_at[:10]) for r in rows], default=None)
    ind = db.execute(select(m.Indicator).where(m.Indicator.subject_id == subject_id)).scalar_one_or_none()
    override = bool(verified_by_source) or bool(ind and ind.basis == "verified_by_source" and ind.status != "withdrawn")
    eligible = independent >= c.settings.min_independent_to_publish or (override and independent >= 1)
    if ind and ind.status == "under_review":
        ind.independent_reports, ind.last_reported = independent, last
        return ind
    if (publish or (ind and ind.status == "published")) and eligible:
        if not ind:
            ind = m.Indicator(subject_id=subject_id)
            db.add(ind)
        ind.status, ind.independent_reports, ind.last_reported = "published", independent, last
        if verified_by_source:
            ind.basis, ind.basis_note = "verified_by_source", verified_by_source[:200]
    elif ind and ind.status == "published":
        ind.status, ind.independent_reports = "withdrawn", independent        # below the threshold again: take it down
    db.flush()
    return ind


# ------------------------------------------------------------------ moderation
def _subjects_of(db: Session, report_id: str) -> list[m.Subject]:
    return db.execute(select(m.Subject).join(m.ReportSubject, m.ReportSubject.subject_id == m.Subject.id).where(m.ReportSubject.report_id == report_id)).scalars().all()


@router.get("/v1/moderation/queue", tags=["moderation"])
def queue(request: Request, status: str = "pending", limit: int = 50, db: Session = Depends(get_db), c: Ctx = Depends(ctx), mod: m.User = Depends(MOD)):
    rows = db.execute(select(m.Report).where(m.Report.moderation_status == status).order_by(m.Report.created_at).limit(min(limit, 100))).scalars().all()
    out = []
    for r in rows:
        subs = _subjects_of(db, r.id)
        same_script = db.execute(select(m.Report).where(m.Report.script_hash == r.script_hash, m.Report.id != r.id)).scalars().all()
        out.append({"report_id": r.id, "created_at": r.created_at, "category": r.category, "narrative": c.crypto.dec(r.narrative_encrypted),
                    "identifiers": [{"id": s.id, "kind": s.subject_type, "masked": s.display_masked} for s in subs], "amount_band": r.amount_band, "incident_date": r.incident_date,
                    "same_script_reports": len(same_script), "distinct_reporters_same_script": len({o.reporter_key for o in same_script} | {r.reporter_key}),
                    "possible_coordinated": r.possible_coordinated, "duplicate_of": r.duplicate_of})
    audit(db, request, mod.id, "moderation.queue_read", "report", None, {"count": len(out), "status": status})
    db.commit()
    return {"reports": out}


@router.post("/v1/moderation/reports/{report_id}/action", tags=["moderation"])
def moderate(report_id: str, body: ModerationActionIn, request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx), mod: m.User = Depends(MOD)):
    r = db.get(m.Report, report_id)
    if not r:
        raise HTTPException(404, "Report not found.")
    if body.publish and body.action != "approve":
        raise HTTPException(422, "Only an approved report can be published.")
    if body.action == "mark_duplicate" and not (body.duplicate_of and db.get(m.Report, body.duplicate_of)):
        raise HTTPException(422, "Say which report this duplicates.")
    status = {"approve": "approved", "reject": "rejected", "request_info": "needs_info", "mark_duplicate": "duplicate"}[body.action]
    outcome = {"approve": "accepted", "reject": "not_accepted", "request_info": "more_information_needed", "mark_duplicate": "duplicate_merged"}[body.action]
    r.moderation_status, r.public_outcome, r.duplicate_of = status, outcome, body.duplicate_of if body.action == "mark_duplicate" else r.duplicate_of
    db.add(m.ModerationAction(moderator_id=mod.id, target_type="report", target_id=r.id, action=body.action, reason_code=body.reason_code, notes=body.notes))
    published = []
    for s in _subjects_of(db, r.id):
        ind = recompute_indicator(db, c, s.id, publish=body.publish, verified_by_source=body.verified_by_source)
        if ind:
            published.append({"indicator_id": ind.id, "status": ind.status, "independent_reports": ind.independent_reports})
    if r.contact_encrypted:
        queue_notification(db, c, "contact", c.crypto.dec(r.contact_encrypted), "report_outcome", {"report_id": r.id, "outcome": outcome}, "reporter_consented_to_contact", r.reporter_user_id)
    audit(db, request, mod.id, f"moderation.{body.action}", "report", r.id, {"reason_code": body.reason_code})
    db.commit()
    return {"report_id": r.id, "status": status, "indicators": published}


@router.post("/v1/moderation/indicators/{indicator_id}/takedown", tags=["moderation"])
def takedown(indicator_id: str, body: ModerationActionIn, request: Request, db: Session = Depends(get_db), mod: m.User = Depends(MOD)):
    ind = db.get(m.Indicator, indicator_id)
    if not ind:
        raise HTTPException(404, "Indicator not found.")
    ind.status = "withdrawn"
    db.add(m.ModerationAction(moderator_id=mod.id, target_type="indicator", target_id=ind.id, action="urgent_takedown", reason_code=body.reason_code, notes=body.notes))
    audit(db, request, mod.id, "moderation.urgent_takedown", "indicator", ind.id, {"reason_code": body.reason_code})
    db.commit()
    return {"indicator_id": ind.id, "status": "withdrawn"}


@router.get("/v1/moderation/campaigns", tags=["moderation"])
def campaigns(db: Session = Depends(get_db), mod: m.User = Depends(MOD)):
    groups: dict[str, list[m.Report]] = defaultdict(list)
    for r in db.execute(select(m.Report).where(m.Report.moderation_status != "rejected")).scalars():
        groups[r.script_hash].append(r)
    out = []
    for h, rs in groups.items():
        if len(rs) < 2:
            continue
        subs = {s.id: s.display_masked for r in rs for s in _subjects_of(db, r.id)}
        out.append({"script_id": h[:12], "reports": len(rs), "distinct_reporters": len({r.reporter_key for r in rs}), "identifiers": len(subs), "sample_identifiers": list(subs.values())[:5],
                    "first_seen": min(r.created_at for r in rs), "last_seen": max(r.created_at for r in rs), "category": rs[0].category})
    return {"campaigns": sorted(out, key=lambda g: -g["reports"])}


# ------------------------------------------------------------------ appeals and corrections
@router.post("/v1/appeals", status_code=201, tags=["appeals"])
def create_appeal(body: AppealIn, request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx)):
    throttle(request, c, "appeals", c.settings.rl_appeals)
    ind = db.get(m.Indicator, body.indicator_id)
    if not ind or ind.status == "withdrawn":
        raise HTTPException(404, "That entry was not found.")
    contact = body.contact.strip()
    kind = "email" if EMAIL.match(contact) else "phone" if nz.normalize_ke_phone(contact) else None
    if not kind:
        raise HTTPException(422, "Give an email address or a Kenyan mobile number we can verify.")
    contact = contact.lower() if kind == "email" else nz.normalize_ke_phone(contact)
    code, token = f"{random.SystemRandom().randrange(10**6):06d}", new_token()
    a = m.Appeal(indicator_id=ind.id, requester_contact_encrypted=c.crypto.enc(contact), contact_kind=kind, issue_type=body.issue_type,
                 statement_encrypted=c.crypto.enc(body.statement), token_hash=sha256(token), code_hash="")
    db.add(a)
    db.flush()
    a.code_hash = sha256(f"{a.id}:{code}")
    queue_notification(db, c, kind, contact, "appeal_verification", {"code": code, "appeal_id": a.id}, "requester_initiated_appeal")
    audit(db, request, None, "appeal.create", "appeal", a.id)
    db.commit()
    resp = {"appeal_id": a.id, "appeal_token": token, "status": a.status, "message": "We sent a code to the contact you gave. Enter it to open your request. Nothing changes until you verify."}
    if c.settings.dev_echo_codes:
        resp["dev_code"] = code
    return resp


@router.post("/v1/appeals/{appeal_id}/verify", tags=["appeals"])
def verify_appeal(appeal_id: str, body: dict, request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx), x_appeal_token: str | None = Header(default=None)):
    a = db.get(m.Appeal, appeal_id)
    if not a or not x_appeal_token or not same(a.token_hash, sha256(x_appeal_token)):
        raise HTTPException(404, "Request not found.")
    if a.status != "pending_verification":
        return {"appeal_id": a.id, "status": a.status}
    if a.code_attempts >= 5:
        raise HTTPException(429, "Too many wrong codes. Please start a new request.")
    a.code_attempts += 1
    if not same(a.code_hash, sha256(f"{a.id}:{str(body.get('code', '')).strip()}")):
        db.commit()
        raise HTTPException(400, "That code is not right.")
    a.status = "open"
    ind = db.get(m.Indicator, a.indicator_id)
    if ind and ind.status == "published":
        ind.status = "under_review"          # conservative: visible as under review while a person looks at it
    audit(db, request, None, "appeal.verified", "appeal", a.id)
    db.commit()
    return {"appeal_id": a.id, "status": a.status, "message": "Verified. The entry now shows as under review while a moderator looks at your request."}


@router.get("/v1/appeals/{appeal_id}", tags=["appeals"])
def appeal_status(appeal_id: str, db: Session = Depends(get_db), x_appeal_token: str | None = Header(default=None)):
    a = db.get(m.Appeal, appeal_id)
    if not a or not x_appeal_token or not same(a.token_hash, sha256(x_appeal_token)):
        raise HTTPException(404, "Request not found.")
    return {"appeal_id": a.id, "status": a.status, "outcome": a.outcome, "created_at": a.created_at, "resolved_at": a.resolved_at}


@router.get("/v1/moderation/appeals", tags=["moderation"])
def appeal_queue(db: Session = Depends(get_db), c: Ctx = Depends(ctx), mod: m.User = Depends(MOD)):
    rows = db.execute(select(m.Appeal).where(m.Appeal.status == "open").order_by(m.Appeal.created_at)).scalars().all()
    return {"appeals": [{"appeal_id": a.id, "indicator_id": a.indicator_id, "issue_type": a.issue_type, "statement": c.crypto.dec(a.statement_encrypted), "created_at": a.created_at} for a in rows]}


@router.post("/v1/moderation/appeals/{appeal_id}/resolve", tags=["moderation"])
def resolve_appeal(appeal_id: str, body: dict, request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx), mod: m.User = Depends(MOD)):
    a = db.get(m.Appeal, appeal_id)
    outcome, reason = body.get("outcome"), body.get("reason_code")
    if not a or a.status != "open":
        raise HTTPException(404, "No open appeal with that id.")
    if outcome not in ("upheld", "rejected") or not reason:
        raise HTTPException(422, "Give an outcome (upheld or rejected) and a reason code.")
    ind = db.get(m.Indicator, a.indicator_id)
    a.status, a.resolved_at = outcome, m.now_iso()
    a.outcome = "The entry was removed or corrected." if outcome == "upheld" else "The entry was reviewed and kept."
    if ind:
        if outcome == "upheld":
            ind.status = "withdrawn"
        else:
            ind.status = "published"
            recompute_indicator(db, c, ind.subject_id)
    db.add(m.ModerationAction(moderator_id=mod.id, target_type="appeal", target_id=a.id, action=outcome, reason_code=reason, notes=body.get("notes")))
    queue_notification(db, c, a.contact_kind, c.crypto.dec(a.requester_contact_encrypted), "appeal_outcome", {"appeal_id": a.id, "outcome": a.outcome}, "requester_initiated_appeal")
    audit(db, request, mod.id, f"appeal.{outcome}", "appeal", a.id, {"reason_code": reason})
    db.commit()
    return {"appeal_id": a.id, "status": a.status, "outcome": a.outcome}


# ------------------------------------------------------------------ business claims (no paid rating, no suppression)
@router.post("/v1/business-claims", status_code=201, tags=["business"])
def claim_business(body: BusinessClaimIn, request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx), user: m.User = Depends(require_user)):
    dom = nz.parse_url(body.domain).registered_domain if body.domain and nz.parse_url(body.domain) else None
    b = m.BusinessClaim(user_id=user.id, business_name=body.business_name.strip(), domain=dom, note_encrypted=c.crypto.enc(body.note) if body.note else None)
    db.add(b)
    db.flush()
    audit(db, request, user.id, "business_claim.create", "business_claim", b.id)
    db.commit()
    return {"claim_id": b.id, "status": b.status, "message": "A moderator will review your claim. A verified claim never removes or hides reports and is not a rating; it only confirms who may respond."}


@router.get("/v1/business-claims/mine", tags=["business"])
def my_claims(db: Session = Depends(get_db), user: m.User = Depends(require_user)):
    return {"claims": [{"claim_id": b.id, "business_name": b.business_name, "domain": b.domain, "status": b.status, "reason_code": b.reason_code}
                       for b in db.execute(select(m.BusinessClaim).where(m.BusinessClaim.user_id == user.id)).scalars()]}


@router.post("/v1/moderation/business-claims/{claim_id}/review", tags=["moderation"])
def review_claim(claim_id: str, body: dict, request: Request, db: Session = Depends(get_db), mod: m.User = Depends(MOD)):
    b = db.get(m.BusinessClaim, claim_id)
    if not b or body.get("status") not in ("approved", "rejected") or not body.get("reason_code"):
        raise HTTPException(422, "Give a status (approved or rejected) and a reason code.")
    b.status, b.reviewed_by, b.reason_code = body["status"], mod.id, body["reason_code"]
    db.add(m.ModerationAction(moderator_id=mod.id, target_type="business_claim", target_id=b.id, action=b.status, reason_code=b.reason_code))
    audit(db, request, mod.id, f"business_claim.{b.status}", "business_claim", b.id)
    db.commit()
    return {"claim_id": b.id, "status": b.status}


# ------------------------------------------------------------------ ML feedback, active learning & model governance
@router.post("/v1/feedback", status_code=201, tags=["feedback"])
def create_feedback(body: FeedbackIn, request: Request, c: Ctx = Depends(ctx)):
    throttle(request, c, "feedback", (10, 60))
    from ssi_rules.ml.feedback_queue import submit_feedback
    item = submit_feedback(
        sample_text=body.sample_text,
        predicted_label=body.predicted_label,
        predicted_category=body.predicted_category,
        user_feedback=body.user_feedback,
        user_comment=body.user_comment,
        check_id=body.check_id,
    )
    if body.user_feedback == "mistake_false_positive":
        try:
            from ssi_rules.ml.drift_monitor import DriftMonitor
            from ssi_rules.ml.model_registry import get_active_model
            DriftMonitor().log_feedback_outcome("false_positive", get_active_model().model_version)
        except Exception:
            pass
    return {"status": "received", "id": item.id, "active_learning_priority": item.active_learning_priority}


@router.get("/v1/feedback/review-queue", tags=["feedback"])
def get_review_queue(min_priority: float = 0.0, limit: int = 50, mod: m.User = Depends(MOD)):
    from ssi_rules.ml.feedback_queue import list_review_queue
    items = list_review_queue(min_priority=min_priority, limit=limit)
    return [it.to_dict() for it in items]


@router.post("/v1/feedback/adjudicate", tags=["feedback"])
def adjudicate_review_item(body: AdjudicationIn, mod: m.User = Depends(MOD)):
    from ssi_rules.ml.feedback_queue import ReviewStatus, adjudicate_feedback
    item = adjudicate_feedback(
        feedback_id=body.feedback_id,
        adjudicated_label=body.adjudicated_label,
        adjudicated_category=body.adjudicated_category,
        reviewer_notes=body.reviewer_notes,
        status=ReviewStatus(body.status),
    )
    if not item:
        raise HTTPException(status_code=404, detail="Feedback item not found")
    return item.to_dict()


@router.get("/v1/models/active", tags=["models"])
def get_active_model_info():
    from ssi_rules.ml.model_registry import get_active_model
    clf = get_active_model()
    return {
        "active_version": clf.model_version,
        "categories": clf.categories,
        "is_trained": clf.is_trained,
    }


@router.post("/v1/models/rollback", tags=["models"])
def rollback_active_model(mod: m.User = Depends(MOD)):
    from ssi_rules.ml.model_registry import rollback_model
    try:
        target = rollback_model()
        return {"status": "rolled_back", "active_version": target}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/v1/models/autonomous/status", tags=["autonomous-ml"])
def get_autonomous_status(mod: m.User = Depends(MOD)):
    """Operational status, dataset coverage, drift health, and active jobs."""
    from ssi_rules.ml.autonomous_orchestrator import AutonomousMLEngine
    engine = AutonomousMLEngine.get_instance()
    return engine.get_status_report().to_dict()


@router.post("/v1/models/autonomous/trigger-cycle", tags=["autonomous-ml"])
def trigger_autonomous_cycle(mod: m.User = Depends(MOD)):
    """Trigger an autonomous ingestion, evaluation, and training cycle."""
    from ssi_rules.ml.autonomous_orchestrator import AutonomousMLEngine
    engine = AutonomousMLEngine.get_instance()
    job = engine.run_cycle(trigger_reason="manual_admin_trigger", force=True)
    return job.to_dict()


@router.post("/v1/models/autonomous/pause", tags=["autonomous-ml"])
def pause_autonomous_engine(body: dict | None = None, mod: m.User = Depends(MOD)):
    """Pause automatic ingestion and training."""
    from ssi_rules.ml.autonomous_orchestrator import AutonomousMLEngine
    engine = AutonomousMLEngine.get_instance()
    reason = (body or {}).get("reason", "Administrator paused engine")
    engine.pause(reason=reason)
    return {"status": "paused", "reason": reason}


@router.post("/v1/models/autonomous/resume", tags=["autonomous-ml"])
def resume_autonomous_engine(mod: m.User = Depends(MOD)):
    """Resume automatic ingestion and training."""
    from ssi_rules.ml.autonomous_orchestrator import AutonomousMLEngine
    engine = AutonomousMLEngine.get_instance()
    engine.resume()
    return {"status": "resumed"}


@router.post("/v1/models/autonomous/rollback", tags=["autonomous-ml"])
def autonomous_emergency_rollback(mod: m.User = Depends(MOD)):
    """Emergency rollback of active model to previous champion."""
    from ssi_rules.ml.model_registry import rollback_model
    try:
        target = rollback_model()
        from ssi_rules.ml.autonomous_orchestrator import AutonomousMLEngine
        AutonomousMLEngine.get_instance().pause("Emergency rollback invoked by administrator")
        return {"status": "rolled_back", "active_version": target}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


