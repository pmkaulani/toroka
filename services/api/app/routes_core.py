from __future__ import annotations

import os
import re
import time
import uuid
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session
from ssi_connectors import channels, images, ocr
from ssi_rules import assess, load_registry, signals
from ssi_rules.fingerprint import minhash, script_hash
from ssi_rules.i18n import localize
from ssi_rules.normalize import mask_phone
from ssi_rules.recovery import triage
from ssi_rules.signals import mask_credential_values
from ssi_rules.vocabulary import POLICY_VERSION

from . import db as m
from . import pipeline
from .deps import Ctx, audit, client_key, ctx, current_user, expiry, get_db, require_role, require_user, throttle
from .schemas import (AuthIn, CheckRequest, CheckResponse, ChatRequest, ChatResponse, EvidenceOut, OpportunityIn, RecoveryIn, VerifiedEntityIn, URLInvestigateRequest)
from .ai_agent import investigate_with_ai, chat_with_ai, chat_with_ai_multilingual
from .public_search import find_public_identifiers, public_search, filter_public_search_results
from .investigation_intelligence import investigate_public_targets, build_verdict_explanation
from ssi_rules.category import detect_category
from .social_intelligence import investigate_social_targets
from .routes_community import upsert_subject
from .url_pipeline import (ThreatFeedManager, investigate_single_url, parse_platform_profile, URLInvestigationResult, is_verified_record_current, invalidate_url_cache)
from ssi_rules import normalize as nz
from .security import hash_password, new_token, same, sha256, verify_password

router = APIRouter()
REGISTRY = load_registry()
MIN_CHARS = 12


def _normalised_quote(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip().casefold()


def _is_non_evidential_link_excerpt(excerpt: str) -> bool:
    """A URL/handle by itself identifies the target; it is not a risk finding."""
    value = (excerpt or "").strip()
    value = re.sub(r"\[([^\]]+)\]\((?:https?://)[^)]+\)", r"\1", value)
    value = re.sub(r"[\[\]()<>{}\"'`,;]+", " ", value).strip()
    if re.fullmatch(r"(?i)(?:https?://|www\.)\S+", value):
        return True
    if re.fullmatch(r"(?i)(?:instagram|tiktok|facebook|x|twitter)\.com/\S+", value):
        return True
    # A bare username/account identifier is not a red flag unless the quote contains
    # an actual behaviour or claim worth analysing.
    if re.fullmatch(r"(?i)@?[a-z0-9_.-]{3,50}", value) and not re.search(
        r"(?i)\b(?:scam|fraud|pay|payment|pin|otp|password|deposit|fee|won|bonus|threat|fake|impersonat|stole|refund|hack)\b",
        value,
    ):
        return True
    return False


def _attach_grounded_ai_quotes(result: dict, ai_result: dict, evidence_text: str) -> int:
    """Attach only literal quotes grounded in current text/OCR; never persist free-form AI claims."""
    normalised_evidence = _normalised_quote(evidence_text)
    existing_quotes = {
        _normalised_quote(f.get("excerpt") or "")
        for f in result.get("findings", [])
        if isinstance(f, dict) and f.get("excerpt")
    }
    accepted = 0
    for finding in (ai_result.get("findings") or [])[:8]:
        if not isinstance(finding, dict):
            continue
        excerpt = str(finding.get("excerpt") or "").strip()[:220]
        quote = _normalised_quote(excerpt)
        if _is_non_evidential_link_excerpt(excerpt):
            continue
        if not quote or quote not in normalised_evidence or quote in existing_quotes:
            continue
        result.setdefault("findings", []).append({
            "code": f"AI_QUOTED_OBSERVATION_{accepted + 1}",
            "evidence_type": "ai_observation_needs_review",
            "plain_text": f'The submitted content includes: “{excerpt}”.',
            "why_it_matters": "This is a quotation from the submitted content, not proof of fraud by itself. Compare it with the sender's identity, the exact offer, and independent source evidence.",
            "excerpt": excerpt,
            "strength": "weak",
            "polarity": "unresolved",
            "needs_external_verification": True,
            "claim_status": "unresolved",
        })
        existing_quotes.add(quote)
        accepted += 1
        if accepted >= 3:
            break
    return accepted


def _is_new_investigation_input(message: str) -> bool:
    """True when a message looks like new evidence and must not inherit unrelated chat context."""
    msg = (message or "").strip()
    low = msg.lower()
    if not msg:
        return False
    if re.search(r"(?:https?://|www\.|(?<![\w.+-])@[a-z0-9_.]{3,35}\b|\b[a-z0-9-]+\.(?:com|co\.ke|org|net|xyz|shop|online|top|site|app)\b)", msg, re.I):
        return True
    if re.search(r"(?i)\b(?:look into|investigate|check this|check the|analyse|analyze|inspect|verify this|another shop|different shop|new message|new screenshot|check this message|check this sms|kagua|chunguza|angalia akaunti)\b", msg):
        return True
    if len(msg) >= 120:
        return True
    if len(msg) >= 55 and re.search(r"(?i)\b(?:freebets?|aviator|casino bonus|redemption|payout|clearance fee|otp|pin|loan fee|job offer|investment|urgent payment|M-PESA|mpesa|customs|parcel)\b", msg):
        return True
    return False


def _is_clear_follow_up(message: str) -> bool:
    """Avoid attaching a previous check to a new, unrelated message."""
    msg = (message or "").strip().lower()
    if not msg or len(msg) > 180:
        return False
    # New evidence, URLs, handles, phone numbers, or shop inquiries start a new investigation.
    if re.search(r"(?:https?://|www\.|(?<![\w.+-])@[a-z0-9_.]{2,35}\b|(?:\+?254|0)[17]\d{8}|\b(?:till|paybill)\s*\d{5,7}|instagram:|tiktok:|facebook:|x:|whatsapp:)", msg, re.I):
        return False
    if re.search(r"\b(?:look into|investigate|check|verify|audit|analyse|analyze|inspect|shop|seller|store|duka|muuzaji|menswear|clothes|clothing|brand|product|order|buy|new message|another shop|different shop|another link|kagua|chunguza|angalia akaunti)\b", msg, re.I):
        return False
    patterns = (
        r"^(?:why|how come|explain|tell me more|more details|what did you find|what did you check|what does that mean|what should i do|what next|is it safe|is this safe|could this be|i already paid|i paid|i clicked|i shared|i sent money|yes|no|and if|what about that|can you explain|kwa nini|mbona|nielezee|niambie zaidi|nifanye nini|nimeshalipa|nimelipa|nilituma pesa|nilibonyeza|ndiyo|hapana)\b"
    )
    return bool(re.search(patterns, msg, re.I)) or msg in {"this one", "that one", "the second one", "same one", "hii", "hiyo"}


# ---------------------------------------------------------------- health
@router.get("/v1/health", tags=["ops"])
def health():
    return {"status": "ok"}


@router.get("/v1/ready", tags=["ops"])
def ready(request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx)):
    db.execute(select(m.Opportunity.id).limit(1))
    return {"status": "ready", "policy_version": POLICY_VERSION, "registry_statements": len(REGISTRY.statements),
            "connectors": {"link_reputation": [type(p).__name__ for p in c.deps.reputation_providers] or "not configured",
                           "redirect_follow": bool(c.deps.follow_redirects), "domain_age": bool(c.deps.domain_age),
                           "geocoder": bool(c.deps.geocoder), "ocr": "tesseract" if ocr.available_languages() else "unavailable",
                           "whatsapp": "whatsapp" in c.senders, "sms": "sms" in c.senders}}


# ---------------------------------------------------------------- diagnostics & URL investigation
@router.get("/v1/system/diagnostics", tags=["ops"])
def system_diagnostics(
    request: Request,
    db: Session = Depends(get_db),
    c: Ctx = Depends(ctx),
    user: m.User | None = Depends(current_user),
    x_admin_key: str | None = Header(default=None),
):
    """Authenticated system diagnostic endpoint reporting verified API connectivity and threat feeds."""
    # Diagnostics expose internal topology, provider status, and database counts.
    # Never bypass authorization in dev: tunnels can make a dev server public.
    # A dedicated key may be used by a trusted deployment monitor, but must not
    # reuse HMAC_KEY and is compared in constant time.
    is_authorized = bool(user and user.role in ("moderator", "admin"))
    if not is_authorized and x_admin_key and c.settings.diagnostics_api_key:
        is_authorized = same(x_admin_key, c.settings.diagnostics_api_key)

    if not is_authorized:
        if user is not None:
            raise HTTPException(403, "Moderator or admin privileges are required for system diagnostics.")
        raise HTTPException(401, "Authentication required for system diagnostics.")

    diag: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": c.settings.env,
        "policy_version": POLICY_VERSION,
    }

    # 1. Gemini & Tavily API diagnostics in parallel
    has_gemini = bool(c.settings.gemini_api_key)
    gemini_diag: dict[str, Any] = {
        "configured": has_gemini,
        "active_model": c.settings.ai_model,
        "ready": False,
        "ping_status": "not_configured" if not has_gemini else "unknown",
    }
    has_tavily = bool(c.settings.tavily_api_key)
    tavily_diag: dict[str, Any] = {
        "configured": has_tavily,
        "ready": False,
        "ping_status": "not_configured" if not has_tavily else "unknown",
    }
    has_webrisk = bool(c.settings.webrisk_api_key)
    webrisk_diag: dict[str, Any] = {
        "configured": has_webrisk,
        "status": "configured" if has_webrisk else "not_configured",
        "ready": False,
        "ping_status": "not_configured" if not has_webrisk else "unknown",
        "detail": "Licensed commercial URI lookup" if has_webrisk else "WEBRISK_API_KEY is not configured",
    }

    def _ping_gemini():
        if not has_gemini:
            return
        t0 = time.monotonic()
        try:
            url = "https://generativelanguage.googleapis.com/v1beta/models"
            with httpx.Client(timeout=2.5) as client:
                r = client.get(url, headers={"x-goog-api-key": c.settings.gemini_api_key})
                latency = round((time.monotonic() - t0) * 1000, 1)
                gemini_diag["http_status"] = r.status_code
                gemini_diag["latency_ms"] = latency
                if r.status_code == 200:
                    gemini_diag["ready"] = True
                    gemini_diag["ping_status"] = "ok"
                else:
                    gemini_diag["ping_status"] = f"http_error_{r.status_code}"
        except Exception as e:
            gemini_diag["ping_status"] = "connection_error"
            gemini_diag["error"] = type(e).__name__

    def _ping_tavily():
        if not has_tavily:
            return
        t0 = time.monotonic()
        try:
            with httpx.Client(timeout=2.5) as client:
                r = client.post("https://api.tavily.com/search", json={"api_key": c.settings.tavily_api_key, "query": "Kenya safety", "max_results": 1})
                latency = round((time.monotonic() - t0) * 1000, 1)
                tavily_diag["http_status"] = r.status_code
                tavily_diag["latency_ms"] = latency
                if r.status_code == 200:
                    tavily_diag["ready"] = True
                    tavily_diag["ping_status"] = "ok"
                else:
                    tavily_diag["ping_status"] = f"http_error_{r.status_code}"
        except Exception as e:
            tavily_diag["ping_status"] = "connection_error"
            tavily_diag["error"] = type(e).__name__

    def _ping_webrisk():
        if not has_webrisk:
            return
        t0 = time.monotonic()
        try:
            url = "https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE&uri=https%3A%2F%2Fexample.com"
            with httpx.Client(timeout=2.5) as client:
                r = client.get(url, headers={"x-goog-api-key": c.settings.webrisk_api_key})
                latency = round((time.monotonic() - t0) * 1000, 1)
                webrisk_diag["http_status"] = r.status_code
                webrisk_diag["latency_ms"] = latency
                if r.status_code == 200:
                    webrisk_diag["ready"] = True
                    webrisk_diag["ping_status"] = "ok"
                    webrisk_diag["service"] = "Google Web Risk"
                else:
                    # Check if free Safe Browsing API v4 is active on this key (no billing required)
                    sb_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
                    sb_test = {
                        "client": {"clientId": "toroka-test", "clientVersion": "1.0"},
                        "threatInfo": {
                            "threatTypes": ["MALWARE"],
                            "platformTypes": ["ANY_PLATFORM"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [{"url": "https://example.com"}],
                        },
                    }
                    r_sb = client.post(sb_url, json=sb_test, headers={"x-goog-api-key": c.settings.webrisk_api_key})
                    if r_sb.status_code == 200:
                        webrisk_diag["ready"] = True
                        webrisk_diag["ping_status"] = "ok"
                        webrisk_diag["service"] = "Google Safe Browsing v4 (Free)"
                        webrisk_diag["http_status"] = 200
                        webrisk_diag["detail"] = "Free Google Safe Browsing API active (no billing required)"
                    else:
                        webrisk_diag["ping_status"] = f"http_error_{r.status_code}"
                        try:
                            err_body = r.json()
                            webrisk_diag["error_message"] = err_body.get("error", {}).get("message", r.text[:120])
                        except Exception:
                            webrisk_diag["error_message"] = r.text[:120]
        except Exception as e:
            webrisk_diag["ping_status"] = "connection_error"
            webrisk_diag["error"] = type(e).__name__

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=3) as executor:
        f_gem = executor.submit(_ping_gemini)
        f_tav = executor.submit(_ping_tavily)
        f_wr = executor.submit(_ping_webrisk)
        f_gem.result()
        f_tav.result()
        f_wr.result()

    diag["gemini"] = gemini_diag
    diag["tavily"] = tavily_diag
    diag["webrisk"] = webrisk_diag

    # 4. Threat Feeds
    tf = ThreatFeedManager.get_instance()
    diag["threat_feeds"] = {
        "total_malicious_urls": len(tf.malicious_urls),
        "total_malicious_domains": len(tf.malicious_domains),
        "feeds": {k: asdict(v) for k, v in tf.statuses.items()},
    }

    # 5. ML Engine & Model Registry
    try:
        from ssi_rules.ml.autonomous_config import AutonomousMLConfig
        from ssi_rules.ml.model_registry import get_active_model_pointer_path
        ptr_file = get_active_model_pointer_path()
        active_ver = "none"
        shadow_ver = "none"
        if os.path.exists(ptr_file):
            import json
            with open(ptr_file, "r", encoding="utf-8") as f:
                p_data = json.load(f)
                active_ver = p_data.get("active_version", "none")
                shadow_ver = p_data.get("shadow_version", "none")
        cfg = AutonomousMLConfig()
        diag["ml_engine"] = {
            "status": "ready",
            "champion_version": active_ver,
            "shadow_mode_enabled": cfg.shadow_mode_enabled,
            "shadow_candidate_version": shadow_ver,
            "min_category_eval_support": cfg.min_category_eval_support,
        }
    except Exception as e:
        diag["ml_engine"] = {"status": "error", "detail": str(e)}

    # 6. Database Counts
    try:
        ind_count = db.execute(select(m.Indicator.id)).scalars().all()
        ver_count = db.execute(select(m.VerifiedRecord.id)).scalars().all()
        opp_count = db.execute(select(m.Opportunity.id)).scalars().all()
        rep_count = db.execute(select(m.Report.id)).scalars().all()
        diag["database"] = {
            "status": "connected",
            "indicators_count": len(ind_count),
            "verified_records_count": len(ver_count),
            "opportunities_count": len(opp_count),
            "reports_count": len(rep_count),
        }
    except Exception as e:
        diag["database"] = {"status": "error", "detail": str(e)}

    return diag


@router.post("/v1/investigate/url", tags=["checks"])
def investigate_url_endpoint(
    body: URLInvestigateRequest,
    request: Request,
    db: Session = Depends(get_db),
    c: Ctx = Depends(ctx),
    user=Depends(current_user),
):
    """Direct URL investigation endpoint executing the 8-step Toroka security pipeline."""
    throttle(request, c, "checks", c.settings.rl_checks_user if user else c.settings.rl_checks, user.id if user else None)
    result = investigate_single_url(
        body.url,
        db,
        c.crypto,
        c.settings,
        user_context=body.question or "",
        language=body.language,
    )
    return asdict(result)


# ---------------------------------------------------------------- auth
@router.post("/v1/auth/register", status_code=201, tags=["accounts"])
def register(body: AuthIn, request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx)):
    throttle(request, c, "auth", c.settings.rl_auth)
    email = body.email.strip().lower()
    h = c.crypto.lookup("email", email)
    if db.execute(select(m.User).where(m.User.email_hmac == h)).scalar_one_or_none():
        raise HTTPException(409, "An account with this email already exists.")
    u = m.User(email_hmac=h, email_encrypted=c.crypto.enc(email), password_hash=hash_password(body.password))
    db.add(u)
    db.flush()
    audit(db, request, u.id, "user.register", "user", u.id)
    token = _login(db, u)
    db.commit()
    return {"user_id": u.id, "role": u.role, "token": token}


def _login(db: Session, u: m.User) -> str:
    t = new_token()
    db.add(m.SessionToken(token_hash=sha256(t), user_id=u.id, expires_at=expiry(30)))
    return t


@router.post("/v1/auth/login", tags=["accounts"])
def login(body: AuthIn, request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx)):
    throttle(request, c, "auth", c.settings.rl_auth)
    u = db.execute(select(m.User).where(m.User.email_hmac == c.crypto.lookup("email", body.email.strip().lower()))).scalar_one_or_none()
    if not u or u.status != "active" or not verify_password(body.password, u.password_hash):
        raise HTTPException(401, "Email or password is not right.")
    token = _login(db, u)
    audit(db, request, u.id, "user.login", "user", u.id)
    db.commit()
    return {"user_id": u.id, "role": u.role, "token": token}


@router.post("/v1/auth/logout", tags=["accounts"])
def logout(request: Request, db: Session = Depends(get_db), authorization: str | None = Header(default=None), u=Depends(require_user)):
    s = db.get(m.SessionToken, sha256(authorization[7:].strip()))
    if s:
        db.delete(s)
        db.commit()
    return {"status": "signed_out"}


# ---------------------------------------------------------------- checks
def _owner_check(db, c: Ctx, request, check_id: str, user, token: str | None, allow_moderator: bool = False) -> m.Check:
    chk = db.get(m.Check, check_id)
    if chk and chk.expires_at < m.now_iso():
        chk = None
    ok = bool(chk) and ((user and chk.user_id == user.id) or (token and chk.guest_token_hash and same(chk.guest_token_hash, sha256(token))))
    if chk and not ok and allow_moderator and user and user.role in ("moderator", "admin"):
        audit(db, request, user.id, "check.moderator_read", "check", chk.id)
        db.commit()
        ok = True
    if not chk or not ok:
        raise HTTPException(404, "Check not found, expired, or you do not have access to it.")   # same answer either way
    return chk


def _evidence_out(db: Session, c: Ctx, chk: m.Check, with_text: bool = True) -> list[EvidenceOut]:
    out = []
    for ev in db.execute(select(m.EvidenceFile).where(m.EvidenceFile.check_id == chk.id).order_by(m.EvidenceFile.created_at)).scalars():
        ex = db.execute(select(m.EvidenceExtraction).where(m.EvidenceExtraction.evidence_id == ev.id)).scalar_one_or_none()
        txt = mask_credential_values(c.crypto.dec(ex.extracted_text_encrypted))[0] if (ex and with_text) else None
        out.append(EvidenceOut(evidence_id=ev.id, mime_type=ev.mime_type, size_bytes=ev.size_bytes, width=ev.width, height=ev.height,
                               redaction_state=ev.redaction_state, ocr_status=ex.status if ex else "not_run", ocr_confidence=ex.confidence if ex else None,
                               ocr_note=ex.note if ex else "", extracted_text=txt, retention_until=ev.retention_until))
    return out


def _render(db, c: Ctx, request, chk: m.Check, lang: str, guest_token: str | None = None) -> CheckResponse:
    a = chk.result_json
    if a and lang != "en":
        a = localize(a, lang)
    elif a:
        a = localize(a, "en")
    prompt = "Please add the full message, a link, or a screenshot so we have enough to check." if chk.status == "needs_more_information" else None
    return CheckResponse(request_id=request.state.request_id, check_id=chk.id, status=chk.status, created_at=chk.created_at, expires_at=chk.expires_at,
                         steps=chk.steps_json or [], prompt=prompt, assessment=a, evidence=_evidence_out(db, c, chk), guest_token=guest_token)


def run_check(db: Session, c: Ctx, chk: m.Check) -> None:
    """(Re)assess a check from its stored text plus any extracted screenshot text. Synchronous in this build."""
    text = c.crypto.dec(chk.input_encrypted) if chk.input_encrypted else ""
    steps = [{"name": "Reading text", "status": "done"}]
    pieces = {"text": text}
    extra_cov, leads_in, raw_images = [], [], []
    for ev in db.execute(select(m.EvidenceFile).where(m.EvidenceFile.check_id == chk.id).order_by(m.EvidenceFile.created_at)).scalars():
        p = os.path.join(c.settings.storage_dir, ev.object_key)
        if os.path.exists(p):
            try:
                with open(p, "rb") as fh:
                    raw_images.append(c.crypto.dec_bytes(fh.read()))
            except Exception:
                pass
        ex = db.execute(select(m.EvidenceExtraction).where(m.EvidenceExtraction.evidence_id == ev.id)).scalar_one_or_none()
        label = f"screenshot-{len(pieces)}"
        t = c.crypto.dec(ex.extracted_text_encrypted) if ex else ""
        if ex and ex.status == "checked" and t.strip():
            pieces[label] = t
        conf = f" Mean confidence {ex.confidence}%." if ex and ex.confidence is not None else ""
        extra_cov.append({"id": f"image_text_{len(pieces)}", "name": "Text read from a screenshot", "status": ex.status if ex else "not_checked",
                          "detail": ((ex.note + " ") if ex and ex.note else "") + ("Text was extracted automatically and may contain mistakes." + conf if ex and ex.status == "checked" else "The text could not be read.")})
        steps.append({"name": "Reading a screenshot", "status": "done" if ex and ex.status == "checked" else "failed"})
        leads_in.append((ev.dhash, ev.check_id, len(t.strip())))
    combined = "\n\n".join(v for v in pieces.values() if v)
    obs = pipeline.gather(db, c.crypto, c.deps, combined, steps)
    obs.extra_coverage = extra_cov
    obs.extra_findings = pipeline.image_leads(db, chk.id, leads_in)
    a = assess(combined, registry=REGISTRY, observations=obs, pieces=pieces if len(pieces) > 1 else None, category_hint=chk.category)
    steps.append({"name": "Combining the evidence", "status": "done"})
    pipeline.persist_assessment(db, chk, a, steps)
    res_dict = pipeline.jsonable(a)

    # Public-web and social intelligence is coordinated after the URL pipeline so its
    # already-filtered Tavily leads can be reused for extraction instead of searching twice.
    public_sources: list[dict] = []
    public_targets = find_public_identifiers(combined)
    url_inv = None

    # Integrated URL Investigation Pipeline (threat feeds, SSRF fetch, impersonation, verified registry)
    extracted_urls = nz.extract_urls(combined)
    extracted_profile = parse_platform_profile(combined)
    if extracted_urls or extracted_profile.is_profile:
        primary_link = extracted_profile.canonical_url or (extracted_urls[0].original if extracted_urls else combined.strip())
        try:
            url_inv = investigate_single_url(primary_link, db, c.crypto, c.settings, user_context=combined, language="en")
            existing_f_codes = {f.get("code") for f in res_dict.get("findings", [])}
            for f in url_inv.findings:
                if f.code not in existing_f_codes:
                    res_dict.setdefault("findings", []).append({
                        "code": f.code,
                        "plain_text": f.plain_text,
                        "why_it_matters": f.why_it_matters,
                        "strength": f.strength,
                        "evidence_type": f.evidence_type,
                        "source_id": f.source_url,
                        "needs_external_verification": False,
                        "polarity": "positive" if url_inv.risk_band == "verified_official" else "risk",
                    })
            for s in url_inv.sources:
                res_dict.setdefault("sources", []).append({
                    "id": s.id,
                    "statement": s.statement,
                    "source_url": s.source_url,
                    "reviewer": s.reviewer,
                    "last_verified_at": s.last_verified_at or datetime.now(timezone.utc).isoformat(),
                    "review_due": None,
                })
            if extracted_profile.is_profile:
                # Replace generic coverage with the specialized social shop checklist
                res_dict["coverage"] = [
                    {
                        "id": cov.id,
                        "name": cov.name,
                        "status": cov.status,
                        "detail": cov.detail,
                        "blocking": False,
                        "source_url": cov.source_url,
                        "provider": cov.provider,
                        "query": cov.query,
                        "results_retrieved": cov.results_retrieved,
                        "results_relevant": cov.results_relevant,
                    }
                    for cov in url_inv.coverage
                ]
                res_dict["label"] = url_inv.risk_band
                res_dict["summary"] = url_inv.summary
                chk.risk_band = url_inv.risk_band
            else:
                # Merge coverage without duplicates or contradictory statuses (Spec 7)
                existing_cov_ids = {c.get("id"): idx for idx, c in enumerate(res_dict.get("coverage", []))}
                # If tavily_search is in url_inv, remove any earlier public_web_search to prevent conflicting statuses
                if any(c.id == "tavily_search" for c in url_inv.coverage) and "public_web_search" in existing_cov_ids:
                    res_dict["coverage"] = [c for c in res_dict["coverage"] if c.get("id") != "public_web_search"]
                    existing_cov_ids = {c.get("id"): idx for idx, c in enumerate(res_dict.get("coverage", []))}

                for cov in url_inv.coverage:
                    if cov.id not in existing_cov_ids:
                        res_dict.setdefault("coverage", []).append({
                            "id": cov.id,
                            "name": cov.name,
                            "status": cov.status,
                            "detail": cov.detail,
                            "blocking": False,
                        })

                if url_inv.risk_band == "high_risk":
                    res_dict["label"] = "high_risk"
                    chk.risk_band = "high_risk"
                    res_dict["summary"] = url_inv.summary
                    if url_inv.next_steps:
                        res_dict["next_steps"] = [{"text": s} for s in url_inv.next_steps]
                elif url_inv.risk_band == "verified_official" and chk.risk_band not in ("high_risk", "suspicious_verify_first"):
                    if not res_dict.get("label") or res_dict.get("label") in ("inconclusive", "no_known_threats_found"):
                        res_dict["label"] = "verified_official"
                        chk.risk_band = "verified_official"
                    if not res_dict.get("summary"):
                        res_dict["summary"] = url_inv.summary

            # Remove unrelated e-commerce boilerplate for non-shopping categories (Spec 6 & 8)
            used_cat = (res_dict.get("category") or {}).get("used", "")
            if used_cat in ("job", "recruitment_overseas", "grant", "government_grants", "prize", "prize_winnings", "payment", "mpesa_payment"):
                ecommerce_keywords = ("delivery terms", "return policy", "order confirmations", "goods are really delivered", "independent customer reviews for this seller", "buyer protection")
                res_dict["next_steps"] = [
                    step for step in res_dict.get("next_steps", [])
                    if not any(kw in step.get("text", "").lower() for kw in ecommerce_keywords)
                ]
            if "safaricom" in combined.lower() or "safaricom" in primary_link.lower():
                safaricom_333_advice = "Forward suspicious SMS messages to Safaricom's free fraud reporting shortcode: 333."
                if not any("333" in s.get("text", "") for s in res_dict.get("next_steps", [])):
                    res_dict["next_steps"].append({"text": safaricom_333_advice})
            for lim in url_inv.limitations:
                if lim not in res_dict.get("limitations", []):
                    res_dict.setdefault("limitations", []).append(lim)
            if url_inv.steps_taken:
                chk.steps_json = (chk.steps_json or []) + url_inv.steps_taken
        except Exception as e:
            logger.warning("URL investigation during check failed: %s", e)

    # Multi-provider investigation: web discovery, social mentions and source extraction.
    # Only public identifiers are sent to external services; the submitted message and
    # screenshot contents remain local to Toroka's assessment engine.
    if public_targets:
        try:
            category_guess = detect_category(combined)
            social_result = investigate_social_targets(public_targets, c.settings)
            search_seed_results = []
            if url_inv is not None:
                for source in (url_inv.sources or []):
                    reviewer = str(getattr(source, "reviewer", "") or "")
                    if "Tavily Web Search" not in reviewer:
                        continue
                    source_url = str(getattr(source, "source_url", "") or "")
                    statement = str(getattr(source, "statement", "") or "")
                    if source_url:
                        search_seed_results.append({
                            "url": source_url,
                            "title": statement.split(":", 1)[0][:180] or "Public search result",
                            "snippet": statement[:1200],
                        })
            intelligence_result = investigate_public_targets(
                public_targets,
                category=category_guess.suggested,
                submitted_text=combined,
                settings=c.settings,
                skip_tavily=url_inv is not None,
                search_seed_results=search_seed_results,
                social_result=social_result,
            )

            evidence_by_id = {str(x.get("evidence_id")): x for x in intelligence_result.get("evidence", []) if isinstance(x, dict)}
            source_type_map = {
                "public_web_search_lead": "public_search_lead",
                "inspected_public_web_page": "inspected_public_web_page",
                "social_public_search_lead": "social_intelligence_lead",
                "social_public_profile_observation": "social_profile_observation",
            }
            for evidence in intelligence_result.get("evidence", [])[:30]:
                if not isinstance(evidence, dict):
                    continue
                evidence_id = str(evidence.get("evidence_id") or "")
                public_type = source_type_map.get(str(evidence.get("source_type") or ""), str(evidence.get("source_type") or "public_search_lead"))
                public_sources.append({**evidence, "source_type": public_type})
                source_url = str(evidence.get("url") or "")
                if source_url:
                    res_dict.setdefault("sources", []).append({
                        "id": f"intelligence-{evidence_id or len(res_dict.get('sources', [])) + 1}",
                        "statement": (
                            f"{evidence.get('provider') or 'Public source'}: {evidence.get('title') or 'Public evidence'}. "
                            f"{str(evidence.get('snippet') or '')[:700]} "
                            "This is public source material; allegations and claims are not automatically verified."
                        ),
                        "source_url": source_url,
                        "last_verified_at": evidence.get("collected_at") or evidence.get("checked_at") or datetime.now(timezone.utc).isoformat(),
                        "review_due": None,
                        "reviewer": str(evidence.get("provider") or "Public intelligence provider"),
                    })

            existing_finding_codes = {str(f.get("code")) for f in res_dict.get("findings", []) if isinstance(f, dict)}
            for flag in intelligence_result.get("red_flags", []):
                if not isinstance(flag, dict) or str(flag.get("code") or "") in existing_finding_codes:
                    continue
                source_refs = [evidence_by_id.get(str(eid), {}).get("url") for eid in flag.get("source_ids", [])]
                source_ref = next((x for x in source_refs if x), None)
                severity = str(flag.get("severity") or "weak").lower()
                strength = "strong" if severity in {"critical", "high"} else "supporting" if severity == "supporting" else "weak"
                res_dict.setdefault("findings", []).append({
                    "code": str(flag.get("code") or "PUBLIC_INTELLIGENCE_WARNING"),
                    "plain_text": str(flag.get("statement") or "A public-source warning requires review."),
                    "why_it_matters": str(flag.get("why_it_matters") or "Public allegations are leads and require independent corroboration."),
                    "strength": strength,
                    "evidence_type": "unresolved_claim",
                    "source_id": source_ref,
                    "needs_external_verification": True,
                    "polarity": "risk",
                    "claim_status": flag.get("evidence_status") or "unverified",
                })
                existing_finding_codes.add(str(flag.get("code") or "PUBLIC_INTELLIGENCE_WARNING"))

            # Provider status is first-class coverage. A missing key or failed endpoint
            # can never be represented as a clean result.
            provider_statuses = [x for x in intelligence_result.get("providers", []) if isinstance(x, dict)]
            tavily_search = [x for x in provider_statuses if str(x.get("provider", "")).casefold() == "tavily" and x.get("operation") == "search"]
            if tavily_search and not any(x.get("id") in {"public_web_search", "tavily_search"} for x in res_dict.get("coverage", [])):
                raw_count = sum(int(x.get("results_retrieved") or 0) for x in tavily_search)
                relevant_count = sum(int(x.get("results_relevant") or 0) for x in tavily_search)
                statuses = {str(x.get("status") or "unknown") for x in tavily_search}
                if "checked" in statuses:
                    coverage_status = "checked"
                elif statuses and statuses <= {"checked_no_match", "not_found"}:
                    coverage_status = "checked_no_match"
                elif "not_configured" in statuses or "not_checked" in statuses:
                    coverage_status = "not_configured"
                else:
                    coverage_status = "failed"
                details = " ".join(str(x.get("detail") or "") for x in tavily_search if x.get("detail"))[:1200]
                res_dict.setdefault("coverage", []).append({
                    "id": "public_web_search", "name": "Public web search", "status": coverage_status,
                    "detail": details or "Tavily search status was not supplied.", "blocking": False,
                    "results_retrieved": raw_count, "results_relevant": relevant_count,
                })

            existing_coverage_ids = {str(x.get("id")) for x in res_dict.get("coverage", []) if isinstance(x, dict)}
            for provider in provider_statuses:
                name = str(provider.get("provider") or "Provider")
                operation = str(provider.get("operation") or "check")
                if name.casefold() == "tavily" and operation == "search":
                    continue  # represented by the single public_web_search row above
                coverage_id = "intel_" + re.sub(r"[^a-z0-9]+", "_", (name + "_" + operation).casefold()).strip("_")[:54]
                if coverage_id in existing_coverage_ids:
                    continue
                res_dict.setdefault("coverage", []).append({
                    "id": coverage_id,
                    "name": f"{name} — {operation.replace('_', ' ')}",
                    "status": str(provider.get("status") or "failed"),
                    "detail": str(provider.get("detail") or "No provider detail available.")[:800],
                    "blocking": False,
                    "results_retrieved": int(provider.get("results_retrieved") or 0),
                    "results_relevant": int(provider.get("results_relevant") or 0),
                })
                existing_coverage_ids.add(coverage_id)

            combined_flags = [x for x in (intelligence_result.get("red_flags") or []) if isinstance(x, dict)]
            if url_inv is not None:
                for finding in (url_inv.findings or []):
                    code = str(getattr(finding, "code", "") or "")
                    plain = str(getattr(finding, "plain_text", "") or "")
                    why = str(getattr(finding, "why_it_matters", "") or "")
                    strength = str(getattr(finding, "strength", "weak") or "weak")
                    evidence_type = str(getattr(finding, "evidence_type", "") or "")
                    source_url = str(getattr(finding, "source_url", "") or "")
                    combined_text = f"{plain} {why}".casefold()
                    if code == "RECRUITMENT_DOMAIN_PHISHING_HISTORY":
                        flag_code = "REPORTED_JOB_CREDENTIAL_HARVESTING" if ("gmail password" in combined_text or "email password" in combined_text) else "REPORTED_RECRUITMENT_SCAM_ASSOCIATION"
                        combined_flags.append({
                            "code": flag_code, "severity": "high" if strength == "strong" else "supporting",
                            "evidence_status": "reported_in_target_matched_public_sources", "statement": plain,
                            "why_it_matters": why + " The historical report is associated with the same domain; the submitted URL path may differ.",
                            "source_ids": [source_url] if source_url else [],
                        })
                    elif code:
                        combined_flags.append({
                            "code": code,
                            "severity": "high" if strength == "strong" else "supporting" if strength == "supporting" else "weak",
                            "evidence_status": "directly_observed_on_target" if evidence_type in {"observed_data", "page_content"} else "verification_gap_in_submission",
                            "statement": plain, "why_it_matters": why, "source_ids": [source_url] if source_url else [],
                        })
                for source in (url_inv.sources or []):
                    reviewer = str(getattr(source, "reviewer", "") or "")
                    statement = str(getattr(source, "statement", "") or "")
                    source_url = str(getattr(source, "source_url", "") or "")
                    if not source_url:
                        continue
                    if "Tavily Web Search" in reviewer:
                        source_type, title = "public_search_lead", "Search lead; not independently verified"
                    elif "Documented Threat Record" in reviewer:
                        source_type, title = "documented_threat_report", "Documented historical threat report; confirm date and exact scope"
                    elif "Toroka Community Review" in reviewer:
                        source_type, title = "toroka_community_record", "Published Toroka community indicator; review moderation basis"
                    elif "MalwareTips" in reviewer or "scanner" in reviewer.casefold() or "threat intel" in reviewer.casefold():
                        source_type, title = "security_reputation_report", "External security reputation report; supporting signal, not proof by itself"
                    else:
                        source_type, title = "url_investigation_source", reviewer or "URL investigation source"
                    public_sources.append({
                        "source_type": source_type, "provider": reviewer or "URL investigation",
                        "title": title, "url": source_url, "snippet": statement[:1200],
                        "published_date": str(getattr(source, "last_verified_at", "") or "")[:80],
                    })

            investigation_advice = list(intelligence_result.get("advice") or [])
            if any(x.get("code") == "REPORTED_JOB_CREDENTIAL_HARVESTING" for x in combined_flags):
                investigation_advice = [
                    "Do not use this application link or enter an email password, OTP or account recovery code.",
                    "If you already entered your email password, change it through the email provider's official website, review signed-in devices and sessions, remove unfamiliar app access and enable two-step verification.",
                    "Ask for the employer's legal name, exact vacancy, written job description, salary, work location and recruiter details.",
                    "Verify the recruiter through Kenya's official National Employment Authority channels and confirm the relevant overseas work-authorisation route.",
                ]
            if url_inv is not None:
                investigation_advice.extend(url_inv.next_steps or [])
                for coverage_item in (url_inv.coverage or []):
                    provider_statuses.append({
                        "provider": getattr(coverage_item, "provider", None) or getattr(coverage_item, "name", "URL investigation"),
                        "operation": getattr(coverage_item, "id", "check"),
                        "status": getattr(coverage_item, "status", "unknown"),
                        "detail": getattr(coverage_item, "detail", ""),
                        "results_retrieved": getattr(coverage_item, "results_retrieved", 0),
                        "results_relevant": getattr(coverage_item, "results_relevant", 0),
                    })
            investigation_limitations = list(intelligence_result.get("limitations") or [])
            if url_inv is not None:
                investigation_limitations.extend(url_inv.limitations or [])
            # Add URL-pipeline evidence to the explanation index as well. Some findings
            # refer to source URLs rather than intelligence evidence IDs.
            explanation_evidence = list(intelligence_result.get("evidence", [])[:30])
            for source in public_sources:
                if not isinstance(source, dict) or not source.get("url"):
                    continue
                if any(x.get("url") == source.get("url") for x in explanation_evidence if isinstance(x, dict)):
                    continue
                explanation_evidence.append({
                    "evidence_id": "url-" + sha256(str(source.get("url")))[:16],
                    "provider": source.get("provider") or "URL investigation",
                    "source_type": source.get("source_type") or "url_investigation_source",
                    "title": source.get("title") or source.get("provider") or "URL investigation source",
                    "snippet": source.get("snippet") or "",
                    "url": source.get("url"),
                    "claim_status": "source_record_not_a_user_allegation",
                    "identity_match": "matched_by_url_investigation_pipeline",
                    "published_at": source.get("published_date") or "",
                })
            verdict_explanation = build_verdict_explanation(
                str(res_dict.get("label") or chk.risk_band or "inconclusive"),
                str(res_dict.get("summary") or ""),
                list({str(x.get("code")): x for x in combined_flags}.values()),
                explanation_evidence,
                investigation_limitations,
                res_dict.get("sources", []),
            )
            res_dict["investigation_intelligence"] = {
                "category": intelligence_result.get("category"),
                "targets": intelligence_result.get("targets", []),
                "red_flags": list({str(x.get("code")): x for x in combined_flags}.values()),
                "advice": list(dict.fromkeys(investigation_advice))[:10],
                "limitations": list(dict.fromkeys(investigation_limitations))[:10],
                "providers": provider_statuses,
                "evidence": intelligence_result.get("evidence", [])[:30],
                "evidence_explanation": verdict_explanation,
                "shop_discovery": intelligence_result.get("shop_discovery"),
                "summary": intelligence_result.get("summary", ""),
                "checked_at": intelligence_result.get("checked_at"),
            }
            for advice_item in investigation_advice:
                if advice_item and not any(str(advice_item).casefold() in str(x.get("text", "")).casefold() for x in res_dict.get("next_steps", []) if isinstance(x, dict)):
                    res_dict.setdefault("next_steps", []).append({"text": str(advice_item)})
            for limitation in investigation_limitations:
                if limitation and limitation not in res_dict.get("limitations", []):
                    res_dict.setdefault("limitations", []).append(str(limitation))

            # Give the optional model the same evidence bundle, but only accept literal
            # quotes grounded in user/OCR text. Model-generated verdicts remain unused.
            if c.settings.gemini_api_key or c.settings.openai_api_key:
                ai_res = investigate_with_ai(combined, images=raw_images if raw_images else None,
                                             settings=c.settings, public_sources=public_sources)
                if ai_res:
                    _attach_grounded_ai_quotes(res_dict, ai_res, combined)
        except Exception as exc:
            logger.warning("Multi-provider investigation failed safely: %s", type(exc).__name__)
            res_dict.setdefault("coverage", []).append({
                "id": "multi_provider_intelligence", "name": "Multi-provider public investigation",
                "status": "failed", "detail": "The additional intelligence checks could not complete. Existing deterministic assessment and URL checks were preserved.",
                "blocking": False,
            })

    chk.result_json = res_dict
    if len(combined.strip()) < MIN_CHARS:
        chk.status = "needs_more_information"


@router.post("/v1/checks", status_code=201, response_model=CheckResponse, response_model_exclude_none=True, tags=["checks"])
def create_check(body: CheckRequest, request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx), user=Depends(current_user)):
    throttle(request, c, "checks", c.settings.rl_checks_user if user else c.settings.rl_checks, user.id if user else None)
    token = None if user else new_token()
    chk = m.Check(user_id=user.id if user else None, guest_token_hash=sha256(token) if token else None, category=body.category,
                  expires_at=expiry(c.settings.retention_days), input_encrypted=c.crypto.enc(mask_credential_values(body.text)[0]), input_sha256=sha256(body.text), input_chars=len(body.text))
    db.add(chk)
    db.flush()
    try:
        run_check(db, c, chk)
    except Exception:
        chk.status = "failed_safely"                      # never a silent pass: say so
        chk.steps_json = (chk.steps_json or []) + [{"name": "Checking", "status": "failed"}]
    audit(db, request, user.id if user else None, "check.create", "check", chk.id)
    db.commit()
    return _render(db, c, request, chk, body.language, token)


@router.get("/v1/checks/{check_id}", response_model=CheckResponse, response_model_exclude_none=True, tags=["checks"])
def read_check(check_id: str, request: Request, lang: str = "en", db: Session = Depends(get_db), c: Ctx = Depends(ctx), user=Depends(current_user),
               x_guest_token: str | None = Header(default=None)):
    chk = _owner_check(db, c, request, check_id, user, x_guest_token, allow_moderator=True)
    return _render(db, c, request, chk, lang)


@router.post("/v1/checks/{check_id}/chat", response_model=ChatResponse, tags=["checks"])
def chat_with_check(check_id: str, body: ChatRequest, request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx),
                    user=Depends(current_user), x_guest_token: str | None = Header(default=None)):
    chk = _owner_check(db, c, request, check_id, user, x_guest_token, allow_moderator=True)
    res = chk.result_json or {}
    summary = res.get("summary", "")
    findings = res.get("findings", [])
    taxonomy_info = res.get("taxonomy")
    shop_profile = res.get("shop_profile")

    phones = nz.extract_phones(body.message)
    payment_ids = nz.extract_payment_ids(body.message)
    matched_indicator = None
    identifier_detected = None

    if phones:
        ph_norm = phones[0].normalized
        identifier_detected = f"phone number {ph_norm}"
        h = c.crypto.lookup("phone", ph_norm)
        row = db.execute(select(m.Indicator, m.Subject).join(m.Subject, m.Subject.id == m.Indicator.subject_id)
                         .where(m.Subject.subject_type == "phone", m.Subject.lookup_hmac == h, m.Indicator.status == "published")).first()
        if row:
            ind, subj = row
            matched_indicator = {"found": True, "kind": "phone number", "identifier": subj.display_masked, "reports": ind.independent_reports}
    elif payment_ids:
        pid = payment_ids[0]
        identifier_detected = f"{pid.kind} {pid.normalized}"
        h = c.crypto.lookup(pid.kind, pid.normalized)
        row = db.execute(select(m.Indicator, m.Subject).join(m.Subject, m.Subject.id == m.Indicator.subject_id)
                         .where(m.Subject.subject_type == pid.kind, m.Subject.lookup_hmac == h, m.Indicator.status == "published")).first()
        if row:
            ind, subj = row
            matched_indicator = {"found": True, "kind": pid.kind, "identifier": subj.display_masked, "reports": ind.independent_reports}

    public_sources: list[dict] = []
    investigation_data = res.get("investigation_intelligence") if isinstance(res.get("investigation_intelligence"), dict) else None
    if investigation_data:
        for evidence in (investigation_data.get("evidence") or [])[:30]:
            if not isinstance(evidence, dict):
                continue
            source_type = str(evidence.get("source_type") or "")
            source_map = {
                "public_web_search_lead": "public_search_lead",
                "inspected_public_web_page": "inspected_public_web_page",
                "social_public_search_lead": "social_intelligence_lead",
                "social_public_profile_observation": "social_profile_observation",
            }
            public_sources.append({**evidence, "source_type": source_map.get(source_type, source_type or "public_search_lead")})
        # Include URL-pipeline sources stored on the assessment (campaign reports,
        # scanner findings, official records) so follow-up answers retain provenance.
        for source in (res.get("sources") or [])[:30]:
            if not isinstance(source, dict) or not source.get("source_url"):
                continue
            reviewer = str(source.get("reviewer") or "")
            if "Tavily" in reviewer:
                source_type = "public_search_lead"
                title = "Public search lead; not independently verified"
            elif "Documented Threat Record" in reviewer:
                source_type = "documented_threat_report"
                title = "Documented historical threat report; check its date and exact scope"
            elif "Toroka Community Review" in reviewer:
                source_type = "toroka_community_record"
                title = "Published Toroka community indicator; inspect its evidence basis"
            elif "MalwareTips" in reviewer or "scanner" in reviewer.casefold() or "threat intel" in reviewer.casefold():
                source_type = "security_reputation_report"
                title = "External security reputation report; supporting signal, not proof"
            else:
                source_type = "url_investigation_source"
                title = reviewer or "URL investigation source"
            public_sources.append({"source_type": source_type, "provider": reviewer, "title": title,
                                   "url": source.get("source_url"), "snippet": str(source.get("statement") or "")[:1200]})
        report_flags = list(investigation_data.get("red_flags") or [])
        existing_codes = {str(x.get("code")) for x in report_flags if isinstance(x, dict)}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            code = str(finding.get("code") or "")
            if not code or code in existing_codes:
                continue
            combined_text = f"{finding.get('plain_text', '')} {finding.get('why_it_matters', '')}".casefold()
            if code == "RECRUITMENT_DOMAIN_PHISHING_HISTORY":
                code = "REPORTED_JOB_CREDENTIAL_HARVESTING" if ("gmail password" in combined_text or "email password" in combined_text) else "REPORTED_RECRUITMENT_SCAM_ASSOCIATION"
            report_flags.append({
                "code": code,
                "severity": "high" if str(finding.get("strength", "")).lower() in {"strong", "high"} else "supporting",
                "evidence_status": "reported_in_target_matched_public_sources" if finding.get("evidence_type") == "threat_intelligence" else "directly_observed_on_target",
                "statement": finding.get("plain_text") or "Investigation finding",
                "why_it_matters": finding.get("why_it_matters") or "Review the associated source and exact scope.",
                "source_ids": [finding.get("source_id")] if finding.get("source_id") else [],
            })
            existing_codes.add(code)
        public_sources.append({
            "source_type": "investigation_summary",
            "category": investigation_data.get("category") or (res.get("category") or {}).get("used", "message"),
            "risk_band": res.get("label"),
            "summary": investigation_data.get("summary") or summary,
            "targets": investigation_data.get("targets") or [],
            "red_flags": report_flags,
            "advice": list(investigation_data.get("advice") or []) + [x.get("text", "") for x in (res.get("next_steps") or []) if isinstance(x, dict)],
            "limitations": list(investigation_data.get("limitations") or []) + list(res.get("limitations") or []),
            "providers": investigation_data.get("providers") or [],
        })
    reply, reply_en, reply_sw = chat_with_ai_multilingual(
        check_summary=summary,
        findings=findings,
        user_message=body.message,
        history=[m.model_dump() for m in body.history],
        language=body.language,
        settings=c.settings,
        indicator_info=matched_indicator,
        identifier_detected=identifier_detected,
        taxonomy_info=taxonomy_info,
        shop_profile=shop_profile,
        public_sources=public_sources or None,
    )
    return ChatResponse(reply=reply, reply_en=reply_en, reply_sw=reply_sw, check_id=check_id)


def _is_url_inquiry(text: str, urls: list, profile: Any = None) -> bool:
    """Determine if a user message is specifically an inquiry to investigate a URL."""
    if not urls and not (profile and getattr(profile, "canonical_url", None)):
        return False
    s = text.strip()
    if re.match(r"(?i)^(?:https?://\S+|www\.\S+|chat\.whatsapp\.com/\S+|wa\.me/\S+|instagram\.com/\S+|tiktok\.com/\S+|facebook\.com/\S+|x\.com/\S+|twitter\.com/\S+)$", s):
        return True
    text_without_urls = s
    for u in urls:
        orig = getattr(u, "original", str(u))
        text_without_urls = text_without_urls.replace(orig, "")
    text_without_urls = text_without_urls.strip(" :,\t\n-?").lower()
    if len(text_without_urls) == 0:
        return True
    inquiry_indicators = (
        "check", "verify", "is this", "genuine", "legit", "legitimate", "safe",
        "scam", "real", "fake", "look into", "investigate", "audit",
        "tovuti", "kiungo", "angalia", "chunguza", "ni ya kweli", "tapeli"
    )
    if len(text_without_urls) < 160 and any(w in text_without_urls for w in inquiry_indicators):
        return True
    return False


@router.post("/v1/chat", response_model=ChatResponse, tags=["chat"])
def general_chat(body: ChatRequest, request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx),
                 user=Depends(current_user)):
    throttle(request, c, "checks", c.settings.rl_checks_user if user else c.settings.rl_checks, user.id if user else None)
    safe_msg, had_cred = mask_credential_values(body.message)

    # 1. Entity Extraction
    phones = nz.extract_phones(safe_msg)
    payment_ids = nz.extract_payment_ids(safe_msg)
    urls = nz.extract_urls(safe_msg)
    soc_profile = parse_platform_profile(urls[0].original if urls else safe_msg)

    # First-class URL & Social Profile Investigation directly in chat
    url_inv = None
    if urls or (soc_profile.is_profile and soc_profile.canonical_url):
        primary_link = soc_profile.canonical_url or urls[0].original
        url_inv = investigate_single_url(
            primary_link,
            db,
            c.crypto,
            c.settings,
            user_context=safe_msg,
            language=body.language,
        )
        if _is_url_inquiry(safe_msg, urls, soc_profile):
            is_sw = body.language == "sw"

            # The direct URL/profile route also receives the multi-source intelligence layer.
            # Reuse the Tavily leads already collected by url_pipeline; do not pay for a
            # duplicate search. Social providers receive only isolated public identifiers.
            category_guess = detect_category(safe_msg)
            platform_hint = soc_profile.platform if soc_profile.is_profile else None
            public_targets = find_public_identifiers(safe_msg, platform_hint=platform_hint)[:3]
            social_result = investigate_social_targets(public_targets, c.settings) if public_targets else {"sources": [], "statuses": [], "red_flags": []}
            search_seed_results = []
            url_public_sources = []
            for source in (url_inv.sources or []):
                reviewer = str(getattr(source, "reviewer", "") or "")
                statement = str(getattr(source, "statement", "") or "")
                source_url = str(getattr(source, "source_url", "") or "")
                title = statement.split(":", 1)[0][:180] if statement else reviewer
                if source_url and "Tavily Web Search" in reviewer:
                    search_seed_results.append({"url": source_url, "title": title or "Public search result", "snippet": statement[:1200]})

            intelligence_result = investigate_public_targets(
                public_targets,
                category=category_guess.suggested,
                submitted_text=safe_msg,
                settings=c.settings,
                skip_tavily=True,
                search_seed_results=search_seed_results,
                social_result=social_result,
            ) if public_targets else {
                "category": category_guess.suggested, "targets": [], "providers": [], "evidence": [],
                "red_flags": [], "advice": [], "limitations": ["No public identifier could be isolated for additional social/web investigation."],
                "manual_searches": [], "summary": "Only the submitted URL checks were available.",
            }

            public_sources: list[dict] = []
            for evidence in intelligence_result.get("evidence", []):
                source_type = str(evidence.get("source_type") or "")
                source_map = {
                    "public_web_search_lead": "public_search_lead",
                    "inspected_public_web_page": "inspected_public_web_page",
                    "social_public_search_lead": "social_intelligence_lead",
                    "social_public_profile_observation": "social_profile_observation",
                }
                public_sources.append({
                    **evidence,
                    "source_type": source_map.get(source_type, source_type or "public_search_lead"),
                    "url": str(evidence.get("url") or ""),
                    "title": str(evidence.get("title") or "Public evidence")[:220],
                    "snippet": str(evidence.get("snippet") or "")[:1200],
                })

            # Preserve the established URL pipeline's campaign, scanner, registry and
            # threat-feed evidence. These records are not replaced by the newer search layer.
            for source in (url_inv.sources or []):
                reviewer = str(getattr(source, "reviewer", "") or "")
                statement = str(getattr(source, "statement", "") or "")
                source_url = str(getattr(source, "source_url", "") or "")
                if "Tavily Web Search" in reviewer:
                    source_type = "public_search_lead"
                    label = "Search result lead; not independently verified"
                elif "Documented Threat Record" in reviewer:
                    source_type = "documented_threat_report"
                    label = "Documented historical threat report; check its date and exact scope"
                elif "Toroka Community Review" in reviewer:
                    source_type = "toroka_community_record"
                    label = "Published Toroka community indicator; inspect its moderation basis"
                elif "MalwareTips" in reviewer or "scanner" in reviewer.casefold() or "threat intel" in reviewer.casefold():
                    source_type = "security_reputation_report"
                    label = "External security reputation report; scanner verdicts are signals, not proof"
                else:
                    source_type = "url_investigation_source"
                    label = f"{reviewer or 'URL investigation source'}; review source provenance"
                url_public_sources.append({
                    "source_type": source_type, "provider": reviewer or "URL investigation",
                    "title": label, "url": source_url, "snippet": statement[:1200],
                    "published_date": str(getattr(source, "last_verified_at", "") or "")[:80],
                    "verification_status": "reported_or_recorded_not_automatically_verified",
                })
            public_sources.extend(url_public_sources)

            combined_flags = [x for x in (intelligence_result.get("red_flags") or []) if isinstance(x, dict)]
            for finding in (url_inv.findings or []):
                code = str(getattr(finding, "code", "") or "")
                plain = str(getattr(finding, "plain_text", "") or "")
                why = str(getattr(finding, "why_it_matters", "") or "")
                strength = str(getattr(finding, "strength", "weak") or "weak")
                evidence_type = str(getattr(finding, "evidence_type", "") or "")
                source_url = str(getattr(finding, "source_url", "") or "")
                combined_text = f"{plain} {why}".casefold()
                if code == "RECRUITMENT_DOMAIN_PHISHING_HISTORY":
                    report_code = "REPORTED_JOB_CREDENTIAL_HARVESTING" if ("gmail password" in combined_text or "email password" in combined_text) else "REPORTED_RECRUITMENT_SCAM_ASSOCIATION"
                    combined_flags.append({
                        "code": report_code,
                        "severity": "high" if strength == "strong" else "supporting",
                        "evidence_status": "reported_in_target_matched_public_sources",
                        "statement": plain,
                        "why_it_matters": why + " The historical report is associated with the same domain; the submitted URL path may be different.",
                        "source_ids": [source_url] if source_url else [],
                    })
                elif code:
                    combined_flags.append({
                        "code": code,
                        "severity": "high" if strength == "strong" else "supporting" if strength == "supporting" else "weak",
                        "evidence_status": "directly_observed_on_target" if evidence_type in {"observed_data", "page_content"} else "verification_gap_in_submission",
                        "statement": plain,
                        "why_it_matters": why,
                        "source_ids": [source_url] if source_url else [],
                    })

            provider_statuses = []
            for provider in (intelligence_result.get("providers") or []):
                if isinstance(provider, dict):
                    provider_statuses.append(provider)
            for coverage in (url_inv.coverage or []):
                provider_statuses.append({
                    "provider": getattr(coverage, "provider", None) or getattr(coverage, "name", "URL investigation"),
                    "operation": getattr(coverage, "id", "check"),
                    "status": getattr(coverage, "status", "unknown"),
                    "detail": getattr(coverage, "detail", ""),
                    "results_retrieved": getattr(coverage, "results_retrieved", 0),
                    "results_relevant": getattr(coverage, "results_relevant", 0),
                })

            investigation_advice = list(intelligence_result.get("advice") or [])
            if any(flag.get("code") == "REPORTED_JOB_CREDENTIAL_HARVESTING" for flag in combined_flags):
                investigation_advice = [
                    "Do not use this application link or enter an email password, OTP or account recovery code.",
                    "If you already entered your email password, change it through the email provider's official website, review signed-in devices and sessions, remove unfamiliar app access and enable two-step verification.",
                    "Ask for the employer's legal name, exact vacancy, written job description, salary, work location and recruiter details.",
                    "Verify the recruitment agency through Kenya's official National Employment Authority channels before paying or submitting identity documents.",
                    "For a US job, independently establish the employer and applicable work-authorisation route.",
                ]
            elif category_guess.suggested == "job":
                investigation_advice = [
                    "Do not pay an unexplained application, registration, medical or processing fee before independently verifying the recruiter and employer.",
                    "Ask for the employer's legal name, exact vacancy, salary, work location and recruitment agency details.",
                    "Verify the agency through Kenya's official National Employment Authority channels and confirm the relevant overseas work-authorisation route.",
                ]
            investigation_advice.extend(url_inv.next_steps or [])
            if public_targets or combined_flags or public_sources:
                public_sources.append({
                    "source_type": "investigation_summary",
                    "category": category_guess.suggested if category_guess.suggested in {"job", "shop", "grant", "payment", "website"} else "website",
                    "risk_band": url_inv.risk_band,
                    "summary": url_inv.summary,
                    "targets": intelligence_result.get("targets") or public_targets,
                    "red_flags": combined_flags,
                    "advice": list(dict.fromkeys(investigation_advice))[:7],
                    "limitations": list(dict.fromkeys((intelligence_result.get("limitations") or []) + (url_inv.limitations or [])))[:7],
                    "providers": provider_statuses,
                })

            manual_searches = []
            for item in (intelligence_result.get("manual_searches") or []):
                if isinstance(item, dict) and item.get("url"):
                    manual_searches.append({"label": item.get("label") or "Search this target", "url": item["url"], "identifier": item.get("identifier") or ""})

            if public_sources and any(x.get("source_type") == "investigation_summary" for x in public_sources):
                reply, reply_en, reply_sw = chat_with_ai_multilingual(
                    check_summary=url_inv.summary,
                    findings=[asdict(x) for x in (url_inv.findings or [])],
                    user_message=safe_msg,
                    history=[m.model_dump() for m in body.history[-12:]],
                    language=body.language,
                    settings=c.settings,
                    public_sources=public_sources,
                )
                reply = reply_sw if is_sw else reply_en
            elif url_inv.ai_conversational_reply:
                reply = url_inv.ai_conversational_reply
                reply_en = reply_sw = reply
            else:
                def _f_str(item):
                    p = getattr(item, "plain_text", item.get("plain_text", "") if isinstance(item, dict) else str(item))
                    w = getattr(item, "why_it_matters", item.get("why_it_matters", "") if isinstance(item, dict) else "")
                    return f"• {p}: {w}" if w else f"• {p}"

                f_lines = "\n".join(_f_str(f) for f in url_inv.findings[:4]) if url_inv.findings else ""
                n_lines = "\n".join(f"• {ns}" for ns in url_inv.next_steps[:3]) if url_inv.next_steps else ""
                if url_inv.risk_band == "verified_official":
                    lead = f"Kiungo hiki kimethibitishwa rasmi ({url_inv.summary})." if is_sw else f"This link is verified official ({url_inv.summary})."
                elif url_inv.risk_band == "high_risk":
                    lead = f"Hatari Kubwa: {url_inv.summary}" if is_sw else f"High Risk: {url_inv.summary}"
                elif url_inv.risk_band == "suspicious_verify_first":
                    lead = f"Tahadhari: {url_inv.summary}" if is_sw else f"Caution: {url_inv.summary}"
                elif url_inv.risk_band == "inconclusive":
                    lead = f"Uchunguzi haujakamilika: {url_inv.summary}" if is_sw else f"Inconclusive: {url_inv.summary}"
                else:
                    lead = f"Hakuna ripoti za utapeli zilizopatikana kuhusu kiungo hiki. Thibitisha kila wakati kabla ya malipo." if is_sw else f"No known threats found across threat feeds or community records. Always verify before making payments."
                parts = [lead]
                if f_lines:
                    parts.append(f_lines)
                if n_lines:
                    parts.append(n_lines)
                reply = "\n\n".join(parts).strip()

            action_chips = []
            if url_inv.risk_band == "high_risk":
                action_chips.append({"label": "Ripoti kisa hiki" if is_sw else "Report this scam", "action": "report", "key": "btn_report_this"})
                action_chips.append({"label": "Usaidizi wa kurejesha malipo" if is_sw else "Payment reversal help", "action": "reversal", "key": "btn_reversal_help"})
            elif soc_profile.is_profile:
                action_chips.append({"label": "Ripoti muuzaji huyu" if is_sw else "Report this seller", "action": "report", "key": "btn_report_this"})
                action_chips.append({"label": "Tafuta muuzaji mwingine" if is_sw else "Look up another seller", "action": "lookup", "key": "btn_lookup_another"})
            else:
                action_chips.append({"label": "Tafuta tovuti nyingine" if is_sw else "Look up another website", "action": "lookup", "key": "btn_lookup_another"})
                action_chips.append({"label": "Ripoti kiungo hiki" if is_sw else "Report this link", "action": "report", "key": "btn_report_this"})

            search_cov = next((c for c in url_inv.coverage if c.id == "tavily_search"), None)
            if search_cov and search_cov.source_url:
                search_label = f"Search the web for @{soc_profile.handle}" if (soc_profile.is_profile and soc_profile.handle) else f"Search public records for {url_inv.domain}"
                ident = f"@{soc_profile.handle}" if (soc_profile.is_profile and soc_profile.handle) else url_inv.domain
                manual_searches.append({"label": search_label, "url": search_cov.source_url, "identifier": ident})
            elif not soc_profile.is_profile:
                for cov in url_inv.coverage:
                    s_url = getattr(cov, "source_url", cov.get("source_url") if isinstance(cov, dict) else None)
                    if s_url:
                        manual_searches.append({"label": f"Search public records for {url_inv.domain}", "url": s_url, "identifier": url_inv.domain})

            # Keep the structured evidence trail available to the chat UI too, not
            # only to the saved /v1/checks assessment flow.
            url_payload = asdict(url_inv)
            explanation_evidence = list(intelligence_result.get("evidence", [])[:30])
            assessment_sources = []
            for source in (url_inv.sources or []):
                source_record = {
                    "id": getattr(source, "id", ""),
                    "statement": getattr(source, "statement", ""),
                    "source_url": getattr(source, "source_url", None),
                    "reviewer": getattr(source, "reviewer", ""),
                    "last_verified_at": getattr(source, "last_verified_at", None),
                }
                assessment_sources.append(source_record)
                source_url = str(source_record.get("source_url") or "")
                if source_url and not any(x.get("url") == source_url for x in explanation_evidence if isinstance(x, dict)):
                    reviewer = str(source_record.get("reviewer") or "URL investigation")
                    if "Tavily Web Search" in reviewer:
                        source_type = "public_search_lead"
                    elif "Documented Threat Record" in reviewer:
                        source_type = "documented_threat_report"
                    elif "Toroka Community Review" in reviewer:
                        source_type = "toroka_community_record"
                    elif "MalwareTips" in reviewer or "scanner" in reviewer.casefold() or "threat intel" in reviewer.casefold():
                        source_type = "security_reputation_report"
                    elif "toroka-verified-" in str(source_record.get("id") or ""):
                        source_type = "verified_registry_record"
                    else:
                        source_type = "url_investigation_source"
                    explanation_evidence.append({
                        "evidence_id": "url-" + sha256(source_url)[:16],
                        "provider": reviewer,
                        "source_type": source_type,
                        "title": reviewer or "URL investigation source",
                        "snippet": str(source_record.get("statement") or "")[:1200],
                        "url": source_url,
                        "claim_status": "source_record_not_a_user_allegation",
                        "identity_match": "matched_by_url_investigation_pipeline",
                        "published_at": source_record.get("last_verified_at") or "",
                    })
            direct_limitations = list(dict.fromkeys((intelligence_result.get("limitations") or []) + (url_inv.limitations or [])))[:10]
            direct_evidence_explanation = build_verdict_explanation(
                str(url_inv.risk_band or "inconclusive"),
                str(url_inv.summary or ""),
                combined_flags,
                explanation_evidence,
                direct_limitations,
                assessment_sources,
            )
            url_payload["investigation_intelligence"] = {
                "category": intelligence_result.get("category"),
                "targets": intelligence_result.get("targets") or public_targets,
                "providers": provider_statuses,
                "red_flags": combined_flags[:20],
                "evidence": intelligence_result.get("evidence", [])[:30],
                "evidence_explanation": direct_evidence_explanation,
                "shop_discovery": intelligence_result.get("shop_discovery"),
                "advice": list(dict.fromkeys(investigation_advice))[:10],
                "limitations": direct_limitations,
            }
            return ChatResponse(
                reply=reply,
                reply_en=locals().get("reply_en", reply),
                reply_sw=locals().get("reply_sw", reply),
                check_id=None,
                action_chips=action_chips,
                manual_searches=manual_searches,
                url_investigation=url_payload,
            )

    # Social media handle extraction
    m_soc = re.search(r"(?:https?://)?(?:www\.)?(instagram\.com|tiktok\.com|facebook\.com|twitter\.com|x\.com)/@?([a-zA-Z0-9_.]+)", safe_msg, re.I)
    detected_social = None
    if m_soc:
        raw_p = m_soc.group(1).lower()
        p_name = "instagram" if "instagram" in raw_p else "tiktok" if "tiktok" in raw_p else "facebook" if "facebook" in raw_p else "x"
        s_handle = m_soc.group(2).rstrip("/")
        if s_handle.lower() not in {"p", "reel", "reels", "stories", "explore", "watch", "share", "direct", "settings", "login", "home"}:
            detected_social = (p_name, s_handle)
    else:
        # A standalone @handle is an explicit identifier; do not confuse email addresses with handles.
        m_handle = re.search(r"(?<![\w.+-])@([a-zA-Z0-9_.]{3,35})\b", safe_msg)
        if m_handle and not re.search(r"(?i)\b(?:look into|investigate|check|verify|shop|seller|account|profile|muuzaji|duka)\b", safe_msg):
            # Infer a platform only from user-authored context. Assistant suggestions such as
            # "Instagram or TikTok" must not arbitrarily force an Instagram lookup.
            user_context = " ".join([safe_msg] + [h.text for h in body.history[-12:] if h.role == "user"])
            found_platforms = set(re.findall(r"(?i)\b(instagram|tiktok|facebook|whatsapp|twitter|x\s*\(twitter\))\b", user_context))
            canon = {"twitter": "x", "x (twitter)": "x"}
            found_platforms = {canon.get(platform.lower(), platform.lower()) for platform in found_platforms}
            p_name = next(iter(found_platforms)) if len(found_platforms) == 1 else "social"
            detected_social = (p_name, m_handle.group(1).rstrip("."))

    detected_domain = None
    if not detected_social:
        if urls:
            detected_domain = urls[0].registered_domain or urls[0].host
        else:
            m_dom = re.search(r"\b([a-zA-Z0-9-]+\.(?:com|co\.ke|org|net|ke|xyz|shop|online|top|site|app|biz|info|travel|aero))\b", safe_msg, re.I)
            if m_dom:
                detected_domain = m_dom.group(1).lower()

    # A plain business name is a search query, not automatically a social handle.
    detected_shop_name = None
    if not detected_social and not detected_domain and not re.search(r"(?<![\w.+-])@[a-zA-Z0-9_.]{3,35}\b", safe_msg):
        shop_match = re.search(
            r"(?i)\b(?:look\s+into|investigate|check|verify|research|audit|kagua|chunguza|angalia|tazama)\s+"
            r"(?:(?:this|that|the|a|an)\s+)?(?:(?:instagram|insta|tiktok|facebook|social\s+media)\s+)?"
            r"(?:online\s+)?(?:shop|store|seller|vendor|page|account|brand|boutique)\s+"
            r"([a-zA-Z0-9][a-zA-Z0-9._-]{2,50})\b", safe_msg)
        if shop_match:
            candidate = shop_match.group(1).rstrip(".,!?;:")
            if candidate.lower() not in {"this", "that", "shop", "store", "seller", "vendor", "page", "account", "brand", "website", "message", "sms"}:
                detected_shop_name = candidate

    # 2. Pattern Recognition (Rule signals)
    detected_patterns: list[str] = []
    for rule in signals.TEXT_RULES:
        for f in rule(safe_msg):
            if f.code not in detected_patterns:
                detected_patterns.append(f.code)

    # 3. Database Indicator Check & Pattern Storing
    matched_indicator = None
    identifier_detected = None
    stored_subject = None

    if phones:
        ph_norm = phones[0].normalized
        identifier_detected = f"phone number {ph_norm}"
        h = c.crypto.lookup("phone", ph_norm)
        row = db.execute(select(m.Indicator, m.Subject).join(m.Subject, m.Subject.id == m.Indicator.subject_id)
                         .where(m.Subject.subject_type == "phone", m.Subject.lookup_hmac == h, m.Indicator.status == "published")).first()
        if row:
            ind, subj = row
            matched_indicator = {"found": True, "kind": "phone number", "identifier": subj.display_masked, "reports": ind.independent_reports}
        try:
            stored_subject = upsert_subject(db, c, "phone", ph_norm, nz.mask_phone(ph_norm))
            db.commit()
        except Exception:
            db.rollback()
    elif payment_ids:
        pid = payment_ids[0]
        identifier_detected = f"{pid.kind} {pid.normalized}"
        h = c.crypto.lookup(pid.kind, pid.normalized)
        row = db.execute(select(m.Indicator, m.Subject).join(m.Subject, m.Subject.id == m.Indicator.subject_id)
                         .where(m.Subject.subject_type == pid.kind, m.Subject.lookup_hmac == h, m.Indicator.status == "published")).first()
        if row:
            ind, subj = row
            matched_indicator = {"found": True, "kind": pid.kind, "identifier": subj.display_masked, "reports": ind.independent_reports}
        try:
            stored_subject = upsert_subject(db, c, pid.kind, pid.normalized, f"{pid.kind} ••{pid.normalized[-3:]}")
            db.commit()
        except Exception:
            db.rollback()
    elif detected_social:
        p_name, s_handle = detected_social
        platform_candidates = [p_name] if p_name in {"instagram", "tiktok", "facebook", "x", "whatsapp", "twitter"} else ["instagram", "tiktok", "facebook", "x", "twitter", "whatsapp", "social"]
        identifier_detected = f"social account @{s_handle}" + (f" on {p_name.capitalize()}" if p_name != "social" else " (platform not specified)")
        exact_matches = []
        # Check exact platform-specific identifiers if the user did not state the platform.
        # If the handle exists on multiple platforms, retain that ambiguity in the response.
        for candidate_platform in platform_candidates:
            h = c.crypto.lookup("handle", f"{candidate_platform}:{s_handle.lower()}")
            row = db.execute(select(m.Indicator, m.Subject).join(m.Subject, m.Subject.id == m.Indicator.subject_id)
                             .where(m.Subject.subject_type == "handle", m.Subject.lookup_hmac == h, m.Indicator.status == "published")).first()
            if row:
                ind, subj = row
                exact_matches.append((candidate_platform, ind, subj))
        if exact_matches:
            exact_platforms = sorted({candidate for candidate, _, _ in exact_matches})
            best_reports = max((ind.independent_reports or 0) for _, ind, _ in exact_matches)
            first_subj = exact_matches[0][2]
            matched_indicator = {
                "found": True,
                "kind": (f"{p_name.capitalize()} account" if p_name != "social" else "social account"),
                "identifier": first_subj.display_masked,
                "reports": best_reports,
                "matched_platforms": exact_platforms,
                "platform_ambiguous": len(exact_platforms) > 1,
            }
        try:
            # Unknown platform gets a distinct generic key; do not silently assign Instagram/TikTok.
            stored_subject = upsert_subject(db, c, "handle", f"{p_name}:{s_handle.lower()}",
                                            f"@{s_handle} ({p_name.capitalize() if p_name != 'social' else 'platform not specified'})")
            db.commit()
        except Exception:
            db.rollback()
    elif detected_shop_name:
        identifier_detected = f"shop name {detected_shop_name}"
        # A plain shop name may match a previously published exact handle on a platform.
        # Query candidate platform keys explicitly; do not use fuzzy name matching.
        exact_matches = []
        candidate_platforms = ["instagram", "tiktok", "facebook", "x", "twitter", "whatsapp", "social"]
        for candidate_platform in candidate_platforms:
            h = c.crypto.lookup("handle", f"{candidate_platform}:{detected_shop_name.lower()}")
            row = db.execute(select(m.Indicator, m.Subject).join(m.Subject, m.Subject.id == m.Indicator.subject_id)
                             .where(m.Subject.subject_type == "handle", m.Subject.lookup_hmac == h, m.Indicator.status == "published")).first()
            if row:
                ind, subj = row
                exact_matches.append((candidate_platform, ind, subj))
        if exact_matches:
            platforms = sorted({platform for platform, _, _ in exact_matches})
            matched_indicator = {
                "found": True,
                "kind": "exact shop-name/handle match",
                "identifier": exact_matches[0][2].display_masked,
                "reports": max((ind.independent_reports or 0) for _, ind, _ in exact_matches),
                "matched_platforms": platforms,
                "platform_ambiguous": len(platforms) > 1,
            }
    elif detected_domain:
        identifier_detected = f"website {detected_domain}"
        h = c.crypto.lookup("domain", detected_domain)
        row = db.execute(select(m.Indicator, m.Subject).join(m.Subject, m.Subject.id == m.Indicator.subject_id)
                         .where(m.Subject.subject_type == "domain", m.Subject.lookup_hmac == h, m.Indicator.status == "published")).first()
        if row:
            ind, subj = row
            matched_indicator = {"found": True, "kind": "website", "identifier": subj.display_masked, "reports": ind.independent_reports}
        try:
            stored_subject = upsert_subject(db, c, "domain", detected_domain, detected_domain)
            db.commit()
        except Exception:
            db.rollback()

    # 4. If fraud incident or high risk signal reported with an identifier, record a private report so pattern is saved
    if stored_subject and ("REPORTED_FRAUD_INCIDENT" in detected_patterns or any(p in detected_patterns for p in ["PIN_OR_OTP_REQUEST", "ADVANCE_PAYMENT_REQUEST", "ADVANCE_FEE_REQUEST", "TASK_SCAM_LURE"])):
        try:
            key = c.crypto.lookup("reporter", user.id) if user else client_key(request, c)
            tok = new_token()
            rep = m.Report(
                reporter_user_id=user.id if user else None,
                reporter_key=key,
                token_hash=sha256(tok),
                category="payment" if payment_ids else "message",
                narrative_encrypted=c.crypto.enc(safe_msg),
                script_hash=script_hash(safe_msg),
                minhash=minhash(safe_msg),
            )
            db.add(rep)
            db.flush()
            db.add(m.ReportSubject(report_id=rep.id, subject_id=stored_subject.id))
            db.commit()
        except Exception:
            db.rollback()

    # 5. Interactive action chips
    action_chips = []
    is_sw = body.language == "sw"
    if "REPORTED_FRAUD_INCIDENT" in detected_patterns or any(w in safe_msg.lower() for w in ["reverse", "rudisha", "paid", "nililipa"]):
        action_chips.append({"label": "Usaidizi wa kurejesha malipo" if is_sw else "Payment reversal help", "action": "reversal", "key": "btn_reversal_help"})
        action_chips.append({"label": "Ripoti kisa hiki" if is_sw else "Report this scam", "action": "report", "key": "btn_report_this"})
    elif phones or payment_ids:
        action_chips.append({"label": "Tafuta nambari nyingine" if is_sw else "Look up another number", "action": "lookup", "key": "btn_lookup_another"})
        action_chips.append({"label": "Ripoti muuzaji huyu" if is_sw else "Report this seller", "action": "report", "key": "btn_report_this"})
    elif detected_social:
        action_chips.append({"label": "Tafuta muuzaji mwingine" if is_sw else "Look up another seller", "action": "lookup", "key": "btn_lookup_another"})
        action_chips.append({"label": "Ripoti muuzaji huyu" if is_sw else "Report this seller", "action": "report", "key": "btn_report_this"})
    elif detected_domain:
        action_chips.append({"label": "Tafuta tovuti nyingine" if is_sw else "Look up another website", "action": "lookup", "key": "btn_lookup_another"})
        action_chips.append({"label": "Ripoti tovuti hii" if is_sw else "Report this website", "action": "report", "key": "btn_report_this"})

    check_summary = "Conversational safety consultation with Toroka copilot"
    findings_list = [{"code": p, "plain_text": p} for p in detected_patterns]
    taxonomy_info = None
    shop_profile = None
    # The browser may retain the last check ID. Only reuse it when the message is clearly a follow-up.
    active_check_id = body.check_id if _is_clear_follow_up(safe_msg) else None
    if soc_profile.is_profile or urls or detected_social or detected_shop_name:
        active_check_id = None

    if active_check_id:
        chk = db.get(m.Check, active_check_id)
        if chk and chk.result_json:
            check_summary = chk.result_json.get("summary", check_summary)
            findings_list = chk.result_json.get("findings", findings_list) + findings_list
            taxonomy_info = chk.result_json.get("taxonomy")
            shop_profile = chk.result_json.get("shop_profile")

    public_sources: list[dict[str, str]] = []
    manual_searches: list[dict[str, str]] = []
    # Extract public identifiers from the current evidence plus recent user-authored
    # context only. External services never receive the raw conversation or secrets.
    public_context = " ".join(h.text for h in body.history[-12:] if h.role == "user") if _is_new_investigation_input(safe_msg) else ""
    public_targets = find_public_identifiers(safe_msg, context_text=public_context)[:3]

    # Run the existing social adapters once, then hand their normalised public evidence
    # to the unified orchestrator. This prevents duplicate Weir/Scrape Creators charges.
    social_result = investigate_social_targets(public_targets, c.settings) if public_targets else {"sources": [], "statuses": [], "red_flags": []}
    category_guess = detect_category(safe_msg)
    intelligence_result = investigate_public_targets(
        public_targets,
        category=category_guess.suggested,
        submitted_text=safe_msg,
        settings=c.settings,
        social_result=social_result,
        web_search_fn=public_search,
    )

    # One common evidence contract feeds the response generator. Provider status is
    # separate from evidence: unavailable is never represented as a clean result.
    provider_lines: list[str] = []
    for provider in intelligence_result.get("providers", []):
        provider_name = str(provider.get("provider") or "Provider")
        operation = str(provider.get("operation") or "check")
        status = str(provider.get("status") or "unknown")
        detail = str(provider.get("detail") or "No provider detail available.")[:600]
        provider_lines.append(f"{provider_name} ({operation}) — {status}: {detail}")
        public_sources.append({
            "source_type": "provider_status",
            "provider": provider_name,
            "operation": operation,
            "status": status,
            "detail": detail,
            "searched_identifier": str(provider.get("searched_identifier") or ""),
            "results_retrieved": int(provider.get("results_retrieved") or 0),
            "results_relevant": int(provider.get("results_relevant") or 0),
        })

    for evidence in intelligence_result.get("evidence", []):
        evidence_type = str(evidence.get("source_type") or "")
        source_type_map = {
            "public_web_search_lead": "public_search_lead",
            "inspected_public_web_page": "inspected_public_web_page",
            "social_public_search_lead": "social_intelligence_lead",
            "social_public_profile_observation": "social_profile_observation",
        }
        public_sources.append({
            **evidence,
            "source_type": source_type_map.get(evidence_type, evidence_type or "public_search_lead"),
            "url": str(evidence.get("url") or ""),
            "snippet": str(evidence.get("snippet") or "")[:1200],
            "title": str(evidence.get("title") or "Public evidence")[:220],
        })

    for flag in intelligence_result.get("red_flags", []):
        if not isinstance(flag, dict):
            continue
        public_sources.append({
            **flag,
            "source_type": "investigation_flag",
            "title": str(flag.get("statement") or flag.get("label") or "Investigation warning")[:220],
            "snippet": str(flag.get("why_it_matters") or "")[:1200],
            "url": "",
        })

    # This structured summary lets the local response composer tailor the answer to
    # the detected investigation type without asking a model to invent missing checks.
    if category_guess.suggested in {"job", "shop", "grant", "payment", "website"} and (
        public_targets or intelligence_result.get("red_flags") or intelligence_result.get("evidence")
    ):
        public_sources.append({
            "source_type": "investigation_summary",
            "category": category_guess.suggested,
            "summary": str(intelligence_result.get("summary") or ""),
            "targets": intelligence_result.get("targets", []),
            "red_flags": intelligence_result.get("red_flags", []),
            "advice": intelligence_result.get("advice", []),
            "limitations": intelligence_result.get("limitations", []),
            "providers": intelligence_result.get("providers", []),
        })

    for item in intelligence_result.get("manual_searches", []):
        if isinstance(item, dict) and item.get("url"):
            manual_searches.append({
                "label": str(item.get("label") or "Search this target"),
                "url": str(item["url"]),
                "identifier": str(item.get("identifier") or ""),
            })
    # Retain one user-facing search status summarising exactly what was attempted.
    if provider_lines:
        public_sources.append({
            "source_type": "search_status",
            "status": "provider_checks_completed",
            "detail": "Investigation provider results: " + " | ".join(provider_lines[:8]),
        })
    elif public_targets:
        public_sources.append({
            "source_type": "search_status",
            "status": "not_checked",
            "detail": "No configured public investigation provider completed a check. This is not evidence of safety or fraud.",
        })

    relevant_history = [m.model_dump() for m in body.history[-12:]]
    if _is_new_investigation_input(safe_msg):
        # Avoid contamination by unrelated cases, but retain an explicitly relevant user context
        # such as "I don't bet and never signed up" when the user then pastes the promotion SMS.
        relevant_history = []
        is_betting_promo = bool(re.search(r"(?i)\b(?:freebets?|free\s+bets?|aviator|casino\s+bonus|betting\s+bonus|sportsbook\s+bonus)\b", safe_msg))
        relevant_context = re.compile(
            r"(?i)(?:\bi\s+(?:do not|don't|dont)\s+(?:do\s+)?(?:bet|betting|gamble|gambling|use betting)|"
            r"\bi\s+(?:never|did not|didn't)\s+(?:register|subscribe|sign up|bet|gamble)|"
            r"\b(?:random|unsolicited|unwanted)\s+(?:betting\s+(?:agencies?\s+)?)?(?:gambling\s+)?(?:sms|texts?|messages?)\b|"
            r"\bkeep getting (?:these|such|random)|\bwithout (?:my\s+)?(?:consent|permission)|"
            r"sijawahi kucheza kamari|sijajiandikisha|ujumbe usioombwa)"
        )
        if is_betting_promo:
            relevant_history = [m.model_dump() for m in body.history[-12:] if m.role == "user" and relevant_context.search(m.text or "")]

    reply, reply_en, reply_sw = chat_with_ai_multilingual(
        check_summary=check_summary,
        findings=findings_list,
        user_message=safe_msg,
        history=relevant_history,
        language=body.language,
        settings=c.settings,
        indicator_info=matched_indicator,
        identifier_detected=identifier_detected,
        taxonomy_info=taxonomy_info,
        shop_profile=shop_profile,
        public_sources=public_sources,
    )
    return ChatResponse(
        reply=reply,
        reply_en=reply_en,
        reply_sw=reply_sw,
        check_id=active_check_id,
        manual_searches=manual_searches,
        detected_patterns=detected_patterns,
        action_chips=action_chips,
        url_investigation=asdict(url_inv) if url_inv else None,
    )


@router.get("/v1/me/checks", tags=["accounts"])
def my_checks(db: Session = Depends(get_db), user: m.User = Depends(require_user)):
    rows = db.execute(select(m.Check).where(m.Check.user_id == user.id, m.Check.expires_at > m.now_iso()).order_by(m.Check.created_at.desc()).limit(50)).scalars()
    return {"checks": [{"check_id": r.id, "created_at": r.created_at, "label": r.risk_band, "status": r.status, "expires_at": r.expires_at} for r in rows]}


@router.delete("/v1/checks/{check_id}", tags=["checks"])
def delete_check(check_id: str, request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx), user=Depends(current_user),
                 x_guest_token: str | None = Header(default=None)):
    chk = _owner_check(db, c, request, check_id, user, x_guest_token)
    _erase_check(db, c, chk)
    audit(db, request, user.id if user else None, "check.delete", "check", check_id)
    db.commit()
    return {"status": "deleted"}


def _erase_check(db: Session, c: Ctx, chk: m.Check):
    for ev in db.execute(select(m.EvidenceFile).where(m.EvidenceFile.check_id == chk.id)).scalars():
        try:
            os.remove(os.path.join(c.settings.storage_dir, ev.object_key))
        except FileNotFoundError:
            pass
    ev_ids = [e.id for e in db.execute(select(m.EvidenceFile).where(m.EvidenceFile.check_id == chk.id)).scalars()]
    for model, cond in ((m.EvidenceExtraction, m.EvidenceExtraction.evidence_id.in_(ev_ids)), (m.EvidenceFile, m.EvidenceFile.check_id == chk.id),
                        (m.RiskSignal, m.RiskSignal.check_id == chk.id), (m.Assessment, m.Assessment.check_id == chk.id),
                        (m.SourceObservation, m.SourceObservation.check_id == chk.id)):
        for row in db.execute(select(model).where(cond)).scalars().all():
            db.delete(row)                  # explicit, so erasure does not depend on the database enforcing cascades
    db.flush()
    db.delete(chk)


def purge_expired(db: Session, c: Ctx) -> int:
    n = 0
    for chk in db.execute(select(m.Check).where(m.Check.expires_at < m.now_iso())).scalars().all():
        _erase_check(db, c, chk)
        n += 1
    for s in db.execute(select(m.SessionToken).where(m.SessionToken.expires_at < m.now_iso())).scalars().all():
        db.delete(s)
    db.commit()
    return n


@router.get("/v1/checks/{check_id}/export", tags=["checks"])
def export_check(check_id: str, request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx), user=Depends(current_user), x_guest_token: str | None = Header(default=None)):
    chk = _owner_check(db, c, request, check_id, user, x_guest_token)
    return {"check_id": chk.id, "created_at": chk.created_at, "expires_at": chk.expires_at, "submitted_text": c.crypto.dec(chk.input_encrypted) if chk.input_encrypted else None,
            "assessment": chk.result_json, "evidence": [e.model_dump() for e in _evidence_out(db, c, chk)], "policy_version": chk.assessment_version,
            "note": "This is everything we hold for this check. It is deleted automatically on the expiry date."}


# ---------------------------------------------------------------- evidence
@router.post("/v1/checks/{check_id}/evidence", status_code=201, response_model=CheckResponse, response_model_exclude_none=True, tags=["checks"])
async def upload_evidence(check_id: str, request: Request, file: UploadFile = File(...), consent_scope: str = Form("this_check_only"), lang: str = Form("en"),
                          db: Session = Depends(get_db), c: Ctx = Depends(ctx), user=Depends(current_user), x_guest_token: str | None = Header(default=None)):
    chk = _owner_check(db, c, request, check_id, user, x_guest_token)
    throttle(request, c, "evidence", c.settings.rl_evidence, chk.id)
    if len(db.execute(select(m.EvidenceFile).where(m.EvidenceFile.check_id == chk.id)).scalars().all()) >= c.settings.max_evidence_per_check:
        raise HTTPException(409, f"A check can hold at most {c.settings.max_evidence_per_check} screenshots.")
    raw = await file.read(images.MAX_BYTES + 1)
    try:
        clean = images.sanitize(raw)
    except images.ImageRejected as e:
        raise HTTPException(400, f"We could not use that file: {e}.")
    r = ocr.ocr_png(clean.png)
    key = f"{uuid.uuid4().hex}.bin"
    os.makedirs(c.settings.storage_dir, exist_ok=True)
    with open(os.path.join(c.settings.storage_dir, key), "wb") as fh:
        fh.write(c.crypto.enc_bytes(clean.png))
    ev = m.EvidenceFile(check_id=chk.id, object_key=key, sha256=clean.sha256_clean, mime_type="image/png", size_bytes=len(clean.png), width=clean.width, height=clean.height,
                        dhash=clean.dhash, consent_scope=consent_scope[:24], retention_until=chk.expires_at)
    db.add(ev)
    db.flush()
    db.add(m.EvidenceExtraction(evidence_id=ev.id, extracted_text_encrypted=c.crypto.enc(r.text or ""), language=r.language, extractor_version="tesseract",
                                status=r.status.value, confidence=int(r.mean_confidence) if r.mean_confidence is not None else None, note=r.note[:200]))
    db.flush()
    try:
        run_check(db, c, chk)
    except Exception:
        chk.status = "failed_safely"
    audit(db, request, user.id if user else None, "evidence.upload", "check", chk.id, {"sha256": clean.sha256_clean})
    db.commit()
    return _render(db, c, request, chk, lang)


@router.get("/v1/checks/{check_id}/evidence", response_model=list[EvidenceOut], tags=["checks"])
def list_evidence(check_id: str, request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx), user=Depends(current_user), x_guest_token: str | None = Header(default=None)):
    chk = _owner_check(db, c, request, check_id, user, x_guest_token, allow_moderator=True)
    return _evidence_out(db, c, chk)          # metadata and redacted text only; the stored files are never served


# ---------------------------------------------------------------- recovery, opportunities
@router.post("/v1/recovery", tags=["checks"])
def recovery(body: RecoveryIn):
    return triage(body.model_dump(exclude={"language"}), language=body.language)


def _opp_out(o: m.Opportunity) -> dict:
    return {"id": o.id, "type": o.opportunity_type, "official_name": o.official_name, "administering_body": o.administering_body, "official_domain": o.official_domain,
            "application_url": o.application_url, "eligibility": o.eligibility, "counties": o.counties, "status": o.status, "fee_policy": o.fee_policy, "source_url": o.source_url,
            "last_verified_at": o.last_verified_at, "review_due": o.review_due, "is_stale": o.review_due < datetime.now(timezone.utc).date().isoformat(), "reviewer": o.reviewer,
            "note": "Verified from the source shown. Always confirm on the official site, typed in yourself."}


@router.get("/v1/opportunities", tags=["registry"])
def list_opportunities(q: str | None = None, type: str | None = None, db: Session = Depends(get_db)):
    rows = [o for o in db.execute(select(m.Opportunity)).scalars() if (not type or o.opportunity_type == type) and (not q or q.lower() in (o.official_name + o.administering_body).lower())]
    return {"opportunities": [_opp_out(o) for o in rows]}


@router.get("/v1/opportunities/{oid}", tags=["registry"])
def get_opportunity(oid: str, db: Session = Depends(get_db)):
    o = db.get(m.Opportunity, oid)
    if not o:
        raise HTTPException(404, "No such record.")
    return _opp_out(o)


@router.put("/v1/admin/opportunities", tags=["registry"])
def upsert_opportunity(body: OpportunityIn, request: Request, db: Session = Depends(get_db), admin: m.User = Depends(require_role("admin", "moderator"))):
    due = (datetime.fromisoformat(body.last_verified_at) + timedelta(days=body.review_interval_days)).date().isoformat()
    row = db.get(m.Opportunity, body.id) or m.Opportunity(id=body.id)
    for k, v in body.model_dump(exclude={"review_interval_days"}).items():
        setattr(row, k, v)
    row.review_due = due
    db.merge(row)
    audit(db, request, admin.id, "opportunity.upsert", "opportunity", body.id, {"source_url": body.source_url})
    db.commit()
    return _opp_out(db.get(m.Opportunity, body.id))


# ---------------------------------------------------------------- verified sites and shops
SHARED_HOSTS = {"blogspot.com", "wixsite.com", "github.io", "vercel.app", "netlify.app", "pages.dev", "herokuapp.com", "web.app", "firebaseapp.com", "myshopify.com", "wordpress.com", "weebly.com",
                "facebook.com", "instagram.com", "tiktok.com", "x.com", "twitter.com", "youtube.com", "google.com", "linktr.ee", "wa.me", "t.me", "bit.ly", "tinyurl.com", "co.ke", "go.ke", "or.ke", "com", "org", "net"}
PLATFORMS = {"instagram", "tiktok", "facebook", "x", "whatsapp"}


def _verified_out(v: m.VerifiedRecord) -> dict:
    return {"id": v.id, "name": v.name, "type": v.entity_type, "domains": v.domains, "handles": v.handles, "basis": v.basis, "source_url": v.source_url, "last_verified_at": v.last_verified_at,
            "review_due": v.review_due, "is_stale": v.review_due < datetime.now(timezone.utc).date().isoformat(), "status": v.status,
            "note": "Verified means the site identity matched the reviewed source. It does not prove every offer or message using its name is genuine; verify the specific offer and payment recipient."}


@router.get("/v1/verified-entities", tags=["registry"])
def list_verified(db: Session = Depends(get_db)):
    # The public registry is not a place to expose unreviewed seed assertions.
    records = db.execute(select(m.VerifiedRecord).where(m.VerifiedRecord.status == "active").order_by(m.VerifiedRecord.name)).scalars()
    return {"verified": [_verified_out(v) for v in records if is_verified_record_current(v)]}


@router.put("/v1/admin/verified-entities", tags=["registry"])
def upsert_verified(body: VerifiedEntityIn, request: Request, db: Session = Depends(get_db), mod: m.User = Depends(require_role("admin", "moderator"))):
    domains = []
    for d in body.domains:
        p = nz.parse_url(d.strip().lower())
        if not p or p.is_ip or p.is_punycode or "." not in p.host or p.host in SHARED_HOSTS or p.registered_domain in SHARED_HOSTS or any(p.host.endswith("." + h) and h not in ("co.ke", "go.ke", "or.ke") for h in SHARED_HOSTS):
            raise HTTPException(422, f"{d!r} cannot be verified: it must be a normal domain that this business controls, not a shared host, social platform or address.")
        domains.append(p.host)
    handles = []
    for h in body.handles:
        pl, _, hd = h.lower().partition(":")
        if pl not in PLATFORMS or not hd or not hd.replace("_", "").replace(".", "").isalnum():
            raise HTTPException(422, f"{h!r} should look like instagram:handle (platforms: {', '.join(sorted(PLATFORMS))}).")
        handles.append(f"{pl}:{hd}")
    if not domains and not handles:
        raise HTTPException(422, "Give at least one domain or social handle.")
    if body.basis != "official_registry" and len((body.evidence_note or "").strip()) < 10:
        raise HTTPException(422, "Say what evidence you checked (at least a sentence). Verification is a public promise.")
    due = (datetime.fromisoformat(body.last_verified_at) + timedelta(days=body.review_interval_days)).date().isoformat()
    row = db.get(m.VerifiedRecord, body.id) or m.VerifiedRecord(id=body.id)
    row.name, row.entity_type, row.domains, row.handles, row.include_subdomains = body.name, body.entity_type, domains, handles, body.include_subdomains
    # Never trust the submitted reviewer string; use the authenticated moderator identity.
    row.basis, row.source_url, row.evidence_note, row.last_verified_at, row.review_due, row.reviewer, row.status, row.revoked_reason = body.basis, body.source_url, body.evidence_note, body.last_verified_at, due, f"moderator:{mod.id}", "active", None
    db.merge(row)
    audit(db, request, mod.id, "verified.upsert", "verified_entity", body.id, {"basis": body.basis, "domains": domains})
    db.commit()
    invalidate_url_cache()
    return _verified_out(db.get(m.VerifiedRecord, body.id))


@router.post("/v1/moderation/verified-entities/{vid}/revoke", tags=["moderation"])
def revoke_verified(vid: str, body: dict, request: Request, db: Session = Depends(get_db), mod: m.User = Depends(require_role("admin", "moderator"))):
    v = db.get(m.VerifiedRecord, vid)
    if not v or not body.get("reason_code"):
        raise HTTPException(422, "Give an existing record id and a reason_code.")
    v.status, v.revoked_reason = "revoked", str(body["reason_code"])[:60]
    audit(db, request, mod.id, "verified.revoke", "verified_entity", vid, {"reason_code": v.revoked_reason})
    db.commit()
    invalidate_url_cache()
    return {"id": vid, "status": "revoked"}


# ---------------------------------------------------------------- forward-to-check channels
def _channel_check(db: Session, c: Ctx, request, text: str, key: str) -> tuple[m.Check, str]:
    throttle(request, c, "channel", c.settings.rl_checks, key)
    token = new_token()
    chk = m.Check(guest_token_hash=sha256(token), expires_at=expiry(c.settings.retention_days), input_type="forwarded", input_encrypted=c.crypto.enc(mask_credential_values(text[:5000])[0]),
                  input_sha256=sha256(text), input_chars=len(text))
    db.add(chk)
    db.flush()
    run_check(db, c, chk)
    db.commit()
    return chk, f"{c.settings.public_base_url}/#r={chk.id}.{token}"       # the token sits in the fragment, so it is not sent to servers or logged


def _send_or_queue(db: Session, c: Ctx, channel: str, to: str, body: str) -> str:
    sender = c.senders.get(channel)
    ok = bool(sender and sender.send_text(to, body))
    db.add(m.Notification(channel=channel, template="forward_to_check_reply", to_encrypted=c.crypto.enc(to), payload_encrypted=c.crypto.enc(body),
                          status="sent" if ok else "unsent_not_configured" if not sender else "failed", consent_context="user_initiated_message"))
    db.commit()
    return "sent" if ok else "queued"


@router.get("/v1/channels/whatsapp/webhook", tags=["channels"])
def whatsapp_verify(request: Request, c: Ctx = Depends(ctx)):
    q = request.query_params
    if c.settings.whatsapp_verify_token and q.get("hub.mode") == "subscribe" and same(q.get("hub.verify_token", ""), c.settings.whatsapp_verify_token):
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(q.get("hub.challenge", ""))
    raise HTTPException(403, "Verification failed.")


@router.post("/v1/channels/whatsapp/webhook", tags=["channels"])
async def whatsapp_webhook(request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx)):
    body = await request.body()
    if not c.settings.whatsapp_app_secret or not channels.verify_meta_signature(c.settings.whatsapp_app_secret, body, request.headers.get("x-hub-signature-256")):
        raise HTTPException(403, "Bad signature.")
    import json
    handled = 0
    for msg in channels.parse_whatsapp(json.loads(body)):
        chk, url = _channel_check(db, c, request, msg.text, c.crypto.lookup("wa", msg.sender))
        _send_or_queue(db, c, "whatsapp", msg.sender, channels.format_reply(chk.result_json, url, max_len=900))
        handled += 1
    return {"handled": handled}                 # always 200 quickly so the platform does not retry


@router.post("/v1/channels/sms/africastalking/{secret}", tags=["channels"])
async def sms_callback(secret: str, request: Request, db: Session = Depends(get_db), c: Ctx = Depends(ctx)):
    if not c.settings.at_callback_secret or not same(secret, c.settings.at_callback_secret):
        raise HTTPException(403, "Not allowed.")
    form = dict((await request.form()).items())
    msg = channels.parse_africastalking(form)
    if not msg:
        return {"handled": 0}
    chk, url = _channel_check(db, c, request, msg.text, c.crypto.lookup("sms", msg.sender))
    _send_or_queue(db, c, "sms", msg.sender, channels.format_reply(chk.result_json, url, max_len=300))
    return {"handled": 1}
