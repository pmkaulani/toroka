"""Assessment pipeline (blueprint 6.4): gather observations in parallel, run the pure assessment, persist the evidence trail.

Connector failures are isolated: they become could_not_check in the result, never a silent pass.
"""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session
from ssi_connectors import reputation as rep, rdap, safe_fetch
from ssi_rules import (CoverageStatus, Observations, Opportunity as OppObs, ReportHit, UrlObservation, assess, load_registry)
from ssi_rules.observations import VerifiedEntity
from ssi_rules import normalize as nz
from ssi_rules.signals import Finding
from ssi_rules.vocabulary import EvidenceType, Strength

from . import db as m
from .security import Crypto

CS = CoverageStatus
_REGISTRY = load_registry()


@dataclass
class Deps:
    """Connector wiring. Empty means 'not configured', which the result reports as not_checked."""
    reputation_providers: list = field(default_factory=list)
    follow_redirects: Callable | None = None          # (url) -> RedirectResult
    domain_age: Callable | None = None                # (domain) -> (status, days)
    geocoder: object | None = None


def build_deps(settings, redirect_transport=None, rdap_transport=None, resolver=None) -> Deps:
    d = Deps()
    if settings.webrisk_api_key:
        d.reputation_providers.append(rep.WebRiskProvider(settings.webrisk_api_key))
    if settings.blocklist_path:
        import json
        d.reputation_providers.append(rep.LocalBlocklist(json.load(open(settings.blocklist_path))["entries"]))
    if settings.enable_link_fetch:
        kw = {"transport": redirect_transport}
        if resolver:
            kw["resolver"] = resolver
        d.follow_redirects = lambda u: safe_fetch.follow_redirects(u, **kw)
    if settings.enable_rdap:
        d.domain_age = lambda dom: rdap.domain_age_days(dom, transport=rdap_transport)
    if settings.geocoder_user_agent:
        from ssi_connectors.geocode import NominatimGeocoder
        d.geocoder = NominatimGeocoder(settings.geocoder_user_agent)
    return d


_SOCIAL_PLATFORMS = ("instagram", "tiktok", "facebook", "x", "whatsapp", "threads")
_SOCIAL_URL = re.compile(r"(?i)(?:https?://)?(?:www\.)?(instagram\.com|tiktok\.com|facebook\.com|x\.com|twitter\.com|threads\.net)/@?([A-Za-z0-9_.-]{2,50})(?![A-Za-z0-9_.-])")
_BARE_HANDLE = re.compile(r"(?<![\w.+-])@([A-Za-z0-9][A-Za-z0-9_.-]{1,49})\b")
_RESERVED_HANDLES = {"p", "reel", "reels", "stories", "explore", "accounts", "login", "about", "share", "intent", "hashtag", "search"}


def _identifiers(text, urls, final_hosts):
    ids = [("phone", p.normalized) for p in nz.extract_phones(text)]
    for pid in nz.extract_payment_ids(text):
        kind, val = pid.normalized.split(":")
        ids.append((kind, val))
    social_roots = {"instagram.com", "tiktok.com", "facebook.com", "x.com", "twitter.com", "threads.net"}
    ids += [("domain", d) for d in sorted(({u.registered_domain for u in urls if not u.is_ip} | set(final_hosts)) - social_roots)]
    # Exact profile URLs are platform-specific. A bare @handle is marked generic and
    # may retrieve distinct platform-specific records without merging those identities.
    handles_from_urls: set[str] = set()
    for match in _SOCIAL_URL.finditer(text or ""):
        host, handle = match.group(1).lower(), match.group(2).lower().lstrip("@")
        platform = "x" if host in {"x.com", "twitter.com"} else ("threads" if host == "threads.net" else host.split(".")[0])
        if handle not in _RESERVED_HANDLES:
            ids.append(("handle", f"{platform}:{handle}"))
            handles_from_urls.add(handle)
    for match in _BARE_HANDLE.finditer(text or ""):
        handle = match.group(1).lower().rstrip(".")
        if handle not in _RESERVED_HANDLES and handle not in handles_from_urls:
            ids.append(("handle", f"social:{handle}"))
    # Preserve order while deduplicating.
    return list(dict.fromkeys(ids))


def report_hits(db: Session, crypto: Crypto, ids) -> dict[str, ReportHit]:
    out = {}
    for kind, val in ids:
        candidates = [val]
        if kind == "handle" and val.startswith("social:"):
            handle = val.split(":", 1)[1]
            candidates = [f"{platform}:{handle}" for platform in _SOCIAL_PLATFORMS] + [val]
        for candidate in candidates:
            row = db.execute(select(m.Indicator).join(m.Subject, m.Subject.id == m.Indicator.subject_id)
                             .where(m.Subject.subject_type == kind, m.Subject.lookup_hmac == crypto.lookup(kind, candidate),
                                    m.Indicator.status.in_(["published", "under_review"]))).scalar_one_or_none()
            if row:
                out[f"{kind}:{candidate}"] = ReportHit(kind, row.independent_reports, True, row.id, row.last_reported, row.status == "under_review")
    return out


def match_opportunities(db: Session, text: str, urls) -> list[OppObs]:
    hosts = {u.registered_domain for u in urls}
    out = []
    for o in db.execute(select(m.Opportunity)).scalars():
        alias_hit = any(re.search(r"(?i)(?<![\w-])" + re.escape(a) + r"(?![\w-])", text) for a in (o.aliases or []))
        if alias_hit or o.official_domain in hosts:
            out.append(OppObs(o.id, o.official_name, o.administering_body, o.official_domain, o.application_url, o.fee_policy,
                              list(o.counties or []), o.source_url, o.last_verified_at, o.review_due, o.reviewer))
    return out


def match_verified(db: Session, text: str, finals: list[str]) -> list[VerifiedEntity]:
    """Candidate verified records for this text. assess() applies the real rules (https, exact host, in date)."""
    low = text.lower() + " " + " ".join(finals)
    out = []
    for r in db.execute(select(m.VerifiedRecord).where(m.VerifiedRecord.status == "active")).scalars():
        if any(d in low for d in (r.domains or [])) or any(h.split(":", 1)[-1] in low for h in (r.handles or [])):
            out.append(VerifiedEntity(r.id, r.name, r.entity_type, list(r.domains or []), list(r.handles or []), bool(r.include_subdomains), r.basis, r.source_url, r.last_verified_at, r.review_due, r.reviewer))
    return out


def image_leads(db: Session, check_id: str, evidence: list[tuple[str, str, int]], max_distance: int = 6) -> list[Finding]:
    """Cross-case similar-image lead. Both current and prior checks must explicitly opt in."""
    from ssi_connectors.images import hamming
    out = []
    now_iso = m.now_iso()
    current_opted_in = set(db.execute(
        select(m.EvidenceFile.dhash).where(
            m.EvidenceFile.check_id == check_id,
            m.EvidenceFile.consent_scope == "cross_case_campaign",
            m.EvidenceFile.retention_until > now_iso,
        )
    ).scalars().all())
    current_hashes = [dh for dh, _, text_len in evidence if text_len < 40 and dh in current_opted_in]
    if not current_hashes:
        return out

    stmt = (
        select(m.EvidenceFile.dhash, m.EvidenceFile.check_id)
        .join(m.Check, m.Check.id == m.EvidenceFile.check_id)
        .where(m.EvidenceFile.check_id != check_id)
        .where(m.EvidenceFile.consent_scope == "cross_case_campaign")
        .where(m.EvidenceFile.retention_until > now_iso)
        .where(m.Check.expires_at > now_iso)
        .order_by(m.EvidenceFile.created_at.desc())
        .limit(600)
    )
    current_check = db.get(m.Check, check_id)
    if current_check and current_check.user_id:
        stmt = stmt.where(m.Check.user_id != current_check.user_id)
    others = db.execute(stmt).all()
    matching_checks = set()
    for dh in current_hashes:
        for other_hash, other_check_id in others:
            try:
                if hamming(dh, other_hash) <= max_distance:
                    matching_checks.add(other_check_id)
            except (TypeError, ValueError):
                continue
    if matching_checks:
        seen = len(matching_checks)
        out.append(Finding("SIMILAR_IMAGE_SEEN_ELSEWHERE", EvidenceType.UNRESOLVED_CLAIM, Strength.WEAK,
                           f"A very similar image appears in {seen} other opted-in {'check' if seen == 1 else 'checks'}.",
                           "Both contributors opted into cross-case image-fingerprint comparison. Sellers often use supplier, catalogue or stock photos, so this is a lead to review, not proof of a problem or common ownership.", None, None, None,
                           needs_external_verification=True))
    return out


def gather(db: Session, crypto: Crypto, deps: Deps, text: str, steps: list[dict], *, budget: float = 12.0) -> Observations:
    obs = Observations()
    urls = nz.extract_urls(text)[:5]

    def per_url(u):
        o = UrlObservation(u.original)
        if deps.reputation_providers:
            o.reputation = rep.combine(deps.reputation_providers, u.original if "://" in u.original else "http://" + u.original)
        if deps.follow_redirects:
            r = deps.follow_redirects(u.original)
            o.redirect_status, o.hops = r.status, r.hops
            o.final_url = r.final_url if r.status == CS.CHECKED else None
        elif u.is_shortener:
            o.redirect_status = CS.NOT_CHECKED
        final = nz.parse_url(o.final_url) if o.final_url else None
        dom = (final or u).registered_domain
        if deps.domain_age and not u.is_ip and not u.is_shortener:
            st, days = deps.domain_age(dom)
            o.domain_facts_status, o.domain_age_days = st, days
        return u.original, o

    t0 = time.monotonic()
    steps.append({"name": "Checking links", "status": "done" if urls else "skipped"})
    if urls:
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = [ex.submit(per_url, u) for u in urls]
            for f, u in zip(futs, urls):
                try:
                    k, o = f.result(timeout=max(0.5, budget - (time.monotonic() - t0)))
                    obs.urls[k] = o
                except Exception:
                    obs.urls[u.original] = UrlObservation(u.original, rep.Reputation(CS.COULD_NOT_CHECK, "link checks") if deps.reputation_providers else None,
                                                          redirect_status=CS.COULD_NOT_CHECK if u.is_shortener else None)
                    steps[-1]["status"] = "partial"
    finals = [nz.parse_url(o.final_url).registered_domain for o in obs.urls.values() if o.final_url and nz.parse_url(o.final_url)]
    obs.verified_entities = match_verified(db, text, [(o.final_url or "") for o in obs.urls.values()])
    ids = _identifiers(text, urls, finals)
    obs.report_hits, obs.report_lookup_ran = report_hits(db, crypto, ids), True
    steps.append({"name": "Comparing identifiers with moderated reports", "status": "done"})
    obs.opportunities, obs.opportunity_lookup_ran = match_opportunities(db, text, urls), True
    steps.append({"name": "Looking for official programme records", "status": "done"})
    return obs


def persist_assessment(db: Session, check: m.Check, a, obs_steps: list[dict]):
    for model in (m.RiskSignal, m.Assessment, m.SourceObservation):
        for row in db.execute(select(model).where(model.check_id == check.id)).scalars():
            db.delete(row)
    db.flush()
    db.add(m.Assessment(check_id=check.id, status_label=a.label.value, summary=a.summary, policy_version=a.policy_version))
    for f in a.findings:
        db.add(m.RiskSignal(check_id=check.id, signal_code=f.code, severity_band=f.strength.value, provenance_type=f.evidence_type.value,
                            evidence_ref=f.source_id, rule_version=a.policy_version))
    for c in a.coverage:
        db.add(m.SourceObservation(check_id=check.id, source=c.id, claim_type=c.name[:30], result=c.status.value, detail=c.detail[:300]))
    check.risk_band, check.assessment_version = a.label.value, a.policy_version
    check.status = "completed"
    check.steps_json = obs_steps

    # Log ML telemetry for autonomous drift monitoring
    if hasattr(a, "ml_prediction") and a.ml_prediction:
        try:
            from ssi_rules.ml.drift_monitor import DriftMonitor
            mlp = a.ml_prediction
            DriftMonitor().log_prediction(
                text_length=len(getattr(check, "user_text_excerpt", None) or ""),
                predicted_category=mlp.get("primary_category", "unknown"),
                fraud_risk_score=mlp.get("fraud_risk_score", 0.5),
                confidence=mlp.get("calibrated_confidence", 1.0),
                abstained=mlp.get("abstain", False),
                model_version=mlp.get("model_version", "unknown"),
            )
        except Exception:
            pass


def jsonable(a) -> dict:
    d = asdict(a)

    def conv(x):
        if isinstance(x, dict):
            return {k: conv(v) for k, v in x.items()}
        if isinstance(x, (list, tuple)):
            return [conv(v) for v in x]
        return x.value if hasattr(x, "value") else x
    return conv(d)
