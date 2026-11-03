"""Rules-first assessment (ADR-002). No model decides the label; evidence does.

Policy v0.3
  high_risk                 a strong verified/corroborated finding, or a specific combination of directly observed
                            indicators that together closely match a high-consequence scam pattern
  suspicious_verify_first   at least one supporting-strength signal without a strong combination
  inconclusive              only weak signals, or a blocking check was not run / failed
  no_known_threats_found    nothing found and nothing blocking; never a guarantee
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from urllib.parse import urlsplit

from . import normalize as nz
from .category import detect_category
from .claims import claim_findings
from .location import counties_by_piece, extract_location_claims
from .observations import Observations, Opportunity, VerifiedEntity
from .registry import Registry, load_registry
from .shop import NO_ADVANCE_PAYMENT, SAFER_BUYING, extract_shop_profile
from .signals import TEXT_RULES, Finding, mask_credential_values, shortened_url
from .taxonomy import classify_text_threat
from .vocabulary import POLICY_VERSION, STRENGTH_ORDER, ClaimStatus, CoverageStatus, EvidenceType, Label, Strength

_RECRUITMENT = re.compile(r"(?i)\b(?:jobs?|vacanc\w+|recruit\w*|appointment|interview|trainee|employment|hiring|shortlist\w*|careers?)\b")
_CALLBACK_CTX = re.compile(r"(?i)\b(?:call|whatsapp|text|contact|piga|wasiliana|reach)\b[^.\n]{0,40}$")
MIN_CHARS = 12
NEW_DOMAIN_DAYS = 30
CS = CoverageStatus


@dataclass
class CoverageItem:
    id: str
    name: str
    status: CoverageStatus
    detail: str
    blocking: bool = False


@dataclass
class NextStep:
    text: str
    source_id: str | None = None


@dataclass
class SourceRef:
    id: str
    statement: str
    source_url: str | None
    last_verified_at: str
    review_due: str | None
    reviewer: str


@dataclass
class Assessment:
    label: Label
    summary: str
    findings: list[Finding]
    coverage: list[CoverageItem]
    next_steps: list[NextStep]
    limitations: list[str]
    entities: dict
    sensitive_data_detected: bool
    checked_at: str
    category: dict = field(default_factory=dict)
    taxonomy: dict = field(default_factory=dict)
    shop_profile: dict | None = None
    sources: list[SourceRef] = field(default_factory=list)
    verified: list[dict] = field(default_factory=list)
    policy_version: str = POLICY_VERSION
    stale_sources: list[str] = field(default_factory=list)
    ml_prediction: dict = field(default_factory=dict)


def _stale(due: str | date, today: date) -> bool:
    d = date.fromisoformat(due) if isinstance(due, str) else due
    return bool(d) and today > d


def _registry_findings(text, claimed, urls, phones, findings, reg, today, stale, sources):
    out: list[Finding] = []

    def statement_review(sid: str) -> tuple[Any, bool]:
        """Return a registry statement and whether it has a current human review."""
        st = reg.statements[sid]
        sources.setdefault(sid, SourceRef(sid, st.statement, st.source_url, st.last_verified_at.isoformat(), st.review_due().isoformat(), st.reviewer))
        reviewer = (st.reviewer or "").strip().casefold()
        is_current = not st.is_stale(today) and reviewer not in {"", "unreviewed", "pending", "system", "automatic", "auto", "none", "null"}
        if not is_current:
            stale.append(sid)
        return st, is_current

    pin = next((f for f in findings if f.code == "PIN_OR_OTP_REQUEST"), None)
    if "safaricom" in claimed and pin:
        st, current = statement_review("safaricom-never-asks-pin")
        if current:
            out.append(Finding("SAFARICOM_NEVER_ASKS_PIN", EvidenceType.VERIFIED_SOURCE, Strength.STRONG,
                               st.statement + " This message asks for one.",
                               "A current, reviewed statement from the organisation conflicts with the request. Do not provide the secret.",
                               pin.excerpt, pin.start, pin.end, source_id="safaricom-never-asks-pin", claim_status=ClaimStatus.CONTRADICTED_BY_SOURCE))
        else:
            out.append(Finding("SAFARICOM_NEVER_ASKS_PIN", EvidenceType.UNRESOLVED_CLAIM, Strength.SUPPORTING,
                               "The message claims to be from Safaricom and asks for a PIN or one-time code.",
                               "The source note in Toroka's registry has not completed a current human review, so it is not treated as verified evidence. The direct request for a secret is itself a serious warning; verify through the official app or contact details obtained independently.",
                               pin.excerpt, pin.start, pin.end, source_id="safaricom-never-asks-pin", claim_status=ClaimStatus.UNSUPPORTED))
    fee = next((f for f in findings if f.code == "ADVANCE_FEE_REQUEST"), None)
    if "kra" in claimed and fee and _RECRUITMENT.search(text):
        st, current = statement_review("kra-recruitment-no-fee")
        if current:
            out.append(Finding("KRA_NO_RECRUITMENT_FEE", EvidenceType.VERIFIED_SOURCE, Strength.STRONG,
                               st.statement + " This message asks for a payment.",
                               "A current, reviewed statement from the organisation conflicts with the request. Verify the vacancy independently before paying.",
                               fee.excerpt, fee.start, fee.end, source_id="kra-recruitment-no-fee", claim_status=ClaimStatus.CONTRADICTED_BY_SOURCE))
        else:
            out.append(Finding("KRA_NO_RECRUITMENT_FEE", EvidenceType.UNRESOLVED_CLAIM, Strength.SUPPORTING,
                               "The message claims to be a KRA recruitment offer and requests a processing or clearance fee.",
                               "Toroka has a registry note about recruitment fees, but that note has not completed a current human review and is not treated as verified evidence. The fee demand warrants caution; check the exact vacancy and payment instructions through KRA's official channels.",
                               fee.excerpt, fee.start, fee.end, source_id="kra-recruitment-no-fee", claim_status=ClaimStatus.UNSUPPORTED))
    if "safaricom" in claimed:
        official = set(reg.organisations["safaricom"].official_numbers)
        for p in phones:
            if p.normalized not in official and _CALLBACK_CTX.search(text[max(0, p.start - 45): p.start]):
                statement_review("safaricom-calls-from")
                out.append(Finding("OFFICIAL_CONTACT_MISMATCH", EvidenceType.AUTOMATED_OBSERVATION, Strength.WEAK,
                                   "The message claims to be from Safaricom but points you to a different mobile number.",
                                   reg.statements["safaricom-calls-from"].statement, text[max(0, p.start - 20): p.end].strip(),
                                   max(0, p.start - 20), p.end, source_id="safaricom-calls-from", needs_external_verification=True))
                break
    for u in urls:
        if u.is_shortener or u.is_ip:
            continue
        for oid, org in reg.organisations.items():
            official = u.registered_domain in org.official_domains
            token_hit = any(t in u.host for t in org.brand_tokens)
            if token_hit and not official:
                out.append(Finding("LOOKALIKE_DOMAIN", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                                   f"The link uses the name {org.display_name} but is not on a domain we have on record for it.",
                                   f"Domains on record for {org.display_name}: {', '.join(org.official_domains)}. The list is not exhaustive.",
                                   text[u.start:u.end], u.start, u.end, needs_external_verification=True))
                break
            if oid in claimed and not official:
                out.append(Finding("OFFICIAL_DOMAIN_MISMATCH", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                                   f"The message names {org.display_name} but links to a different site.",
                                   f"Domains on record for {org.display_name}: {', '.join(org.official_domains)}. The list is not exhaustive.",
                                   text[u.start:u.end], u.start, u.end, needs_external_verification=True))
                break
    return out


def _observation_findings(text, urls, obs: Observations, findings, today, stale, sources, reg, claimed):
    out: list[Finding] = []
    for u in urls:
        o = obs.urls.get(u.original)
        if not o:
            continue
        rep = o.reputation
        if rep and rep.status == CS.CHECKED and rep.threat_types:
            sid = f"reputation:{rep.source}"
            sources.setdefault(sid, SourceRef(sid, f"{rep.source} lists this link as: {', '.join(rep.threat_types)}", None,
                                              rep.observed_at or "", rep.valid_until, "automated source"))
            out.append(Finding("THREAT_FEED_MATCH", EvidenceType.VERIFIED_SOURCE, Strength.STRONG,
                               f"The link matches a known threat listing ({', '.join(rep.threat_types).lower().replace('_', ' ')}) from {rep.source}.",
                               "Threat lists are not exhaustive, but a match is strong evidence the page is harmful.",
                               text[u.start:u.end], u.start, u.end, source_id=sid))
        if o.final_url:
            fin = nz.parse_url(o.final_url, u.start, u.end)
            if fin and fin.registered_domain != u.registered_domain:
                out.append(Finding("REDIRECTS_TO_DIFFERENT_SITE", EvidenceType.AUTOMATED_OBSERVATION, Strength.WEAK,
                                   f"The link leads to a different site ({fin.registered_domain}).",
                                   "Redirects are common and often harmless. What matters is whether the final site matches who the message says it is from.",
                                   text[u.start:u.end], u.start, u.end))
            if fin:
                for oid, org in reg.organisations.items():
                    official = fin.registered_domain in org.official_domains
                    if any(t in fin.host for t in org.brand_tokens) and not official:
                        out.append(Finding("LOOKALIKE_DOMAIN", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                                           f"The link leads to a site using the name {org.display_name} that is not on a domain we have on record for it.",
                                           f"Domains on record: {', '.join(org.official_domains)}. The list is not exhaustive.",
                                           text[u.start:u.end], u.start, u.end, needs_external_verification=True))
                        break
                    if oid in claimed and not official:
                        out.append(Finding("OFFICIAL_DOMAIN_MISMATCH", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                                           f"The message names {org.display_name} but the link leads to a different site.",
                                           f"Domains on record: {', '.join(org.official_domains)}. The list is not exhaustive.",
                                           text[u.start:u.end], u.start, u.end, needs_external_verification=True))
                        break
        if o.domain_age_days is not None and o.domain_age_days < NEW_DOMAIN_DAYS:
            out.append(Finding("NEW_DOMAIN", EvidenceType.AUTOMATED_OBSERVATION, Strength.WEAK,
                               f"The website's domain was registered {o.domain_age_days} days ago.",
                               "New sites are common for genuine small businesses too, so this is only a weak signal.",
                               text[u.start:u.end], u.start, u.end))
    return out


_KIND_WORD = {"phone": "phone number", "till": "Till number", "paybill": "Paybill number", "domain": "website", "handle": "social-media handle"}


def _report_findings(obs: Observations, sources):
    out = []
    for key, hit in obs.report_hits.items():
        if not hit.published or hit.independent_reports < 1:
            continue
        sid = f"indicator:{hit.indicator_id or key}"
        strength = Strength.WEAK if hit.under_review else (Strength.STRONG if hit.independent_reports >= 3 else Strength.SUPPORTING)
        note = " This entry is under review after a correction or appeal request." if hit.under_review else ""
        sources.setdefault(sid, SourceRef(sid, f"Moderated indicator: {hit.independent_reports} independent reports; last reported {hit.last_reported or 'unknown'}.",
                                          None, hit.last_reported or "", None, "moderators"))
        described = _KIND_WORD.get(hit.kind, "identifier")
        if hit.kind == "handle" and key.startswith("handle:"):
            _, platform, handle = (key.split(":", 2) + [""])[:3]
            if platform and platform != "social":
                described = f"{platform.title()} handle @{handle}"
            elif handle:
                described = f"social-media handle @{handle} (platform unspecified)"
        out.append(Finding({"phone": "REPORTED_PHONE_NUMBER", "domain": "REPORTED_DOMAIN", "handle": "REPORTED_SOCIAL_HANDLE"}.get(hit.kind, "REPORTED_PAYMENT_DESTINATION"),
                           EvidenceType.MODERATED_REPORT, strength,
                           f"{hit.independent_reports} independent {'report' if hit.independent_reports == 1 else 'reports'}, reviewed by moderators, mention this {described}.{note}",
                           "Reports are claims from users that moderators have reviewed. They are not a court finding, and the owner may dispute them. A matching handle on another platform may belong to a different account; check the exact profile URL.",
                           None, None, None, source_id=sid))
    return out


def _opportunity_findings(text, urls, obs: Observations, findings, today, stale, sources, county_claims):
    out = []
    fee = next((f for f in findings if f.code == "ADVANCE_FEE_REQUEST"), None)
    for opp in obs.opportunities:
        sid = f"opportunity:{opp.id}"
        sources.setdefault(sid, SourceRef(sid, f"{opp.official_name} ({opp.administering_body}). Official domain: {opp.official_domain}.",
                                          opp.source_url, opp.last_verified_at, opp.review_due, opp.reviewer))
        is_stale = bool(opp.review_due) and _stale(opp.review_due, today)
        if is_stale:
            stale.append(sid)
        strong = Strength.SUPPORTING if is_stale else Strength.STRONG
        if fee and opp.fee_policy == "no_fee":
            out.append(Finding("PROGRAMME_FEE_CONTRADICTION", EvidenceType.VERIFIED_SOURCE, strong,
                               f"The official record for {opp.official_name} says no fee is charged, but this message asks for a payment.",
                               "A message that conflicts with the programme's own published rule is a strong reason not to act on it.",
                               fee.excerpt, fee.start, fee.end, source_id=sid, claim_status=ClaimStatus.CONTRADICTED_BY_SOURCE))
        for u in urls:
            if not u.is_shortener and u.registered_domain != opp.official_domain:
                out.append(Finding("PROGRAMME_DOMAIN_MISMATCH", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                                   f"The link is not on the official domain for {opp.official_name} ({opp.official_domain}).",
                                   "Open the official site by typing its address yourself, then look for the same opportunity there.",
                                   text[u.start:u.end], u.start, u.end, source_id=sid, needs_external_verification=True))
                break
        if opp.counties and county_claims and not (set(opp.counties) & {c for _, c in county_claims}):
            out.append(Finding("PROGRAMME_COUNTY_MISMATCH", EvidenceType.AUTOMATED_OBSERVATION, Strength.SUPPORTING,
                               f"The message names a county that is not listed for {opp.official_name}.",
                               "County and constituency schemes have specific eligibility. Check the official record.",
                               None, None, None, source_id=sid, needs_external_verification=True))
    return out


BASIS_TEXT = {"official_registry": "from the organisation's own published information", "official_self_declaration": "from the organisation's own published information",
              "government_register": "against a government register", "regulator_list": "against a regulator's list", "moderator_verified_documents": "by moderators, from the business's documents"}


def _entity_has_valid_review_provenance(e: VerifiedEntity) -> bool:
    """Validate that the record has a real human-review trail, independent of freshness."""
    reviewer = (e.reviewer or "").strip().casefold()
    if reviewer in {"", "unreviewed", "pending", "system", "automatic", "auto", "none", "null"}:
        return False
    try:
        date.fromisoformat(str(e.last_verified_at)[:10])
        date.fromisoformat(str(e.review_due)[:10])
        src = urlsplit(e.source_url or "")
    except (TypeError, ValueError):
        return False
    if src.scheme != "https" or not src.hostname or src.username or src.password:
        return False
    return bool(e.domains or e.handles)


def _entity_is_currently_reviewed(e: VerifiedEntity, today: date) -> bool:
    """Only a dated, human-reviewed, HTTPS-sourced record within its review window may verify an entity."""
    if not _entity_has_valid_review_provenance(e):
        return False
    try:
        last_verified = date.fromisoformat(str(e.last_verified_at)[:10])
        review_due = date.fromisoformat(str(e.review_due)[:10])
    except (TypeError, ValueError):
        return False
    return last_verified <= today and review_due >= today


def _host_ok(host: str, e: VerifiedEntity) -> bool:
    return any(host == d or host == "www." + d or (e.include_subdomains and host.endswith("." + d)) for d in e.domains)


def _verified(text, urls, shop, obs: Observations, today, stale, sources):
    """Positive findings from reviewed records. A link counts only if it is https (or bare), not an IP/punycode/credentialed address, and the record is in date."""
    pos, matches, total, ok = [], [], 0, 0

    def record(e, host, kind, start, end):
        sid = f"verified:{e.id}"
        sources.setdefault(sid, SourceRef(sid, f"{e.name}: official {e.entity_type.replace('_', ' ')} ({', '.join(e.domains + e.handles)}). Verified {BASIS_TEXT.get(e.basis, e.basis)}.", e.source_url or None, e.last_verified_at, e.review_due, e.reviewer))
        what = f"{host} is the official website of {e.name}." if kind == "site" else f"The {host} is the verified shop of {e.name}."
        pos.append(Finding("VERIFIED_OFFICIAL_SITE" if kind == "site" else "VERIFIED_OFFICIAL_SHOP", EvidenceType.VERIFIED_SOURCE, Strength.STRONG, what,
                           f"Verified {BASIS_TEXT.get(e.basis, e.basis)} on {e.last_verified_at}. A genuine website does not make every offer or message in its name genuine.",
                           text[start:end] if end else None, start if end else None, end if end else None, source_id=sid, polarity="positive"))
        matches.append({"id": e.id, "name": e.name, "type": e.entity_type, "basis": e.basis, "matched_on": host, "source_url": e.source_url, "verified_at": e.last_verified_at, "review_due": e.review_due})

    def note_unreviewed_match(e: VerifiedEntity, label: str) -> None:
        sid = f"verified:{e.id}"
        reviewer = (e.reviewer or "").strip().casefold()
        reason = "no completed human review"
        try:
            if reviewer not in {"", "unreviewed", "pending", "system", "automatic", "auto", "none", "null"}:
                last_verified = date.fromisoformat(str(e.last_verified_at)[:10])
                review_due = date.fromisoformat(str(e.review_due)[:10])
                if last_verified > today:
                    reason = "verification date is in the future"
                elif _stale(review_due, today):
                    reason = f"review expired on {review_due.isoformat()}"
                else:
                    parts = urlsplit(e.source_url or "")
                    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
                        reason = "source or review provenance is incomplete"
            else:
                review_due = None
        except (TypeError, ValueError):
            reason = "review dates are missing or invalid"
        stale.append(sid)
        domains_handles = ", ".join(e.domains + e.handles)
        sources.setdefault(sid, SourceRef(
            sid,
            f"Prior registry entry for {e.name} ({domains_handles}); not used as current verification because it has {reason}.",
            e.source_url or None, e.last_verified_at or None, e.review_due or None, e.reviewer or "unreviewed",
        ))

    for u in urls:
        o = obs.urls.get(u.original)
        fin = nz.parse_url(o.final_url, u.start, u.end) if (u.is_shortener and o and o.final_url and o.redirect_status == CS.CHECKED) else None
        total += 1
        if u.is_shortener and not fin:
            continue
        t = fin or u
        raw = (o.final_url if fin else u.original) or ""
        if t.is_ip or t.is_punycode or t.has_userinfo or raw.lower().startswith("http://"):
            continue
        stale_candidates = []
        matched_current = False
        for e in obs.verified_entities:
            if not _host_ok(t.host, e):
                continue
            if not _entity_has_valid_review_provenance(e):
                stale_candidates.append(e)
                continue
            if _stale(e.review_due, today):
                stale_candidates.append(e)
                continue
            if not _entity_is_currently_reviewed(e, today):
                stale_candidates.append(e)
                continue
            ok += 1
            record(e, t.host, "site", u.start, u.end)
            matched_current = True
            break
        if not matched_current and stale_candidates:
            # Surface the strongest matching stale candidate, but never let it verify the site.
            note_unreviewed_match(stale_candidates[0], t.host)

    handle_ok = False
    if shop and shop.handle and total == 0:
        key = f"{shop.platform}:{shop.handle}".lower()
        stale_candidates = []
        for e in obs.verified_entities:
            if key not in [h.lower() for h in e.handles]:
                continue
            if not _entity_has_valid_review_provenance(e) or _stale(e.review_due, today) or not _entity_is_currently_reviewed(e, today):
                stale_candidates.append(e)
                continue
            handle_ok = True
            record(e, f"{shop.platform} account @{shop.handle}", "shop", 0, 0)
            break
        if not handle_ok and stale_candidates:
            note_unreviewed_match(stale_candidates[0], f"{shop.platform} account @{shop.handle}")
    return pos, matches, bool((total and total == ok) or handle_ok)


def _coverage(claimed, urls, phones, payment_ids, findings, reg, obs: Observations, category, shop, county_claims, hosts) -> list[CoverageItem]:
    cov = [CoverageItem("text_rules", "Phrase and pattern rules", CS.CHECKED, f"Rules {POLICY_VERSION}.")]
    if claimed:
        names = ", ".join(reg.organisations[o].display_name for o in sorted(claimed))
        cov.append(CoverageItem("official_statements", "Official statements on record", CS.CHECKED,
                                f"Organisations recognised in the message: {names}. The registry currently covers only "
                                f"{', '.join(o.display_name for o in reg.organisations.values())}."))
        cov.append(CoverageItem("live_official_page", "Organisation's live website and notices", CS.NOT_CHECKED,
                                "We did not open the organisation's current pages."))
    if category in ("job", "grant"):
        if obs.opportunity_lookup_ran and obs.opportunities:
            cov.append(CoverageItem("official_programmes", "Official programme records", CS.CHECKED,
                                    "Matched: " + "; ".join(o.official_name for o in obs.opportunities) + "."))
        elif obs.opportunity_lookup_ran:
            cov.append(CoverageItem("official_programmes", "Official programme records", CS.NOT_FOUND,
                                    "No matching programme in the records we hold. That means not independently verified, not that it does not exist."))
        else:
            cov.append(CoverageItem("official_programmes", "Official programme records", CS.NOT_CHECKED, "The programme records were not consulted."))
    if urls:
        reps = [obs.urls[u.original].reputation for u in urls if u.original in obs.urls and obs.urls[u.original].reputation]
        if len(reps) < len(urls):
            cov.append(CoverageItem("url_reputation", "Link reputation", CS.NOT_CHECKED, "No link-reputation source is connected for this link.", blocking=True))
        elif any(r.status != CS.CHECKED for r in reps):
            cov.append(CoverageItem("url_reputation", "Link reputation", CS.COULD_NOT_CHECK, "The link-reputation source did not answer. Try again later.", blocking=True))
        else:
            cov.append(CoverageItem("url_reputation", "Link reputation", CS.CHECKED,
                                    "No match in: " + ", ".join(sorted({r.source for r in reps})) + ". Lists are not exhaustive." if not any(r.threat_types for r in reps) else
                                    "Matched in: " + ", ".join(sorted({r.source for r in reps if r.threat_types})) + "."))
        cov.append(CoverageItem("official_domain_check", "Link against official domains on record", CS.CHECKED, "Compared each link's domain with domains on record."))
        short = [u for u in urls if u.is_shortener]
        if short:
            st = [obs.urls[u.original].redirect_status for u in short if u.original in obs.urls]
            if len(st) == len(short) and all(s == CS.CHECKED for s in st):
                cov.append(CoverageItem("redirect_destination", "Where the shortened link leads", CS.CHECKED, "Followed the redirect safely, without opening the page."))
            else:
                bad = CS.COULD_NOT_CHECK if any(s == CS.COULD_NOT_CHECK for s in st) else CS.NOT_CHECKED
                cov.append(CoverageItem("redirect_destination", "Where the shortened link leads", bad, "We did not get to the final destination.", blocking=True))
        social_roots = {"instagram.com", "tiktok.com", "facebook.com", "x.com", "twitter.com", "threads.net"}
        non_social_urls = [u for u in urls if u.registered_domain not in social_roots]
        if non_social_urls:
            facts = [obs.urls[u.original].domain_facts_status for u in non_social_urls if u.original in obs.urls and obs.urls[u.original].domain_facts_status]
            cov.append(CoverageItem("domain_facts", "Website registration facts", CS.CHECKED if facts and all(f == CS.CHECKED for f in facts) else
                                    (CS.COULD_NOT_CHECK if facts else CS.NOT_CHECKED), "Registration age and similar facts. Not proof either way."))
    if payment_ids or any(f.code == "PAYMENT_TO_MOBILE_NUMBER" for f in findings):
        cov.append(CoverageItem("payment_destination", "Who owns the payment destination", CS.NOT_CHECKED,
                                "We cannot see who owns a Till, Paybill or phone number.", blocking=True))
    if phones or payment_ids or hosts:
        if obs.report_lookup_ran:
            hit = any(h.published for h in obs.report_hits.values())
            cov.append(CoverageItem("number_reports", "Moderated user reports", CS.CHECKED if hit else CS.NOT_FOUND,
                                    "Published indicators were found." if hit else "No published reports. That is not proof of anything."))
        else:
            cov.append(CoverageItem("number_reports", "Moderated user reports", CS.NOT_CHECKED, "Reports were not consulted."))
    if county_claims:
        g = [obs.geocodes[c] for _, c in county_claims if c in obs.geocodes]
        cov.append(CoverageItem("address_lookup", "Whether the claimed place exists", CS.CHECKED if g and all(x.status == CS.CHECKED for x in g) else CS.NOT_CHECKED,
                                "A real address can be copied, so this is context, not proof."))
    if shop:
        cov.append(CoverageItem("platform_profile", "The seller's page on the platform", CS.NOT_CHECKED,
                                "Most social platforms do not allow checks without their approval. We analyse only what you submit."))
    for e in obs.extra_coverage:
        cov.append(CoverageItem(e["id"], e["name"], CS(e["status"]), e["detail"], e.get("blocking", False)))
    return cov


_SUMMARY = {
    Label.HIGH_RISK: "High risk. {lead} Do not pay or share anything until you have checked with the organisation yourself.",
    Label.SUSPICIOUS_VERIFY_FIRST: "Suspicious. Verify first. {lead} This is not proof of fraud, and some real organisations do ask for similar things.",
    Label.INCONCLUSIVE: "We couldn't confirm this either way. {lead}",
    Label.NO_KNOWN_THREATS_FOUND: "No known threats found in the checks we ran. That is not a guarantee that the message is genuine.",
    Label.VERIFIED_OFFICIAL: "Verified. {lead} That means the site is genuine, not that every offer made in its name is. Verify the specific offer and payment recipient.",
}
_HIGH_EVIDENCE = (EvidenceType.VERIFIED_SOURCE, EvidenceType.MODERATED_REPORT)


def assess(text: str, *, now: datetime | None = None, registry: Registry | None = None, observations: Observations | None = None,
           pieces: dict[str, str] | None = None, category_hint: str | None = None) -> Assessment:
    reg = registry or load_registry()
    obs = observations or Observations()
    now = now or datetime.now(timezone.utc)
    today: date = now.date()
    safe, had_cred = mask_credential_values(text)
    safe_pieces = {k: mask_credential_values(v)[0] for k, v in (pieces or {}).items()}

    urls = nz.extract_urls(safe)
    phones = nz.extract_phones(safe)
    payment_ids = nz.extract_payment_ids(safe)
    amounts = nz.extract_amounts(safe)
    claimed = {oid for oid, o in reg.organisations.items() if o.alias_regex().search(safe)}
    guess = detect_category(safe, urls, phones, payment_ids)
    category = category_hint or guess.suggested
    county_claims = extract_location_claims(safe)
    shop = extract_shop_profile(safe)
    if shop and category in ("message", "website", "payment") and not category_hint:
        category = "shop"
    hosts = sorted({u.registered_domain for u in urls if not u.is_ip})

    findings: list[Finding] = []
    for rule in TEXT_RULES:
        findings += rule(safe)
    findings += claim_findings(safe)
    findings += shortened_url(urls, safe)
    stale: list[str] = []
    sources: dict[str, SourceRef] = {}
    findings += _registry_findings(safe, claimed, urls, phones, findings, reg, today, stale, sources)
    findings += _observation_findings(safe, urls, obs, findings, today, stale, sources, reg, claimed)
    findings += _report_findings(obs, sources)
    findings += _opportunity_findings(safe, urls, obs, findings, today, stale, sources, county_claims)
    findings += list(obs.extra_findings)
    pos, vmatches, v_all = _verified(safe, urls, shop, obs, today, stale, sources)
    findings += pos

    from .specialist_rules import evaluate_specialist_rules
    domain_val = hosts[0] if hosts else None
    path_val = urlsplit(urls[0].original).path if urls else None
    findings += evaluate_specialist_rules(safe, category, urls=urls, domain=domain_val, path=path_val)
    if obs.opportunity_lookup_ran and category in ("job", "grant") and not obs.opportunities and not any(f.code == "KRA_NO_RECRUITMENT_FEE" for f in findings):
        findings.append(Finding("OFFICIAL_SOURCE_NOT_FOUND", EvidenceType.UNRESOLVED_CLAIM, Strength.WEAK,
                                "We could not independently verify this programme or vacancy from an official source we hold.",
                                "A failed search is not proof it does not exist. Find the official site yourself and look for the same opportunity there.",
                                None, None, None, needs_external_verification=True))
    if safe_pieces:
        by_piece = counties_by_piece(safe_pieces)
        if len({c for s in by_piece.values() for c in s}) > 1 and len(by_piece) > 1 and len({frozenset(s) for s in by_piece.values()}) > 1:
            findings.append(Finding("LOCATION_CLAIMS_DIFFER", EvidenceType.AUTOMATED_OBSERVATION, Strength.WEAK,
                                    "The pieces you submitted name different places.",
                                    "Businesses can have several branches or deliver from elsewhere, so this is only a reason to ask where the goods really are.",
                                    None, None, None, needs_external_verification=True))
    for place, g in obs.geocodes.items():
        if g.status == CS.CHECKED and g.found is False:
            findings.append(Finding("PLACE_NOT_FOUND", EvidenceType.AUTOMATED_OBSERVATION, Strength.WEAK,
                                    f"A map search for {place} found nothing.",
                                    "Map data is incomplete, and a real address can be copied, so this proves little either way.", None, None, None))
    # A specific combination of a promised payout and an explicit upfront release fee is
    # materially stronger than either weak clue alone. Treat it as HIGH RISK (not as
    # confirmed fraud), while preserving the exact observed fee excerpt and limitations.
    finding_codes = {f.code for f in findings}
    has_payout_fee_combo = (
        "REDEMPTION_PAYOUT_TRAP" in finding_codes
        and bool(finding_codes & {"ADVANCE_FEE_REQUEST", "ADVANCE_PAYMENT_REQUEST"})
    )
    has_diplomatic_parcel_fee_combo = (
        "DIPLOMATIC_PARCEL_CUSTOMS_TRAP" in finding_codes
        and bool(finding_codes & {"ADVANCE_FEE_REQUEST", "ADVANCE_PAYMENT_REQUEST"})
    )
    if has_payout_fee_combo or has_diplomatic_parcel_fee_combo:
        fee_finding = next((f for f in findings if f.code in {"ADVANCE_FEE_REQUEST", "ADVANCE_PAYMENT_REQUEST"}), None)
        combo_code = "ADVANCE_FEE_PAYOUT_COMBINATION" if has_payout_fee_combo else "PARCEL_RELEASE_FEE_COMBINATION"
        combo_text = (
            "The submitted content combines a promised payout with a request to pay a fee before release."
            if has_payout_fee_combo else
            "The submitted content combines an overseas/diplomatic parcel story with a request to pay a release fee."
        )
        combo_why = (
            "This combination closely matches a recognised advance-fee scam pattern. It is a high-risk warning, not independent proof of the sender's identity or that the promised payout is fictitious. Verify the issuer and payment recipient through independently found official channels."
            if has_payout_fee_combo else
            "This combination closely matches a known parcel-release advance-fee scam pattern. It is a high-risk warning, not independent proof of who sent the message or whether a parcel exists. Verify the courier and fee directly through independently found official channels."
        )
        if not any(f.code == combo_code for f in findings):
            findings.append(Finding(
                combo_code, EvidenceType.AUTOMATED_OBSERVATION, Strength.STRONG,
                combo_text, combo_why,
                fee_finding.excerpt if fee_finding else None,
                fee_finding.start if fee_finding else None,
                fee_finding.end if fee_finding else None,
                needs_external_verification=True,
            ))

    risk = [f for f in findings if f.polarity == "risk"]
    coverage = _coverage(claimed, urls, phones, payment_ids, findings, reg, obs, category, shop, county_claims, hosts)
    verified_ok = v_all and not any(STRENGTH_ORDER[f.strength] >= STRENGTH_ORDER[Strength.SUPPORTING] for f in risk)
    blocking = [c for c in coverage if c.blocking and c.status != CS.CHECKED and not (verified_ok and c.id == "url_reputation")]

    if (any(f.evidence_type in _HIGH_EVIDENCE and f.strength == Strength.STRONG for f in risk)
            or any(f.code in {"ADVANCE_FEE_PAYOUT_COMBINATION", "PARCEL_RELEASE_FEE_COMBINATION", "PIN_OR_OTP_REQUEST"} for f in risk)):
        label = Label.HIGH_RISK
    elif any(STRENGTH_ORDER[f.strength] >= STRENGTH_ORDER[Strength.SUPPORTING] for f in risk):
        label = Label.SUSPICIOUS_VERIFY_FIRST
    elif verified_ok and not blocking:
        label = Label.VERIFIED_OFFICIAL
    elif risk or blocking or len(safe.strip()) < MIN_CHARS:
        label = Label.INCONCLUSIVE
    else:
        label = Label.NO_KNOWN_THREATS_FOUND
    pos_first = label == Label.VERIFIED_OFFICIAL
    findings.sort(key=lambda f: ((-1 if pos_first else 1) if f.polarity == "positive" else 0, -STRENGTH_ORDER[f.strength], 0 if f.evidence_type == EvidenceType.VERIFIED_SOURCE else 1, f.start if f.start is not None else 999999))

    lead = findings[0].plain_text if findings else (
        "There was too little text to check." if len(safe.strip()) < MIN_CHARS else
        ("; ".join(c.name.lower() + (" was not checked" if c.status == CS.NOT_CHECKED else " could not be checked") for c in blocking[:2]).capitalize() + ".") if blocking else "")
    if any(f.code == "REPORTED_FRAUD_INCIDENT" for f in findings):
        summary = "Reported Incident. You reported paying for goods or services that were not delivered, or being defrauded. Take immediate steps to attempt payment reversal and report this seller."
    elif label == Label.INCONCLUSIVE and any(f.code == "GAMBLING_BONUS_PROMOTION" for f in findings):
        summary = ("This appears to be a betting or casino promotion, not proof that you have won cash. "
                   "The sender and offer could not be authenticated from the submitted message. If you did not request it, treat it as unsolicited marketing and do not follow its link or register just to claim the bonus.")
    elif label == Label.HIGH_RISK and any(f.code == "ADVANCE_FEE_PAYOUT_COMBINATION" for f in findings):
        summary = ("High risk: the submitted content combines a promised payout with a request to pay an upfront fee before release. "
                   "This closely matches a recognised advance-fee scam pattern, but it does not independently prove the sender's identity or that the payout is fictitious.")
    elif label == Label.HIGH_RISK and any(f.code == "PARCEL_RELEASE_FEE_COMBINATION" for f in findings):
        summary = ("High risk: the submitted content combines an overseas/diplomatic parcel story with a demand for a release fee. "
                   "This closely matches a known advance-fee scam pattern, but the sender and parcel have not been independently verified.")
    elif label == Label.SUSPICIOUS_VERIFY_FIRST and any(f.code == "REDEMPTION_PAYOUT_TRAP" for f in findings) and any(f.code == "ADVANCE_FEE_REQUEST" for f in findings):
        summary = ("Suspicious: the submitted content appears to request an upfront fee before a promised payout is released. "
                   "That is a recognised advance-fee warning pattern. This check cannot independently verify the issuer or the promised payout.")
    else:
        summary = _SUMMARY[label].format(lead=lead).replace("  ", " ").strip()

    limitations = ["This check reads only what you submitted. It cannot tell who actually sent it; sender names and caller IDs can be faked.",
                   "It did not contact the sender or open live websites on your behalf."]
    if stale:
        limitations.append("Some matching source or identity records are stale, unreviewed, or lack a complete review trail, so they were not treated as current verification: " + ", ".join(sorted(set(stale))) + ".")
    if had_cred:
        limitations.append("A PIN-like or code-like value was hidden from this result and is not stored.")
    for c in coverage:
        if c.status == CS.COULD_NOT_CHECK:
            limitations.append(f"{c.name} could not be checked this time.")

    official_numbers = {n for o in reg.organisations.values() for n in o.official_numbers}
    has_imgs = bool(safe_pieces and any(k.startswith("screenshot") for k in safe_pieces))
    corrob_count = sum(r.independent_reports for r in obs.report_hits.values()) if obs.report_hits else 0
    threat_tax = classify_text_threat(
        safe,
        urls=urls,
        phones=phones,
        payment_ids=payment_ids,
        shop_profile=shop,
        has_images=has_imgs,
        is_verified_source=bool(vmatches),
        corroborated_reports_count=corrob_count,
    )

    taxonomy_output = threat_tax.as_dict()
    # Expose the final evidence-policy label consistently; the taxonomy's pattern severity
    # is not allowed to contradict the assessment displayed to the user.
    taxonomy_output["risk_band"] = label.value
    if any(f.code in {"ADVANCE_FEE_PAYOUT_COMBINATION", "PARCEL_RELEASE_FEE_COMBINATION"} for f in findings):
        taxonomy_output["confidence"] = "strong"

    # Layer B: Machine Learning Pattern & Risk Prediction (informs assessment without overriding verified evidence)
    ml_output: dict = {}
    try:
        from .ml.model_registry import get_active_model
        clf = get_active_model()
        pred = clf.predict(safe)
        pred.disagreement_with_rules = bool(
            (pred.fraud_risk_score >= 0.70 and label in (Label.NO_KNOWN_THREATS_FOUND, Label.INCONCLUSIVE))
            or (pred.fraud_risk_score <= 0.20 and label in (Label.HIGH_RISK, Label.SUSPICIOUS_VERIFY_FIRST))
        )
        ml_output = pred.to_dict()
    except Exception:
        pass

    return Assessment(
        label=label, summary=summary, findings=findings, coverage=coverage,
        next_steps=_next_steps(label, claimed, findings, had_cred, reg, category, shop, vmatches), limitations=limitations,
        entities={"phones": [p.normalized if p.normalized in official_numbers else nz.mask_phone(p.normalized) for p in phones],
                  "link_hosts": sorted({u.host for u in urls}), "amounts_ksh": [a.normalized for a in amounts],
                  "payment_ids": [p.normalized for p in payment_ids], "claimed_organisations": sorted(claimed),
                  "claimed_counties": [c for _, c in county_claims],
                  "correlations": threat_tax.entity_correlations},
        sensitive_data_detected=had_cred, checked_at=now.isoformat(),
        category={"suggested": guess.suggested, "used": category, "alternatives": guess.alternatives,
                  "primary_domain": threat_tax.primary_domain.value,
                  "secondary_domains": [d.value for d in threat_tax.secondary_domains],
                  "matched_patterns": [p.id for p in threat_tax.matched_patterns],
                  "workflow": threat_tax.suggested_workflow.value,
                  "indicators": threat_tax.indicators_detected},
        taxonomy=taxonomy_output,
        shop_profile=shop.as_dict() if shop else None, sources=sorted(sources.values(), key=lambda s: s.id), stale_sources=sorted(set(stale)),
        verified=vmatches if label == Label.VERIFIED_OFFICIAL else [],
        ml_prediction=ml_output)


def _next_steps(label, claimed, findings, had_cred, reg, category, shop, vmatches=()) -> list[NextStep]:
    if any(f.code == "GAMBLING_BONUS_PROMOTION" for f in findings):
        # A promotion is not automatically fraudulent, but a recipient who did not
        # request it should not be directed to ask the sender for confirmation.
        steps = [
            NextStep("A free-bet or casino bonus is not cash or a guaranteed prize. If you did not request it, do not click a link, register, deposit, or share personal or account details just to claim it."),
            NextStep("The wording and opt-out code do not authenticate the sender or offer. If these messages are unwanted, use your mobile provider's official app or menu to manage promotional messages; on Safaricom, open *456# yourself rather than following instructions from the SMS."),
            NextStep("Keep the sender ID and a screenshot. Report repeated unsolicited messages to your mobile provider; if the issue is not resolved, escalate it to the Communications Authority of Kenya."),
        ]
        if had_cred:
            steps.insert(0, NextStep("Never share a PIN or one-time code. If you already shared one, contact the relevant provider immediately using official contact details."))
        return steps
    if any(f.code == "REPORTED_FRAUD_INCIDENT" for f in findings):
        return [
            NextStep("Stop all further payments to this seller. Do not pay any extra 'delivery', 'customs', or 'clearance' fees."),
            NextStep("If you paid via M-PESA, call Safaricom immediately on 234 or 100 to report the transaction as fraud and request an urgent reversal."),
            NextStep("Save all evidence: keep your M-PESA confirmation SMS, seller phone or Till number, and chat screenshots."),
            NextStep("Report this seller on Toroka using the 'Report this' button below to alert other buyers.")
        ]
    steps: list[NextStep] = []
    if label == Label.VERIFIED_OFFICIAL:
        return [NextStep("Open the site by typing its address yourself, or from the organisation's official app, and check it matches exactly: " + ", ".join(sorted({m['matched_on'] for m in vmatches})) + ". Copies of genuine sites exist."),
                NextStep("Keep order confirmations and receipts, and contact them only through the details listed on their official site.")]
    if had_cred:
        steps.append(NextStep("Never share a PIN or one-time code. If you already did, contact your provider now using the number on its official website or app."))
    if label in (Label.HIGH_RISK, Label.SUSPICIOUS_VERIFY_FIRST):
        steps.append(NextStep("Do not pay or reply yet. Contact the organisation using a website or number you look up yourself, not the one in the message."))
    if label == Label.INCONCLUSIVE:
        steps.append(NextStep("Ask the sender for details and confirm with the organisation through its official channels before acting."))
    if label == Label.NO_KNOWN_THREATS_FOUND:
        steps.append(NextStep("If money or personal details are involved, still confirm through the organisation's official channels."))
    if category in ("job", "recruitment_overseas"):
        if label != Label.NO_KNOWN_THREATS_FOUND:
            steps.append(NextStep("Open the organisation's official website by typing its address yourself and look for the same vacancy. Do not use links from the message."))
        steps.append(NextStep("Never share email passwords, OTPs, or M-PESA PINs. Legitimate employers never ask for your account password."))
        steps.append(NextStep("Never pay upfront application, registration, medical, visa or processing fees before contracts are confirmed."))
        steps.append(NextStep("Verify recruitment agencies and foreign employment permits with the National Employment Authority (NEA) via diaspora.go.ke/verify."))
        steps.append(NextStep("For US employment, an authorized employer must file an approved petition with USCIS (uscis.gov) before a work visa can be issued."))
    elif category in ("grant", "government_grants"):
        if label != Label.NO_KNOWN_THREATS_FOUND:
            steps.append(NextStep("Open the organisation's official website by typing its address yourself and look for the same programme. Do not use links from the message."))
        steps.append(NextStep("All genuine Kenyan government funds and grants operate exclusively on '.go.ke' domains. Never register on third-party sites."))
        steps.append(NextStep("Official government grants do not require an upfront fee for processing or disbursement."))
    elif category in ("prize", "prize_winnings"):
        steps.append(NextStep("Legitimate lotteries and prize promotions never ask for upfront release fees, taxes, or delivery charges."))
    elif shop:
        steps += [NextStep(s) for s in SAFER_BUYING[:3]]
    elif category == "shop" and label != Label.HIGH_RISK:
        steps.append(NextStep(NO_ADVANCE_PAYMENT))
    if any(f.code.startswith("REPORTED_") for f in findings):
        steps.append(NextStep("If you own this number or site and believe the entry is wrong, use the correction option on this page."))
    if "safaricom" in claimed and label != Label.NO_KNOWN_THREATS_FOUND:
        steps.append(NextStep(reg.statements["safaricom-report-333"].statement, "safaricom-report-333"))
    if "kra" in claimed and label != Label.NO_KNOWN_THREATS_FOUND and any(f.code == "KRA_NO_RECRUITMENT_FEE" for f in findings):
        steps.append(NextStep(reg.statements["kra-report-channel"].statement, "kra-report-channel"))
    return steps
