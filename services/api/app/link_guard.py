"""Applies link-level safety on top of the investigation: deceptive links are flagged; a real marketplace site is said to be real, with the seller question kept separate."""
from __future__ import annotations

from ssi_connectors.deceptive_links import deceptive_link_flags, registered_domain
from ssi_connectors.marketplace import _MARKETPLACES  # (name, domains, ...) entries; adapt if your tuple shape differs

from .decision_report import build_decision, facts_from_result

EXTRA_BRANDS = {
    "Safaricom": {"safaricom.co.ke"},
    "Airtel": {"airtel.co.ke"},
    "Telkom": {"telkom.co.ke"},
    "KRA": {"kra.go.ke"},
    "eCitizen": {"ecitizen.go.ke"},
    "NTSA": {"ntsa.go.ke"},
    "HELB": {"helb.co.ke"},
    "SHA": {"sha.go.ke", "nhif.or.ke"},
    "NSSF": {"nssf.or.ke"},
    "Posta": {"posta.co.ke"},
    "Equity": {"equitybank.co.ke", "equitygroupholdings.com"},
    "KCB": {"kcbgroup.com", "kcb.co.ke"},
    "Co-op Bank": {"co-opbank.co.ke"},
    "NCBA": {"ncbagroup.com"},
    "Absa": {"absabank.co.ke"},
    "Stanbic": {"stanbicbank.co.ke"},
    "DTB": {"dtbafrica.com"},
    "I&M": {"imbankgroup.com"},
    "Naivas": {"naivas.online", "naivas.co.ke"},
    "Quickmart": {"quickmart.co.ke"},
    "Carrefour": {"carrefourkenya.com"},
}      # verified official Kenyan domains for essential services and banks
RANK = {"verified_official": 0, "looks_genuine": 0, "no_known_threats_found": 1, "inconclusive": 2, "suspicious_verify_first": 3, "high_risk": 4}


def brands() -> dict[str, set[str]]:
    out = {name: {registered_domain(d) for d in domains} for name, domains, *_ in _MARKETPLACES}
    out.update(EXTRA_BRANDS); return out


def _real_brand(domain: str, table: dict[str, set[str]]) -> str | None:
    d = registered_domain(domain or "")
    return next((n for n, ds in table.items() if d in ds), None)


def apply_link_guard(result, url: str, language: str = "en"):
    from .url_pipeline import URLFinding                                    # imported here to avoid a circular import
    table, bad = brands(), deceptive_link_flags(url, brands())
    have = {f.code for f in result.findings}
    for fl in bad:
        code = f"DECEPTIVE_{fl.code.upper()}"
        if code not in have:
            result.findings.append(URLFinding(code, fl.text, "Scam links are often built to look like a brand you trust. Open the real site by typing its address yourself.", "strong" if fl.severity == "critical" else "supporting",
                                              "automated_observation", url))
    if bad:
        target = "high_risk" if bad[0].severity == "critical" else "suspicious_verify_first"
        if RANK.get(result.risk_band, 2) < RANK[target]: result.risk_band = target
    else:
        brand = _real_brand(getattr(result, "domain", None), table)
        if brand and not url.lower().startswith("http://"):
            result.findings.append(URLFinding("OFFICIAL_BRAND_SITE", f"{result.domain} is the real {brand} website (its exact address matches the one {brand} uses).",
                                              "This says the website is the genuine one. It does not say that a seller on it, or an offer sent in its name, is genuine.", "supporting", "automated_observation", url, "positive"))
            result.page_data = {**(result.page_data or {}), "official_brand": brand}
    result.decision = build_decision(facts_from_result(result, language), language)
    result.summary = result.decision["headline"]
    return result
