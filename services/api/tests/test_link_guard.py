from types import SimpleNamespace as NS

from app.link_guard import apply_link_guard
from app.url_pipeline import URLFinding


def fake(domain, band="inconclusive"):
    return NS(domain=domain, risk_band=band, findings=[], page_data={}, platform_profile=None, coverage=[], contradictions=[], summary="", next_steps=[], decision=None)


def test_lookalikes_become_dont_pay_or_pause():
    for url, dom, band in (("https://www.jumia.co.ke.cheap-phones.xyz/login", "cheap-phones.xyz", "high_risk"), ("https://jumia.co.ke@cheap-phones.xyz/", "cheap-phones.xyz", "high_risk"),
                           ("https://jumia-kenya-deals.com/promo", "jumia-kenya-deals.com", "suspicious_verify_first"), ("https://www.jum1a.co.ke/phone", "jum1a.co.ke", "suspicious_verify_first")):
        r = apply_link_guard(fake(dom), url)
        assert r.risk_band == band and r.decision["decision"] in ("dont_pay", "pause_and_verify") and any(f.code.startswith("DECEPTIVE_") for f in r.findings), (url, r.risk_band)


def test_a_worse_existing_band_is_never_lowered_and_real_sites_are_not_penalised():
    assert apply_link_guard(fake("jumia-kenya-deals.com", "high_risk"), "https://jumia-kenya-deals.com").risk_band == "high_risk"
    r = apply_link_guard(fake("jumia.co.ke"), "https://www.jumia.co.ke/phone-123.html")
    assert r.risk_band == "inconclusive" and not [f for f in r.findings if f.code.startswith("DECEPTIVE_")]
    assert any(f.code == "OFFICIAL_BRAND_SITE" and f.polarity == "positive" for f in r.findings) and r.page_data["official_brand"] == "Jumia"
    assert not any(f.code == "OFFICIAL_BRAND_SITE" for f in apply_link_guard(fake("jumia.co.ke"), "http://jumia.co.ke/x").findings)       # plain http: no endorsement


def test_host_extraction_with_credentials_never_yields_fake_prefix():
    from urllib.parse import urlsplit
    url = "https://jumia.co.ke:pw@evil.example/"
    host = (urlsplit(url).hostname or "").lower()
    assert host == "evil.example"
    assert host != "jumia.co.ke"


def test_kenyan_bank_and_gov_brands_protected():
    # Real brand affirmation
    eq_real = apply_link_guard(fake("equitybank.co.ke"), "https://www.equitybank.co.ke/personal")
    assert any(f.code == "OFFICIAL_BRAND_SITE" and f.polarity == "positive" for f in eq_real.findings)
    assert eq_real.page_data.get("official_brand") == "Equity"

    kcb_real = apply_link_guard(fake("kcbgroup.com"), "https://kcbgroup.com/loans")
    assert any(f.code == "OFFICIAL_BRAND_SITE" and f.polarity == "positive" for f in kcb_real.findings)
    assert kcb_real.page_data.get("official_brand") == "KCB"

    ecitizen_real = apply_link_guard(fake("ecitizen.go.ke"), "https://accounts.ecitizen.go.ke/login")
    assert any(f.code == "OFFICIAL_BRAND_SITE" and f.polarity == "positive" for f in ecitizen_real.findings)
    assert ecitizen_real.page_data.get("official_brand") == "eCitizen"

    # Deceptive brand phishing detection
    eq_fake = apply_link_guard(fake("equity-loans.com"), "https://equity-loans.com")
    assert eq_fake.risk_band == "suspicious_verify_first"
    assert any(f.code == "DECEPTIVE_BRAND_IN_DOMAIN" for f in eq_fake.findings)

    kcb_fake = apply_link_guard(fake("kcb-support.com"), "https://kcb-support.com")
    assert kcb_fake.risk_band == "suspicious_verify_first"
    assert any(f.code == "DECEPTIVE_BRAND_IN_DOMAIN" for f in kcb_fake.findings)

    ntsa_fake = apply_link_guard(fake("portal.xyz"), "https://ntsa.go.ke.portal.xyz/login")
    assert ntsa_fake.risk_band == "high_risk"
    assert any(f.code == "DECEPTIVE_EMBEDDED_OFFICIAL_DOMAIN" for f in ntsa_fake.findings)

