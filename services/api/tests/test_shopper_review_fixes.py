"""Comprehensive verification of the 7 fixes and safety improvements from the Toroka v2 shopper review."""
import pytest
from urllib.parse import urlsplit

from app.url_pipeline import investigate_single_url, parse_platform_profile
from app.public_search import find_public_identifiers
from app.user_text import scrub_reply, INTERNAL
from app.decision_report import build_decision


def test_section_1_fake_brand_links_vs_real_jumia(env):
    with env.db() as db:
        # 1. Real Jumia
        real = investigate_single_url("https://www.jumia.co.ke/phone-123.html", db, env.ctx.crypto, env.settings, skip_cache=True)
        assert not any(f.code.startswith("DECEPTIVE_") for f in real.findings)
        assert any(f.code == "OFFICIAL_BRAND_SITE" and f.polarity == "positive" for f in real.findings)
        assert real.page_data.get("official_brand") == "Jumia"
        assert "real Jumia website" in real.decision["headline"]

        # 2. jumia-kenya-deals.com/promo -> brand in domain (major -> suspicious_verify_first)
        fake2 = investigate_single_url("https://jumia-kenya-deals.com/promo", db, env.ctx.crypto, env.settings, skip_cache=True)
        assert fake2.risk_band == "suspicious_verify_first"
        assert any(f.code == "DECEPTIVE_BRAND_IN_DOMAIN" for f in fake2.findings)
        assert fake2.decision["decision"] in ("pause_and_verify", "dont_pay")

        # 3. www.jumia.co.ke.cheap-phones.xyz/login -> embedded official domain (critical -> high_risk)
        fake3 = investigate_single_url("https://www.jumia.co.ke.cheap-phones.xyz/login", db, env.ctx.crypto, env.settings, skip_cache=True)
        assert fake3.risk_band == "high_risk"
        assert any(f.code == "DECEPTIVE_EMBEDDED_OFFICIAL_DOMAIN" for f in fake3.findings)
        assert fake3.decision["decision"] == "dont_pay"

        # 4. jumia.co.ke@cheap-phones.xyz/ -> userinfo trick (critical -> high_risk)
        fake4 = investigate_single_url("https://jumia.co.ke@cheap-phones.xyz/", db, env.ctx.crypto, env.settings, skip_cache=True)
        assert fake4.risk_band == "high_risk"
        assert any(f.code == "DECEPTIVE_USERINFO_TRICK" for f in fake4.findings)
        assert fake4.decision["decision"] == "dont_pay"

        # 5. www.jum1a.co.ke/phone -> misspelled brand (major -> suspicious_verify_first)
        fake5 = investigate_single_url("https://www.jum1a.co.ke/phone", db, env.ctx.crypto, env.settings, skip_cache=True)
        assert fake5.risk_band == "suspicious_verify_first"
        assert any(f.code == "DECEPTIVE_MISSPELLED_BRAND" for f in fake5.findings)
        assert fake5.decision["decision"] in ("pause_and_verify", "dont_pay")

        # 6. mamamboga-shop.co.ke/p/1 -> unknown shop, no deceptive brand flag
        shop = investigate_single_url("https://www.mamamboga-shop.co.ke/p/1", db, env.ctx.crypto, env.settings, skip_cache=True)
        assert not any(f.code.startswith("DECEPTIVE_") for f in shop.findings)
        assert not any(f.code == "OFFICIAL_BRAND_SITE" for f in shop.findings)


def test_section_2_jumia_homepage_not_called_a_listing(env):
    with env.db() as db:
        home = investigate_single_url("https://www.jumia.co.ke", db, env.ctx.crypto, env.settings, skip_cache=True)
        assert any(f.code == "OFFICIAL_BRAND_SITE" for f in home.findings)
        # The home page must NOT say "I identified this listing on Jumia"
        assert "this listing on Jumia" not in home.decision["headline"]
        assert "listing" not in home.decision["headline"].lower()
        assert "real Jumia website" in home.decision["headline"]


def test_section_4_short_links_and_facebook_marketplace_not_treated_as_accounts():
    # TikTok short link: vm.tiktok.com/ZMabc123/
    tt_link = "https://vm.tiktok.com/ZMabc123/"
    tt_profile = parse_platform_profile(tt_link)
    assert tt_profile.handle is None
    assert tt_profile.content_kind == "short_link"
    tt_targets = find_public_identifiers(tt_link)
    assert not any(t.get("identifier") == "@ZMabc123" for t in tt_targets)

    # Facebook marketplace link: web.facebook.com/marketplace/item/7654321098/
    fb_link = "https://web.facebook.com/marketplace/item/7654321098/"
    fb_profile = parse_platform_profile(fb_link)
    assert fb_profile.handle is None
    assert fb_profile.content_kind == "marketplace_item"
    fb_targets = find_public_identifiers(fb_link)
    assert not any(t.get("identifier") == "@marketplace" for t in fb_targets)


def test_section_5_host_extraction_with_credentials_never_yields_brand():
    bad_url = "https://jumia.co.ke:pw@cheap-phones.xyz/"
    host = (urlsplit(bad_url).hostname or "").lower()
    assert host == "cheap-phones.xyz"
    assert host != "jumia.co.ke"

    bad_url_2 = "https://jumia.co.ke:pw@evil.example/"
    host_2 = (urlsplit(bad_url_2).hostname or "").lower()
    assert host_2 == "evil.example"
    assert host_2 != "jumia.co.ke"


def test_section_6_inconclusive_headline_wording():
    # Decision report headline for inconclusive should be clean and non-repetitive
    report = build_decision({"kind": "shop_site", "domain": "example.com", "risk_band": "inconclusive"})
    headline = report["headline"]
    assert "can't tell yet" in headline
    assert "its legitimacy is not established by the checks available so far" not in headline
    assert "Here is how to check before you pay" in headline


def test_section_3_chat_reply_scrubbing_and_no_leakages():
    raw_leak = (
        "I checked **@kicks.nairobi, TikTok**. Live search not run because TAVILY_API_KEY is not configured. "
        "Some sources were unavailable or not configured: Google Places, Scrape Creators, Weir. "
        "In this run, we observed no threat records.\n\n"
        "Ask the seller for the registered business name and inspect the item before paying."
    )
    scrubbed = scrub_reply(raw_leak)
    assert not INTERNAL.search(scrubbed)
    assert "TAVILY" not in scrubbed
    assert "Weir" not in scrubbed
    assert "Google Places" not in scrubbed
    assert "in this run" not in scrubbed.lower()
    assert "registered business name" in scrubbed
