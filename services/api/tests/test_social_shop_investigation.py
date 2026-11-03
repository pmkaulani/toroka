"""Regression tests for social-shop investigation quality, search relevance,
and cross-investigation contamination prevention (demonstrated by @base_menswear).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from app.public_search import evaluate_search_relevance
from app.url_pipeline import (
    URLInvestigationCache,
    investigate_single_url,
    parse_platform_profile,
)


# ---------------------------------------------------------------------------
# 1. URL & Profile Canonicalisation Tests
# ---------------------------------------------------------------------------

def test_instagram_url_canonicalisation_and_param_stripping():
    # Target with unnecessary tracking parameters
    url_with_tracking = "https://instagram.com/base_menswear?xtok=abc123xyz&igsh=testtoken&utm_source=ig_web_copy_link"
    prof = parse_platform_profile(url_with_tracking)

    assert prof.is_profile is True
    assert prof.platform == "instagram"
    assert prof.handle == "base_menswear"
    assert prof.identifier == "instagram:base_menswear"
    assert prof.canonical_url == "https://www.instagram.com/base_menswear"
    assert prof.tracking_params.get("xtok") == "abc123xyz"
    assert prof.tracking_params.get("igsh") == "testtoken"


def test_cross_platform_identity_separation():
    # Same handle across different platforms must not merge
    ig = parse_platform_profile("https://www.instagram.com/base_menswear")
    tt = parse_platform_profile("https://www.tiktok.com/@base_menswear")
    fb = parse_platform_profile("https://www.facebook.com/base_menswear")
    x_prof = parse_platform_profile("https://x.com/base_menswear")

    assert ig.identifier == "instagram:base_menswear"
    assert tt.identifier == "tiktok:base_menswear"
    assert fb.identifier == "facebook:base_menswear"
    assert x_prof.identifier == "x:base_menswear"

    assert ig.identifier != tt.identifier
    assert ig.canonical_url != tt.canonical_url


def test_url_cache_deduplication_with_tracking_params(env):
    cache = URLInvestigationCache.get_instance()
    cache.clear()

    url_a = "https://instagram.com/base_menswear?xtok=11111"
    url_b = "https://instagram.com/base_menswear?xtok=22222"

    with env.db() as session:
        res_a = investigate_single_url(url_a, session, env.ctx.crypto, env.settings)
        res_b = investigate_single_url(url_b, session, env.ctx.crypto, env.settings)

    # Both must normalise to the exact same canonical URL and share cache
    assert res_a.normalized_url.rstrip("/") == "https://www.instagram.com/base_menswear"
    assert res_a.normalized_url == res_b.normalized_url


# ---------------------------------------------------------------------------
# 2. Search Relevance Ranking Tests
# ---------------------------------------------------------------------------

def test_search_relevance_distinguishes_direct_related_background_and_irrelevant():
    prof = parse_platform_profile("https://www.instagram.com/base_menswear")

    # 1. Direct evidence: Exact profile page
    direct_item = {
        "url": "https://www.instagram.com/base_menswear",
        "title": "BASE MENSWEAR (@base_menswear) • Instagram photos and videos",
        "snippet": "Nairobi menswear fashion and stylish apparel.",
    }
    rel_direct = evaluate_search_relevance(direct_item, platform=prof.platform, handle=prof.handle, canonical_url=prof.canonical_url)
    assert rel_direct["category"] == "direct_evidence"
    assert rel_direct["is_entity_match"] is True

    # 2. Direct evidence: External scam complaint naming exact handle
    complaint_item = {
        "url": "https://kenyacomplaints.com/report/123",
        "title": "Scam complaint against @base_menswear",
        "snippet": "I paid KSh 2,500 for a shirt to @base_menswear on Instagram and they blocked me without delivery.",
    }
    rel_complaint = evaluate_search_relevance(complaint_item, platform=prof.platform, handle=prof.handle, canonical_url=prof.canonical_url)
    assert rel_complaint["category"] == "direct_evidence"
    assert rel_complaint["is_entity_match"] is True

    # 3. Related evidence: Spaced business name in Kenyan clothing context
    related_item = {
        "url": "https://nairobihub.co.ke/shops/base-menswear",
        "title": "Base Menswear Nairobi Shop",
        "snippet": "Popular online clothing shop for men in Nairobi.",
    }
    rel_related = evaluate_search_relevance(related_item, platform=prof.platform, handle=prof.handle, canonical_url=prof.canonical_url)
    assert rel_related["category"] == "related_evidence"
    assert rel_related["is_entity_match"] is True

    # 4. General background: Educational article / advice
    bg_item = {
        "url": "https://growyourclothingbrand.com/tips",
        "title": "Grow Your Clothing Brand",
        "snippet": "Best practices for launching and managing an online apparel business safely.",
    }
    rel_bg = evaluate_search_relevance(bg_item, platform=prof.platform, handle=prof.handle, canonical_url=prof.canonical_url)
    assert rel_bg["category"] in ("general_background", "irrelevant")
    assert rel_bg["is_entity_match"] is False

    # 5. Irrelevant: Unrelated overseas business with substring collision
    unrelated_item = {
        "url": "https://trustpilot.com/review/baseusclothing.com",
        "title": "Baseus Clothing Reviews",
        "snippet": "Customer reviews of baseusclothing.com international store.",
    }
    rel_unrelated = evaluate_search_relevance(unrelated_item, platform=prof.platform, handle=prof.handle, canonical_url=prof.canonical_url)
    assert rel_unrelated["category"] == "irrelevant"
    assert rel_unrelated["is_entity_match"] is False


def test_pipeline_excludes_irrelevant_search_results_from_evidence(env):
    cache = URLInvestigationCache.get_instance()
    cache.clear()

    # Mock Tavily to return the noisy results described by the user
    mock_tavily = {
        "status": "checked",
        "provider": "Tavily",
        "query": '"base_menswear" instagram reviews scam Kenya',
        "results": [
            {
                "url": "https://growyourclothingbrand.com/how-to-start",
                "title": "Grow Your Clothing Brand",
                "snippet": "Tips for building your clothing brand and marketing on social media.",
            },
            {
                "url": "https://trustpilot.com/review/baseusclothing.com",
                "title": "Baseus Clothing Store Reviews",
                "snippet": "Review of baseusclothing.com.",
            },
            {
                "url": "https://instagram.com/reel/general_scam_warning",
                "title": "How to avoid scams online in Kenya",
                "snippet": "Awareness reel on fake sellers demanding upfront money.",
            },
        ],
        "manual_search_url": "https://www.google.com/search?q=test",
    }

    orig_key = env.settings.tavily_api_key
    env.settings.tavily_api_key = "mock-tavily-key"
    try:
        with patch("app.url_pipeline.public_search", return_value=mock_tavily):
            with env.db() as session:
                res = investigate_single_url("https://instagram.com/base_menswear", session, env.ctx.crypto, env.settings)
    finally:
        env.settings.tavily_api_key = orig_key

    # All 3 mock results are unrelated to @base_menswear
    # None of them should be included as entity-specific sources
    assert len(res.sources) == 0

    # Coverage status must be checked_no_match with explicit statement
    tavily_cov = next((c for c in res.coverage if c.id == "tavily_search"), None)
    assert tavily_cov is not None
    assert tavily_cov.status == "checked_no_match"
    assert "no independent reports matching @base_menswear" in tavily_cov.detail.lower()
    assert tavily_cov.results_retrieved == 3
    assert tavily_cov.results_relevant == 0

    # Risk band must be inconclusive (not high risk, not no_known_threats_found)
    assert res.risk_band == "inconclusive"


# ---------------------------------------------------------------------------
# 3. Adapted Social Shop Checklist Tests
# ---------------------------------------------------------------------------

def test_social_shop_checklist_has_shop_checks_and_no_sms_or_domain_age(env):
    cache = URLInvestigationCache.get_instance()
    cache.clear()

    with env.db() as session:
        res = investigate_single_url("https://instagram.com/base_menswear", session, env.ctx.crypto, env.settings)

    coverage_ids = [c.id for c in res.coverage]

    # Must contain social shop items
    assert "profile_identity" in coverage_ids
    assert "toroka_intel" in coverage_ids
    assert "tavily_search" in coverage_ids
    assert "business_links" in coverage_ids
    assert any(cid in coverage_ids for cid in ["safe_web_fetch", "profile_inspection"])
    assert "payment_evidence" in coverage_ids

    # Must NOT contain irrelevant generic SMS/domain checks
    assert "official_statements" not in coverage_ids
    assert "domain_facts" not in coverage_ids
    assert "text_rules" not in coverage_ids


# ---------------------------------------------------------------------------
# 4. Cross-Investigation Contamination Regression Tests
# ---------------------------------------------------------------------------

def test_cross_case_contamination_prevented_in_chat(env):
    # Step 1: User runs an inquiry about a foreign payout / advance fee scam
    payout_msg = (
        "Foreign or simulated payout documentation labeled redemption with an unverified foreign contact. "
        "Pay an upfront M-PESA fee for cross-border taxes and clearance before releasing the payout."
    )
    r_payout = env.client.post("/v1/chat", json={"message": payout_msg, "history": [], "language": "en"})
    assert r_payout.status_code == 200
    payout_reply = r_payout.json()["reply"]
    # Payout inquiry should discuss advance-fee / payout
    assert any(term in payout_reply.lower() for term in ["advance-fee", "payout", "redemption", "fee", "payouts"])

    # Step 2: Next, in the exact same session or subsequent request, investigate an unrelated Instagram clothing shop
    shop_msg = "Is @base_menswear on Instagram legit?"
    r_shop = env.client.post("/v1/chat", json={
        "message": shop_msg,
        "history": [{"role": "user", "text": payout_msg}, {"role": "model", "text": payout_reply}],
        "language": "en",
        "check_id": r_payout.json().get("check_id"),
    })
    assert r_shop.status_code == 200
    shop_reply = r_shop.json()["reply"]

    # CRITICAL: Shop response MUST NOT contain any payout contamination!
    assert "redemption" not in shop_reply.lower()
    assert "foreign or simulated payout" not in shop_reply.lower()
    assert "mike adamson" not in shop_reply.lower()
    assert "clearance fee" not in shop_reply.lower()
    assert "invoicebase" not in shop_reply.lower()


def test_concurrent_investigations_remain_strictly_isolated(env):
    payout_text = (
        "Payout release notification: foreign document redemption code INV-9901. "
        "Send KSh 4500 clearance tax to claim your prize."
    )
    shop_text = "https://instagram.com/base_menswear?xtok=testconcurrency"

    def run_payout():
        return env.client.post("/v1/chat", json={"message": payout_text, "language": "en"}).json()

    def run_shop():
        return env.client.post("/v1/chat", json={"message": shop_text, "language": "en"}).json()

    with ThreadPoolExecutor(max_workers=4) as pool:
        f_payout = pool.submit(run_payout)
        f_shop = pool.submit(run_shop)

        res_payout = f_payout.result()
        res_shop = f_shop.result()

    # Verify payout result
    assert "payout" in res_payout["reply"].lower() or "fee" in res_payout["reply"].lower()

    # Verify shop result has zero payout contamination
    assert "redemption" not in res_shop["reply"].lower()
    assert "foreign or simulated payout" not in res_shop["reply"].lower()
    assert "clearance tax" not in res_shop["reply"].lower()

    # Verify shop investigation structure
    assert res_shop.get("url_investigation") is not None
    inv = res_shop["url_investigation"]
    assert inv["risk_band"] == "inconclusive"
    assert inv["platform_profile"]["identifier"] == "instagram:base_menswear"
