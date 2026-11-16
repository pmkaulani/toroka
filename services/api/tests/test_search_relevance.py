"""Regression tests for entity-aware web search and evidence isolation."""
from app.public_search import filter_public_search_results
from app.routes_core import _attach_grounded_ai_quotes
from app.url_pipeline import URLInvestigationResult, PlatformProfile, _cache_payload, _canonical_profile_url


def _base_menswear_results():
    return [
        {
            "title": "Instagram. Log In Sign Up base_menswear profile",
            "url": "https://www.instagram.com/p/Devq8hqNs2h",
            "snippet": "base\\_menswear • Follow. Photo by Base Men's Wear. No comments yet.",
        },
        {
            "title": "Legit Check KE — How to Spot a Fake Instagram Seller",
            "url": "https://legitcheck.co.ke/guide",
            "snippet": "Tips on how to spot fake Instagram sellers and avoid Instagram scams.",
        },
        {
            "title": "Baseus Clothing is rated Bad",
            "url": "https://www.trustpilot.com/review/www.baseusclothing.com",
            "snippet": "This company is a scam. The product quality was poor.",
        },
        {
            "title": "Instagram Alert: avoid fake pages",
            "url": "https://www.instagram.com/reel/DWjxojRjvL-",
            "snippet": "A different seller lists a phone number and warns about fake pages.",
        },
        {
            "title": "4 Instagram sellers you can actually trust",
            "url": "https://www.youtube.com/watch?v=NivC1gu-Wi8",
            "snippet": "A creator reviews several unrelated clothing brands.",
        },
    ]


def test_search_relevance_keeps_exact_account_mentions_and_excludes_lookalikes():
    ranked = filter_public_search_results(
        _base_menswear_results(),
        identifier="@base_menswear",
        kind="handle",
        platform="instagram",
    )

    assert ranked["raw_result_count"] == 5
    assert ranked["relevant_count"] == 1
    assert ranked["background_count"] == 2
    assert ranked["irrelevant_count"] == 2
    assert "base_menswear" in ranked["relevant_results"][0]["snippet"].replace("\\_", "_")
    assert ranked["relevant_results"][0]["relevance"] == "entity_mention"
    assert ranked["relevant_results"][0]["claim_signal"] is False
    all_relevant_urls = [x["url"] for x in ranked["relevant_results"]]
    assert not any("baseusclothing" in url for url in all_relevant_urls)
    assert not any("DWjxojRjvL-" in url for url in all_relevant_urls)


def test_exact_profile_url_is_match_but_not_proof_of_fraud():
    ranked = filter_public_search_results(
        [{"title": "base_menswear on Instagram", "url": "https://www.instagram.com/base_menswear/", "snippet": "Public profile page."}],
        identifier="base_menswear",
        kind="handle",
        platform="instagram",
    )
    item = ranked["relevant_results"][0]
    assert item["relevance"] == "exact_entity"
    assert item["claim_signal"] is False


def test_claim_words_in_unrelated_text_do_not_turn_exact_mention_into_complaint():
    ranked = filter_public_search_results(
        [{
            "title": "base_menswear profile",
            "url": "https://www.instagram.com/p/abc123",
            "snippet": "The post shows a shirt. General news today mentions fraud in another sector.",
        }],
        identifier="base_menswear",
        kind="handle",
        platform="instagram",
    )
    assert ranked["relevant_count"] == 1
    assert ranked["relevant_results"][0]["claim_signal"] is False


def test_domain_search_keeps_exact_domain_review_and_excludes_other_brands():
    ranked = filter_public_search_results(
        [
            {"title": "Example shop reviews", "url": "https://reviews.example.com/shop", "snippet": "Reviews of example-shop.co.ke"},
            {"title": "Another shop scam complaint", "url": "https://review.example.net/other-shop", "snippet": "Another unrelated shop"},
        ],
        identifier="example-shop.co.ke",
        kind="domain",
        platform=None,
        target_url="https://example-shop.co.ke",
    )
    assert ranked["relevant_count"] == 1
    assert ranked["irrelevant_count"] == 1


def test_canonical_instagram_profile_drops_tracking_parameters():
    value = _canonical_profile_url("https://www.instagram.com/base_menswear?xtok=secret-tracker")
    assert value == "https://www.instagram.com/base_menswear/"
    assert "xtok" not in value


def test_cache_payload_never_stores_contextual_ai_reply():
    result = URLInvestigationResult(
        target_url="https://www.instagram.com/base_menswear/",
        normalized_url="https://www.instagram.com/base_menswear/",
        domain="instagram.com",
        platform_profile=PlatformProfile(True, "instagram", "base_menswear", "instagram:base_menswear"),
        risk_band="inconclusive",
        summary="The profile could not be inspected directly.",
        ai_conversational_reply="Response tailored to private user context that must not be cached.",
    )
    payload = _cache_payload(result)
    assert payload["ai_conversational_reply"] is None


def test_url_only_ai_quote_is_not_added_as_a_finding():
    result = {"findings": []}
    ai_result = {"findings": [{
        "code": "PROFILE_URL",
        "plain_text": "The submitted content includes the profile URL.",
        "why_it_matters": "The link is the URL to investigate.",
        "excerpt": "[https://www.instagram.com/base_menswear?xtok=abc](https://www.instagram.com/base_menswear?xtok=abc)",
    }]}
    accepted = _attach_grounded_ai_quotes(
        result,
        ai_result,
        "Please investigate this Instagram shop: [https://www.instagram.com/base_menswear?xtok=abc](https://www.instagram.com/base_menswear?xtok=abc)",
    )
    assert accepted == 0
    assert result["findings"] == []


def test_specific_payment_request_quote_can_still_be_added():
    result = {"findings": []}
    ai_result = {"findings": [{"excerpt": "Pay KSh 500 to release your winnings"}]}
    accepted = _attach_grounded_ai_quotes(result, ai_result, "Pay KSh 500 to release your winnings before payout.")
    assert accepted == 1
    assert result["findings"][0]["excerpt"] == "Pay KSh 500 to release your winnings"


def test_url_pipeline_surfaces_only_target_relevant_search_results_and_stays_inconclusive(make_env, monkeypatch):
    from app.url_pipeline import ThreatFeedManager, URLInvestigationCache, investigate_single_url

    env = make_env(tavily_api_key="test-key")
    cache = URLInvestigationCache.get_instance()
    cache.clear()
    raw_results = _base_menswear_results()

    def fake_public_search(query, api_key, max_results=5):
        assert 'base_menswear' in query
        assert api_key == "test-key"
        return {
            "status": "checked",
            "detail": "Mock provider response.",
            "results": raw_results,
            "manual_search_url": "https://www.google.com/search?q=base_menswear",
        }

    monkeypatch.setattr("app.url_pipeline.public_search", fake_public_search)
    monkeypatch.setattr(ThreatFeedManager, "refresh_feeds", lambda self, **kwargs: None)

    with env.db() as db:
        result = investigate_single_url(
            "https://www.instagram.com/base_menswear?xtok=tracking-secret",
            db,
            env.ctx.crypto,
            env.settings,
            user_context="Look into this shop before I buy.",
        )

    assert result.normalized_url == "https://www.instagram.com/base_menswear/"
    assert result.risk_band == "inconclusive"
    assert "can't tell yet" in result.summary.lower() or "not established" in result.summary.lower() or "not a finding" in result.summary.lower()
    public_leads = [s for s in result.sources if "Tavily" in s.reviewer]
    assert len(public_leads) == 1
    assert "base_menswear" in public_leads[0].statement.lower()
    assert public_leads[0].claim_signal is False
    assert all("baseusclothing" not in (source.source_url or "") for source in result.sources)
    assert all("DWjxojRjvL-" not in (source.source_url or "") for source in result.sources)
    coverage = next(c for c in result.coverage if c.id == "tavily_search")
    assert "5 result(s)" in coverage.detail
    assert "1 relevant" in coverage.detail
    assert "2 general background" in coverage.detail
    assert "2 unrelated" in coverage.detail
    profile_check = next(c for c in result.coverage if c.id == "safe_web_fetch")
    assert profile_check.status == "not_checked"
    assert "did not directly inspect" in profile_check.detail


def test_chat_shop_search_response_omits_irrelevant_sources(make_env, monkeypatch):
    env = make_env(tavily_api_key="test-key")

    def fake_public_search(query, api_key, max_results=5):
        return {
            "status": "checked",
            "detail": "Provider returned results.",
            "results": _base_menswear_results(),
            "manual_search_url": "https://www.google.com/search?q=base_menswear",
        }

    monkeypatch.setattr("app.routes_core.public_search", fake_public_search)
    response = env.client.post("/v1/chat", json={
        "message": "Please investigate @base_menswear on Instagram",
        "language": "en",
        "history": [],
    })
    assert response.status_code == 200, response.text
    body = response.json()
    answer = (body.get("reply_en") or body.get("reply") or "").lower()
    assert "base_menswear" in answer
    assert "search retrieved 5 result(s)" in answer
    assert "1 result(s) mention or link to the exact target" in answer
    assert "baseusclothing" not in answer
    assert "dwjxojrjv-l" not in answer
    assert "public search leads" in answer
