from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from app.social_intelligence import (
    _complaint_flags,
    _exact_identity_match,
    _post_sources,
    investigate_social_targets,
)


def test_missing_keys_are_not_reported_as_clean():
    result = investigate_social_targets(
        [{"kind": "handle", "identifier": "@shop_ke", "platform": "instagram"}],
        SimpleNamespace(weir_api_key="", scrape_creators_api_key=""),
    )
    assert result["sources"] == []
    assert {row["status"] for row in result["statuses"]} == {"not_configured"}
    assert result["red_flags"] == []


def test_handle_match_requires_exact_token_not_substring():
    target = {"kind": "handle", "identifier": "@base_menswear", "platform": "instagram"}
    assert _exact_identity_match(target, "Complaint about @base_menswear", "paid but no delivery", "https://x.com/a/1")[0]
    assert not _exact_identity_match(target, "base_menswears review", "unrelated", "https://x.com/a/1")[0]


def test_weir_posts_are_normalised_and_unrelated_posts_excluded():
    target = {"kind": "handle", "identifier": "@base_menswear", "platform": "instagram"}
    payload = {
        "data": [
            {
                "id": "1", "text": "I paid @base_menswear but never received my shirt",
                "url": "https://x.com/customer/status/1", "createdAt": "2026-10-20T09:00:00Z",
                "author": {"username": "customer_one"},
            },
            {
                "id": "2", "text": "Baseus clothing was great",
                "url": "https://x.com/customer/status/2", "author": {"username": "customer_two"},
            },
        ]
    }
    records = _post_sources(target, payload, "Weir", "x")
    assert len(records) == 1
    assert records[0]["verification_status"] == "unverified_public_mention"
    assert records[0]["author_username"] == "customer_one"


def test_repeated_complaint_flag_requires_two_distinct_authors_and_posts():
    sources = [
        {"source_type": "social_intelligence_lead", "evidence_type": "public_post_or_complaint_lead", "snippet": "I paid @shop_ke but never received delivery", "url": "https://x.com/a/status/1", "author_username": "a", "searched_identifier": "shop_ke"},
        {"source_type": "social_intelligence_lead", "evidence_type": "public_post_or_complaint_lead", "snippet": "Paid @shop_ke, goods were not delivered", "url": "https://reddit.com/r/kenya/2", "author_username": "b", "searched_identifier": "shop_ke"},
    ]
    flags = _complaint_flags(sources)
    assert len(flags) == 1
    assert flags[0]["strength"] == "supporting"
    assert flags[0]["status"] == "reported_pattern"
    assert "not independently verified" in flags[0]["explanation"]


def test_same_author_repeating_complaint_does_not_meet_independence_threshold():
    sources = [
        {"source_type": "social_intelligence_lead", "evidence_type": "public_post_or_complaint_lead", "snippet": "I paid @shop_ke but never received delivery", "url": "https://x.com/a/status/1", "author_username": "a", "searched_identifier": "shop_ke"},
        {"source_type": "social_intelligence_lead", "evidence_type": "public_post_or_complaint_lead", "snippet": "Paid @shop_ke, goods were not delivered", "url": "https://x.com/a/status/2", "author_username": "a", "searched_identifier": "shop_ke"},
    ]
    flags = _complaint_flags(sources)
    assert len(flags) == 1
    assert flags[0]["strength"] == "weak"
    assert flags[0]["independent_corroboration_threshold_met"] is False


def test_scrape_creators_profile_and_tiktok_search_use_configured_key():
    target = {"kind": "handle", "identifier": "@shop_ke", "platform": "tiktok"}
    profile = {"success": True, "data": {"username": "shop_ke", "full_name": "Shop KE", "bio": "Nairobi online shop"}}
    posts = {"success": True, "search_item_list": [{
        "aweme_info": {
            "desc": "Customers ask about @shop_ke order delivery",
            "share_url": "https://www.tiktok.com/@customer/video/123",
            "author": {"unique_id": "customer"},
        }
    }]}

    def fake_request(method, url, **kwargs):
        if url.endswith("/v1/tiktok/profile"):
            assert kwargs["headers"]["x-api-key"] == "test-key"
            return "checked", profile, "ok"
        if url.endswith("/v1/tiktok/search/keyword"):
            assert kwargs["params"]["query"] == "shop_ke"
            return "checked", posts, "ok"
        raise AssertionError(url)

    with patch("app.social_intelligence._request_json", side_effect=fake_request):
        result = investigate_social_targets([target], SimpleNamespace(weir_api_key="", scrape_creators_api_key="test-key"))
    assert any(s["source_type"] == "social_profile_observation" for s in result["sources"])
    assert any(s["platform"] == "tiktok" and "Customers ask" in s["snippet"] for s in result["sources"])


def test_weir_x_request_uses_documented_query_field_and_small_limit():
    from app.social_intelligence import _call_weir

    target = {"kind": "handle", "identifier": "@shop_ke", "platform": "instagram"}

    def fake_request(method, url, **kwargs):
        assert method == "POST"
        assert url.endswith("/v1/x/search")
        body = kwargs["json_body"]
        assert '"shop_ke"' in body["query"]
        assert "scam OR fraud" in body["query"]
        assert body["limit"] == 12
        return "checked", {"data": []}, "ok"

    with patch("app.social_intelligence._request_json", side_effect=fake_request):
        rows, status = _call_weir(target, "private-test-key", "x")
    assert rows == []
    assert status["status"] == "checked_no_match"


def test_weir_reddit_query_is_bounded_and_uses_one_year_window():
    from app.social_intelligence import _call_weir

    target = {"kind": "handle", "identifier": "@shop_ke", "platform": "tiktok"}

    def fake_request(method, url, **kwargs):
        assert url.endswith("/v1/reddit/search")
        body = kwargs["json_body"]
        assert '"shop_ke"' in body["query"]
        assert body["limit"] == 5
        assert body["time"] == "year"
        return "checked", {"data": []}, "ok"

    with patch("app.social_intelligence._request_json", side_effect=fake_request):
        rows, status = _call_weir(target, "private-test-key", "reddit")
    assert rows == []
    assert status["status"] == "checked_no_match"


def test_social_lookup_uses_short_lived_cache_for_repeated_public_target():
    from app import social_intelligence

    target = {"kind": "handle", "identifier": "@cache_shop", "platform": "instagram"}
    settings = SimpleNamespace(weir_api_key="cache-key", scrape_creators_api_key="")
    social_intelligence._SOCIAL_CACHE.clear()
    calls = []

    def fake_weir(_target, _key, platform):
        calls.append(platform)
        return [], {"provider": "Weir", "platform": platform, "status": "checked_no_match", "detail": "No matching result", "results": 0}

    with patch("app.social_intelligence._call_weir", side_effect=fake_weir):
        first = social_intelligence.investigate_social_targets([target], settings)
        second = social_intelligence.investigate_social_targets([target], settings)

    assert len(calls) == 2  # X + Reddit run only once each.
    assert first["cache"]["hit"] is False
    assert second["cache"]["hit"] is True
