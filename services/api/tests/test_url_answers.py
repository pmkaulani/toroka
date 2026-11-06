import json
from unittest.mock import patch

import pytest

from app.url_pipeline import ThreatFeedManager
from app.social_meta import parse_tiktok_oembed

SAMPLE = {
    "title": "Air Max 90 KSh 3,500 only! Pay half to reserve, DM",
    "author_url": "https://www.tiktok.com/@kicks.nairobi",
    "author_name": "Kicks Nairobi",
    "provider_name": "TikTok",
}

LINKS = [
    "https://www.tiktok.com/@kicks.nairobi/video/7312345678901234567",
    "https://vm.tiktok.com/ZMabc123/",
    "https://www.tiktok.com/@kicks.nairobi",
    "https://www.instagram.com/p/CxYz123AbC/",
    "https://www.facebook.com/marketplace/item/7654321098/",
    "https://www.mamamboga-shop.co.ke/products/air-max-90",
]
BANNED = ("not_configured", "API_KEY", "Tavily", "Gemini", "could not complete enough independent checks", "confirm with the organisation")


@pytest.mark.parametrize("link", LINKS)
def test_each_link_shape_returns_complete_decision(env, monkeypatch, link):
    env.settings.enable_link_fetch = False
    manager = ThreatFeedManager.get_instance()
    monkeypatch.setattr(manager, "refresh_feeds", lambda **kwargs: None)
    monkeypatch.setattr(manager, "check", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.social_meta.fetch_tiktok_oembed", lambda url: parse_tiktok_oembed(SAMPLE) if "tiktok" in url else None)

    response = env.client.post("/v1/investigate/url", json={"url": link, "language": "en"})
    assert response.status_code == 200, response.text
    payload = response.json()
    decision = payload["decision"]
    assert decision["headline"]
    assert decision["decision"] in {"dont_pay", "pause_and_verify", "cant_tell_yet", "pay_only_safely"}
    assert any("half-payment" in item for item in decision["before_you_pay"])
    assert "registered business name" in decision["ask_the_seller"]
    if decision["decision"] == "cant_tell_yet":
        assert len(decision["how_to_find_out"]) == 5
    blob = json.dumps(decision)
    assert not [word for word in BANNED if word.casefold() in blob.casefold()]


def test_tiktok_caption_advance_payment_is_a_finding(env, monkeypatch):
    env.settings.enable_link_fetch = False
    manager = ThreatFeedManager.get_instance()
    monkeypatch.setattr(manager, "refresh_feeds", lambda **kwargs: None)
    monkeypatch.setattr(manager, "check", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.social_meta.fetch_tiktok_oembed", lambda url: parse_tiktok_oembed(SAMPLE))
    response = env.client.post("/v1/investigate/url", json={
        "url": "https://www.tiktok.com/@kicks.nairobi/video/7312345678901234567", "language": "en"
    })
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["platform_profile"]["handle"] == "kicks.nairobi"
    assert any("caption" in f["plain_text"].lower() and "upfront" in f["why_it_matters"].lower() or "advance" in f["why_it_matters"].lower() for f in payload["findings"])


def test_plain_shop_page_is_read_when_safe_fetch_is_enabled(env, monkeypatch):
    from ssi_connectors.url_fetcher import SafePageContent
    from ssi_rules.vocabulary import CoverageStatus

    # Keep external threat/search providers mocked; exercise the real pipeline
    # decision to fetch a normal shop domain when link fetching is enabled.
    env.settings.enable_link_fetch = True
    manager = ThreatFeedManager.get_instance()
    monkeypatch.setattr(manager, "refresh_feeds", lambda **kwargs: None)
    monkeypatch.setattr(manager, "check", lambda *args, **kwargs: None)
    calls = []

    def fake_fetch(url, **kwargs):
        calls.append(url)
        return SafePageContent(
            status=CoverageStatus.CHECKED, final_url=url, status_code=200,
            title="Mama Mboga Online Shop",
            meta_description="Fresh groceries delivered in Nairobi",
            visible_text="Contact us. Delivery and refund policy. Pay on delivery available.",
            phones=["+254700000000"], fetch_time_ms=12.0,
        )

    monkeypatch.setattr("app.url_pipeline.safe_fetch_page", fake_fetch)
    response = env.client.post("/v1/investigate/url", json={
        "url": "https://mamamboga-shop.co.ke/products/air-max-90", "language": "en"
    })
    assert response.status_code == 200, response.text
    payload = response.json()
    assert calls == ["https://mamamboga-shop.co.ke/products/air-max-90"]
    assert payload["page_data"]["title"] == "Mama Mboga Online Shop"
    assert payload["page_data"]["visible_text_excerpt"].startswith("Contact us")
    assert any(check["id"] == "safe_web_fetch" and check["status"] == "checked" for check in payload["coverage"])


def test_safe_shop_page_fetch_is_enabled_by_default():
    from app.config import Settings
    assert Settings().enable_link_fetch is True


@pytest.mark.parametrize("link", [LINKS[0], LINKS[3], LINKS[5]])
def test_normal_chat_returns_the_same_decision_first_url_report(env, monkeypatch, link):
    env.settings.enable_link_fetch = False
    manager = ThreatFeedManager.get_instance()
    monkeypatch.setattr(manager, "refresh_feeds", lambda **kwargs: None)
    monkeypatch.setattr(manager, "check", lambda *args, **kwargs: None)
    monkeypatch.setattr("app.social_meta.fetch_tiktok_oembed", lambda url: parse_tiktok_oembed(SAMPLE) if "tiktok" in url else None)
    response = env.client.post("/v1/chat", json={"message": link, "language": "en", "history": []})
    assert response.status_code == 200, response.text
    investigation = response.json().get("url_investigation")
    assert investigation and investigation.get("decision")
    assert investigation["decision"]["headline"]
    assert investigation["decision"]["decision"] in {"dont_pay", "pause_and_verify", "cant_tell_yet", "pay_only_safely"}
    public_report = json.dumps(investigation["decision"]).casefold()
    for internal in ("not_configured", "api_key", "tavily", "gemini", "organisation"):
        assert internal not in public_report


def test_decision_report_hides_unsanitised_raw_findings_panel():
    from pathlib import Path
    app_js = Path(__file__).parents[1] / "app" / "static" / "app.js"
    source = app_js.read_text(encoding="utf-8")
    assert "if (!inv.decision && inv.findings && inv.findings.length)" in source
