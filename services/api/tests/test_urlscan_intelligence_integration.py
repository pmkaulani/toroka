from unittest.mock import patch

from app.config import Settings
from app.evidence_graph import build_evidence_graph
from app.investigation_intelligence import investigate_public_targets, upgrade_url_assessment


def _scan_result(domain="example.co.ke", malicious=True):
    return {
        "status": "checked",
        "provider": "urlscan.io",
        "detail": f"One historical scan record for {domain}.",
        "results_retrieved": 1,
        "results_relevant": 1,
        "search_date_limit_days": 90,
        "results": [{
            "scan_id": "scan-123",
            "domain": domain,
            "scan_date": "2026-10-01T12:00:00Z",
            "page_title": "Account Login",
            "malicious_verdict": malicious,
            "verdict_score": 85,
            "redirected": "https://elsewhere.example/login",
            "visibility": "public",
            "result_url": "https://urlscan.io/result/scan-123/",
        }],
    }


def test_domain_investigation_adds_historical_scanner_evidence_but_does_not_auto_upgrade_risk():
    settings = Settings(urlscan_api_key="test-key", intelligence_cache_ttl_seconds=0)
    with patch("app.investigation_intelligence.search_historical_domain", return_value=_scan_result()) as lookup:
        result = investigate_public_targets(
            [{"kind": "domain", "identifier": "example.co.ke"}],
            category="website", submitted_text="Please check https://example.co.ke", settings=settings,
        )

    lookup.assert_called_once_with("test-key", "example.co.ke")
    evidence = next(item for item in result["evidence"] if item["source_type"] == "urlscan_historical_scan")
    assert evidence["malicious_verdict"] is True
    assert evidence["identity_match"] == "exact_domain_historical_scan_match"
    assert "historical observation" in evidence["snippet"]
    provider = next(item for item in result["providers"] if item["provider"] == "urlscan.io")
    assert provider["status"] == "checked"
    flag = next(item for item in result["red_flags"] if item["code"] == "URLSCAN_HISTORICAL_MALICIOUS_VERDICT")
    assert flag["severity"] == "supporting"
    assert upgrade_url_assessment("inconclusive", result["red_flags"])[0] == "inconclusive"
    assert any(edge["relation"] == "supported_by_source" and edge["evidence_id"] == evidence["evidence_id"] for edge in result["evidence_graph"]["edges"])


def test_shop_profile_external_domain_is_linked_to_historical_scan_as_context_only():
    settings = Settings(urlscan_api_key="test-key", intelligence_cache_ttl_seconds=0)
    social_result = {
        "sources": [{
            "provider": "Instagram",
            "platform": "Instagram",
            "source_type": "social_profile_observation",
            "searched_identifier": "base_menswear",
            "url": "https://www.instagram.com/base_menswear/",
            "title": "Base Menswear",
            "snippet": "Official clothing shop. Based in Westlands, Nairobi.",
            "external_url": "https://basemenswear.example/shop",
        }],
        "statuses": [],
    }
    with patch("app.investigation_intelligence.search_historical_domain", return_value=_scan_result("basemenswear.example", True)) as lookup:
        result = investigate_public_targets(
            [{"kind": "handle", "platform": "instagram", "identifier": "base_menswear"}],
            category="shop", submitted_text="Check this Instagram shop", settings=settings,
            social_result=social_result,
        )

    lookup.assert_called_once_with("test-key", "basemenswear.example")
    profile = next(item for item in result["evidence"] if item["source_type"] == "social_public_profile_observation")
    historical = next(item for item in result["evidence"] if item["source_type"] == "urlscan_historical_scan")
    assert historical["linked_from_evidence_id"] == profile["evidence_id"]
    edge = next(edge for edge in result["evidence_graph"]["edges"] if edge["relation"] == "linked_domain_has_historical_scan")
    assert edge["strength"] == "context"
    assert edge["evidence_id"] == historical["evidence_id"]
    assert not any(edge["strength"] == "strong" and edge["evidence_id"] == historical["evidence_id"] for edge in result["evidence_graph"]["edges"])


def test_evidence_graph_preserves_profile_to_historical_domain_scan_chain():
    graph = build_evidence_graph(
        [{"kind": "handle", "platform": "instagram", "identifier": "base_menswear"}],
        [
            {"evidence_id": "profile-1", "source_type": "social_public_profile_observation", "identity_match": "exact_social_profile_match", "target_identifier": "base_menswear", "title": "Base Menswear", "url": "https://www.instagram.com/base_menswear/"},
            {"evidence_id": "scan-1", "source_type": "urlscan_historical_scan", "identity_match": "seller_published_external_domain_historical_scan", "target_identifier": "base_menswear", "linked_from_evidence_id": "profile-1", "related_domain": "basemenswear.example", "title": "Old scan", "url": "https://urlscan.io/result/scan-1/"},
        ],
    )
    relations = {edge["relation"] for edge in graph["edges"]}
    assert "linked_domain_has_historical_scan" in relations
    assert "historical_scan_of_domain" in relations
