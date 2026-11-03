import httpx

from ssi_connectors.urlscan import normalize_domain, search_historical_domain


def test_normalize_domain_rejects_urls_with_credentials_and_bad_hosts():
    assert normalize_domain("EXAMPLE.co.ke") == "example.co.ke"
    assert normalize_domain("https://sub.example.co.ke/path") == "sub.example.co.ke"
    assert normalize_domain("https://user:pass@example.com") is None
    assert normalize_domain("example.com?token=secret") is None
    assert normalize_domain("localhost") is None


def test_historical_search_returns_exact_domain_records_and_scanner_context():
    seen = {}

    def handler(request: httpx.Request):
        seen["url"] = str(request.url)
        seen["key"] = request.headers.get("api-key")
        return httpx.Response(200, json={
            "total": 3,
            "search_date_limit_days": 90,
            "results": [
                {
                    "task": {"uuid": "scan-123", "domain": "shop.example.co.ke", "visibility": "public", "time": "2026-10-01"},
                    "page": {"title": "Login", "url": "https://shop.example.co.ke/login", "redirected": "same-domain"},
                    "verdicts": {"malicious": True, "score": 85},
                },
                {
                    "task": {"uuid": "wrong-456", "domain": "notexample.co.ke", "visibility": "public"},
                    "page": {"title": "Unrelated"},
                },
            ],
        })

    result = search_historical_domain("secret-key", "example.co.ke", transport=httpx.MockTransport(handler))
    assert result["status"] == "checked"
    assert result["results_retrieved"] == 3
    assert result["results_relevant"] == 1
    assert result["results"][0]["malicious_verdict"] is True
    assert result["results"][0]["result_url"].endswith("scan-123/")
    assert seen["key"] == "secret-key"
    assert "task.domain%3Aexample.co.ke" in seen["url"]
    assert "last 90 days" in result["detail"]


def test_no_scan_matches_is_not_a_safe_result():
    result = search_historical_domain("secret-key", "example.co.ke", transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"results": [], "total": 0})))
    assert result["status"] == "checked_no_match"
    assert "not a clean bill" in result["detail"]


def test_urlscan_missing_key_and_provider_outage_are_not_clean():
    assert search_historical_domain("", "example.co.ke")["status"] == "not_configured"
    failed = search_historical_domain("key", "example.co.ke", transport=httpx.MockTransport(lambda req: httpx.Response(429)))
    assert failed["status"] == "failed"
    assert failed["failure_reason"] == "http_429"
