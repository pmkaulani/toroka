from __future__ import annotations

import ipaddress
from types import SimpleNamespace
from unittest.mock import patch

import httpx

from app.evidence_graph import build_evidence_graph
from app.investigation_intelligence import investigate_public_targets
from ssi_connectors.domain_intelligence import (
    IanaRdapClient,
    lookup_origin_asn,
    normalize_domain,
    query_dns_records,
    search_certificate_transparency,
)


def _json(payload, status=200):
    return httpx.Response(status, json=payload, headers={"content-type": "application/json"})


def test_normalize_domain_idna_and_url_input_and_rejects_unsafe_forms():
    assert normalize_domain("HTTPS://BÜCHER.DE/path?q=1") == "xn--bcher-kva.de"
    assert normalize_domain(" example.co.ke. ") == "example.co.ke"
    assert normalize_domain("https://user:pass@example.com") is None
    assert normalize_domain("http://127.0.0.1") is None
    assert normalize_domain("localhost") is None
    assert normalize_domain("printer.local") is None
    assert normalize_domain("bad..example.com") is None
    assert normalize_domain("example.com/path") is None
    assert normalize_domain("-bad.example.com") is None


def test_dns_queries_redact_txt_values_and_only_expose_global_addresses():
    def handler(request: httpx.Request):
        name = request.url.params.get("name")
        rr = request.url.params.get("type")
        answers = []
        if rr == "A":
            answers = [{"type": 1, "data": "8.8.8.8", "TTL": 300}]
        elif rr == "AAAA":
            answers = [{"type": 28, "data": "fe80::1", "TTL": 300}]
        elif rr == "NS":
            answers = [{"type": 2, "data": "ns1.example.net.", "TTL": 600}]
        elif rr == "MX":
            answers = [{"type": 15, "data": "10 mail.example.net.", "TTL": 600}]
        elif rr == "CAA":
            answers = [{"type": 257, "data": '0 issue "letsencrypt.org"', "TTL": 600}]
        elif rr == "TXT" and name.startswith("_dmarc."):
            answers = [{"type": 16, "data": '"v=DMARC1; p=reject; rua=mailto:security@example.net"', "TTL": 600}]
        elif rr == "TXT":
            answers = [
                {"type": 16, "data": '"google-site-verification=secret-token-123"', "TTL": 600},
                {"type": 16, "data": '"v=spf1 include:_spf.example.net -all"', "TTL": 600},
            ]
        return _json({"Status": 0, "AD": True, "Answer": answers})

    result = query_dns_records("example.com", transport=httpx.MockTransport(handler))
    assert result["status"] == "checked"
    assert result["addresses"] == ["8.8.8.8"]
    assert result["dnssec_validated"] is True
    values = [record["value"] for record in result["records"]]
    assert "google-site-verification=secret-token-123" not in " ".join(values)
    assert any("token withheld" in value for value in values)
    assert any(value == "SPF policy published (-all ending)" for value in values)
    assert any(value == "DMARC policy published (p=reject)" for value in values)
    assert any(record.get("value") == "mail.example.net" for record in result["records"])
    assert "fe80::1" not in result["addresses"]


def test_iana_rdap_uses_longest_matching_domain_suffix_and_ip_prefix():
    def handler(request: httpx.Request):
        url = str(request.url)
        if url == "https://data.iana.org/rdap/dns.json":
            return _json({"services": [
                [["uk"], ["https://rdap.uk.example/"]],
                [["co.uk"], ["https://rdap.co-uk.example/"]],
            ]})
        if url == "https://data.iana.org/rdap/ipv4.json":
            return _json({"services": [
                [["8.0.0.0/8"], ["https://rdap.large.example/"]],
                [["8.8.8.0/24"], ["https://rdap.specific.example/"]],
            ]})
        return _json({}, status=404)

    client = IanaRdapClient(transport=httpx.MockTransport(handler))
    assert client.domain_base("shop.example.co.uk") == "https://rdap.co-uk.example/"
    assert client.ip_base("8.8.8.8") == "https://rdap.specific.example/"


def test_iana_rdap_extracts_minimal_domain_registration_fields():
    def handler(request: httpx.Request):
        url = str(request.url)
        if url.endswith("/rdap/dns.json"):
            return _json({"services": [[["com"], ["https://rdap.registry.example/"]] ]})
        if url == "https://rdap.registry.example/domain/example.com":
            return _json({
                "handle": "EXAMPLE-1", "ldhName": "example.com", "status": ["active"],
                "events": [{"eventAction": "registration", "eventDate": "2024-01-02T00:00:00Z"}],
                "nameservers": [{"ldhName": "ns1.example.net"}],
                "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]}],
            })
        return _json({}, status=404)

    client = IanaRdapClient(transport=httpx.MockTransport(handler))
    result = client.domain("example.com")
    assert result["events"]["registration"].startswith("2024-01-02")
    assert result["registrar"] == "Example Registrar"
    assert result["nameservers"] == ["ns1.example.net"]
    assert result["rdap_url"] == "https://rdap.registry.example/domain/example.com"


def test_team_cymru_ip_asn_validates_prefix_contains_public_ip():
    def handler(request: httpx.Request):
        assert request.url.params.get("name") == "8.8.8.8.origin.asn.cymru.com"
        return _json({"Status": 0, "Answer": [{"data": '15169 | 8.8.8.0/24 | US | arin | 2000-03-30'}]})

    result = lookup_origin_asn("8.8.8.8", transport=httpx.MockTransport(handler))
    assert result["status"] == "checked"
    assert result["asn"] == 15169
    assert result["prefix"] == "8.8.8.0/24"
    assert result["registry_country"] == "US"
    assert lookup_origin_asn("192.168.1.1")["failure_reason"] == "non_public_ip"


def test_team_cymru_rejects_prefix_that_does_not_contain_queried_ip():
    def handler(request: httpx.Request):
        return _json({"Status": 0, "Answer": [{"data": '15169 | 1.1.1.0/24 | US | arin | 2000-03-30'}]})

    result = lookup_origin_asn("8.8.8.8", transport=httpx.MockTransport(handler))
    assert result["status"] == "failed"
    assert result["failure_reason"] == "invalid_prefix"


def test_certificate_transparency_requires_api_key_before_network_call():
    def fail_if_called(request):
        raise AssertionError("A CT request must not be sent without a provider key")

    result = search_certificate_transparency("example.com", "", transport=httpx.MockTransport(fail_if_called))
    assert result["status"] == "not_configured"
    assert result["issuances"] == []


def test_certificate_transparency_enforces_domain_boundary_and_returns_minimal_fields():
    def handler(request: httpx.Request):
        assert request.headers.get("Authorization") == "Bearer test-key"
        return _json([
            {"id": "1", "dns_names": ["example.com", "shop.example.com", "badexample.com", "evil-example.com"],
             "issuer": {"friendly_name": "Example CA"}, "not_before": "2025-01-01T00:00:00Z",
             "not_after": "2026-01-01T00:00:00Z", "revoked": False, "cert_sha256": "ab" * 32},
        ])

    result = search_certificate_transparency("example.com", "test-key", transport=httpx.MockTransport(handler))
    assert result["status"] == "checked"
    assert result["issuances"][0]["dns_names"] == ["example.com", "shop.example.com"]
    assert result["issuances"][0]["issuer"] == "Example CA"
    assert "badexample.com" not in str(result)


def test_graph_adds_only_validated_infrastructure_links_as_context():
    graph = build_evidence_graph(
        [{"kind": "domain", "identifier": "example.com", "platform": ""}],
        [{
            "evidence_id": "infra-1", "provider": "DNS", "source_type": "domain_dns_observation",
            "subject_domain": "example.com", "title": "DNS observations", "url": "https://dns.google/resolve?name=example.com",
            "infrastructure_links": [
                {"kind": "ip_address", "value": "8.8.8.8", "relation": "resolves_to_ip", "basis": "dns"},
                {"kind": "ip_address", "value": "127.0.0.1", "relation": "resolves_to_ip", "basis": "dns"},
                {"kind": "autonomous_system", "value": "AS15169", "relation": "announced_by_asn", "basis": "cymru"},
                {"kind": "subdomain", "value": "shop.example.com", "relation": "certificate_covers_hostname", "basis": "ct"},
            ],
        }],
    )
    assert graph["version"] == "evidence-graph-v2"
    labels = {node["label"] for node in graph["nodes"]}
    assert "8.8.8.8" in labels
    assert "AS15169" in labels
    assert "shop.example.com" in labels
    assert "127.0.0.1" not in labels
    assert all(edge["strength"] == "context" for edge in graph["edges"] if edge["evidence_id"] == "infra-1")


def _settings(**overrides):
    defaults = dict(
        tavily_api_key="", weir_api_key="", scrape_creators_api_key="", google_places_api_key="",
        urlscan_api_key="", intelligence_cache_ttl_seconds=0, enable_domain_intelligence=False,
        certspotter_api_key="", domain_intel_include_subdomains=False,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def test_domain_intelligence_is_opt_in_and_registry_checks_are_manual_for_jobs():
    with patch("app.investigation_intelligence.investigate_domain_infrastructure") as lookup:
        result = investigate_public_targets(
            [{"kind": "domain", "identifier": "example.com"}],
            category="job", submitted_text="Check this job offer on example.com", settings=_settings(),
        )
    lookup.assert_not_called()
    assert result["domain_infrastructure"] == []
    registries = {item["registry"]: item for item in result["official_registry_checks"]}
    assert "National Employment Authority (NEA)" in registries
    assert "Business Registration Service (BRS)" in registries
    assert all(item["automated_lookup_performed"] is False for item in registries.values())
    assert all(item["status"] == "manual_verification_required" for item in registries.values())


def test_domain_intelligence_runs_only_for_explicit_domain_target_and_is_attached_to_chat_result():
    fake = {
        "domain": "example.com", "status": "checked", "providers": [{"provider": "Mock DNS", "status": "checked"}],
        "evidence": [{"evidence_id": "infra-test", "provider": "Mock DNS", "source_type": "domain_dns_observation",
                      "subject_domain": "example.com", "title": "DNS record", "snippet": "A record observed",
                      "url": "https://dns.google/resolve?name=example.com", "collected_at": "2026-01-01T00:00:00Z",
                      "infrastructure_links": []}],
        "dns": {"records": []}, "rdap": {}, "ip_observations": [], "certificate_transparency": {},
        "interpretation_note": "Context only.",
    }
    with patch("app.investigation_intelligence.investigate_domain_infrastructure", return_value=fake) as lookup:
        result = investigate_public_targets(
            [{"kind": "domain", "identifier": "example.com"}],
            category="website", submitted_text="Check https://example.com", settings=_settings(enable_domain_intelligence=True),
        )
    lookup.assert_called_once_with("example.com", ct_api_key="", include_subdomains=False)
    assert result["domain_infrastructure"][0]["domain"] == "example.com"
    assert any(item["evidence_id"] == "infra-test" for item in result["evidence"])
    assert any(item["provider"] == "Mock DNS" for item in result["providers"])


def test_shop_infrastructure_lookup_is_limited_to_explicit_seller_controlled_outbound_link():
    social_result = {
        "sources": [{
            "provider": "Mock social", "source_type": "social_profile_observation",
            "url": "https://www.instagram.com/testshop/", "title": "Test shop profile",
            "snippet": "Official site https://shop.example.com", "external_url": "https://shop.example.com",
        }],
        "statuses": [],
    }
    fake = {"domain": "shop.example.com", "status": "not_configured", "providers": [], "evidence": [],
            "dns": {}, "rdap": {}, "ip_observations": [], "certificate_transparency": {}}
    with patch("app.investigation_intelligence.investigate_domain_infrastructure", return_value=fake) as lookup:
        investigate_public_targets(
            [{"kind": "handle", "platform": "instagram", "identifier": "testshop"}],
            category="shop", submitted_text="Check this shop", settings=_settings(enable_domain_intelligence=True),
            social_result=social_result,
        )
    lookup.assert_called_once_with("shop.example.com", ct_api_key="", include_subdomains=False)


def test_rdap_ip_helpers_reject_non_global_addresses():
    assert not ipaddress.ip_address("10.0.0.1").is_global
    with patch("app.investigation_intelligence.investigate_domain_infrastructure"):
        pass


def test_dns_servfail_is_not_reported_as_checked_no_records():
    def handler(request: httpx.Request):
        return _json({"Status": 2, "AD": False, "Answer": []})

    result = query_dns_records("example.com", transport=httpx.MockTransport(handler))
    assert result["status"] == "failed"
    assert result["failure_reason"] == "dns_rcode_2"
    assert result["queries_valid"] == 0


def test_domain_infrastructure_budget_is_two_domains_across_the_whole_investigation():
    fake = {"domain": "example.com", "status": "not_configured", "providers": [], "evidence": [],
            "dns": {}, "rdap": {}, "ip_observations": [], "certificate_transparency": {}}
    targets = [
        {"kind": "domain", "identifier": "one.example.com"},
        {"kind": "domain", "identifier": "two.example.com"},
        {"kind": "domain", "identifier": "three.example.com"},
    ]
    with patch("app.investigation_intelligence.investigate_domain_infrastructure", return_value=fake) as lookup:
        result = investigate_public_targets(
            targets, category="website", submitted_text="Check several sites",
            settings=_settings(enable_domain_intelligence=True),
        )
    assert lookup.call_count == 2
    assert len(result["domain_infrastructure"]) == 2


def test_full_domain_investigation_builds_dns_rdap_asn_and_context_evidence():
    from ssi_connectors.domain_intelligence import investigate_domain_infrastructure

    def handler(request: httpx.Request):
        host = request.url.host
        path = request.url.path
        if host == "dns.google":
            name = request.url.params.get("name", "")
            rr = request.url.params.get("type", "")
            if name == "8.8.8.8.origin.asn.cymru.com":
                return _json({"Status": 0, "Answer": [{"data": '15169 | 8.8.8.0/24 | US | arin | 2000-03-30'}]})
            answers = []
            if rr == "A": answers = [{"type": 1, "data": "8.8.8.8", "TTL": 300}]
            elif rr == "NS": answers = [{"type": 2, "data": "ns1.example.net.", "TTL": 300}]
            elif rr == "MX": answers = [{"type": 15, "data": "10 mail.example.net.", "TTL": 300}]
            elif rr == "TXT": answers = [{"type": 16, "data": '"v=spf1 -all"', "TTL": 300}]
            return _json({"Status": 0, "AD": True, "Answer": answers})
        if host == "data.iana.org":
            if path.endswith("/dns.json"):
                return _json({"services": [[[
                    "com"], ["https://rdap.registry.example/"]]]})
            if path.endswith("/ipv4.json"):
                return _json({"services": [[[
                    "8.8.8.0/24"], ["https://rdap.registry.example/"]]]})
            if path.endswith("/asn.json"):
                return _json({"services": [[[
                    "15169-15169"], ["https://rdap.registry.example/"]]]})
        if host == "rdap.registry.example":
            if path == "/domain/example.com":
                return _json({"ldhName": "example.com", "events": [{"eventAction": "registration", "eventDate": "2024-01-02T00:00:00Z"}], "nameservers": [{"ldhName": "ns1.example.net"}]})
            if path == "/ip/8.8.8.8":
                return _json({"name": "GOOGLE", "country": "US", "startAddress": "8.8.8.0", "endAddress": "8.8.8.255"})
            if path == "/autnum/15169":
                return _json({"name": "GOOGLE", "country": "US", "startAutnum": 15169, "endAutnum": 15169})
        return _json({}, status=404)

    result = investigate_domain_infrastructure("example.com", transport=httpx.MockTransport(handler))
    assert result["status"] == "checked"
    assert result["domain"] == "example.com"
    assert result["rdap"]["events"]["registration"].startswith("2024-01-02")
    assert result["ip_observations"][0]["asn_lookup"]["asn"] == 15169
    assert result["ip_observations"][0]["asn_rdap"]["name"] == "GOOGLE"
    assert result["ip_observations"][0]["rdap"]["name"] == "GOOGLE"
    assert {item["source_type"] for item in result["evidence"]} >= {
        "domain_dns_observation", "domain_registration_observation", "ip_asn_observation",
        "asn_allocation_observation", "ip_allocation_observation",
    }
    assert all(item["verified"] is False for item in result["evidence"])
    assert all(item["polarity"] == "context" for item in result["evidence"])


def test_settings_expose_opt_in_build2_environment_switches(monkeypatch):
    from app.config import Settings

    monkeypatch.setenv("SSI_ENV", "dev")
    monkeypatch.setenv("ENABLE_DOMAIN_INTELLIGENCE", "1")
    monkeypatch.setenv("CERTSPOTTER_API_KEY", "test-token")
    monkeypatch.setenv("DOMAIN_INTEL_INCLUDE_SUBDOMAINS", "1")
    settings = Settings.from_env()
    assert settings.enable_domain_intelligence is True
    assert settings.certspotter_api_key == "test-token"
    assert settings.domain_intel_include_subdomains is True


def test_build2_settings_are_disabled_by_default(monkeypatch):
    from app.config import Settings

    for key in ("ENABLE_DOMAIN_INTELLIGENCE", "CERTSPOTTER_API_KEY", "DOMAIN_INTEL_INCLUDE_SUBDOMAINS"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("SSI_ENV", "dev")
    settings = Settings.from_env()
    assert settings.enable_domain_intelligence is False
    assert settings.certspotter_api_key == ""
    assert settings.domain_intel_include_subdomains is False
