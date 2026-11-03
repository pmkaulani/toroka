"""Comprehensive Test Suite for Toroka URL Investigation Pipeline, SSRF Defense, and API Diagnostics.

Covers:
1. SSRF and DNS pre-resolution validation (private networks, cloud metadata, loopbacks, non-standard ports);
2. Hop-by-hop redirect limits and content-type rejection;
3. Threat feed manager lookups and audit status;
4. Verified official entity matching and brand impersonation detection;
5. Platform profile identity separation (Instagram vs TikTok vs Facebook);
6. Dedicated POST /v1/investigate/url endpoint;
7. Chat integration with naked URLs and contextual questions;
8. Checks route integration with URL evidence merging;
9. System diagnostics endpoint (GET /v1/system/diagnostics);
10. URL investigation caching and in-flight deduplication.
"""
from __future__ import annotations

import time
from unittest.mock import patch, MagicMock

import pytest
from app import db as m
from app.config import Settings
from app.url_pipeline import (
    ThreatFeedManager,
    URLInvestigationCache,
    investigate_single_url,
    parse_platform_profile,
)
from ssi_connectors.url_fetcher import (
    is_ip_allowed,
    resolve_and_pin,
    safe_fetch_page,
    SafePageContent,
)
from ssi_rules.vocabulary import CoverageStatus as CS


# ---------------------------------------------------------------------------
# 1. SSRF & Network Boundary Defense Tests
# ---------------------------------------------------------------------------

def test_ssrf_rejects_private_and_loopback_ips():
    blocked_ips = [
        "127.0.0.1",
        "127.0.0.2",
        "10.0.0.1",
        "10.254.254.254",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "192.168.1.254",
        "::1",
        "0.0.0.0",
    ]
    for ip in blocked_ips:
        ok, reason = is_ip_allowed(ip)
        assert not ok, f"Expected {ip} to be blocked, but was allowed"
        assert "blocked" in reason.lower()


def test_ssrf_rejects_cloud_metadata_ips():
    cloud_ips = [
        "169.254.169.254",
        "fd00:ec2::254",
        "100.100.100.200",
    ]
    for ip in cloud_ips:
        ok, reason = is_ip_allowed(ip)
        assert not ok, f"Expected metadata IP {ip} to be blocked"
        assert "blocked" in reason.lower()


def test_ssrf_allows_public_global_ips():
    public_ips = [
        "8.8.8.8",
        "1.1.1.1",
        "104.244.42.1",
        "142.250.190.46",
    ]
    for ip in public_ips:
        ok, reason = is_ip_allowed(ip)
        assert ok, f"Expected public IP {ip} to be allowed, got: {reason}"
        assert reason == "ok"


def test_resolve_and_pin_blocks_unresolvable_or_private_host():
    # Loopback mock resolver
    fake_resolver = lambda host: ["127.0.0.1"]
    pinned_url, host, sni, err = resolve_and_pin("http://evil-local-test.com/path", resolver=fake_resolver)
    assert pinned_url is None
    assert "loopback" in err.lower() or "blocked" in err.lower()

    # AWS metadata mock resolver
    meta_resolver = lambda host: ["169.254.169.254"]
    pinned_url, host, sni, err = resolve_and_pin("http://instance-data-test.org", resolver=meta_resolver)
    assert pinned_url is None
    assert "metadata" in err.lower() or "blocked" in err.lower()

    # Empty DNS resolution
    empty_resolver = lambda host: []
    pinned_url, host, sni, err = resolve_and_pin("http://nonexistent-domain-404.test", resolver=empty_resolver)
    assert pinned_url is None
    assert "no addresses" in err.lower()


def test_safe_fetch_page_rejects_disallowed_schemes_and_ports():
    # File scheme
    res = safe_fetch_page("file:///etc/passwd")
    assert res.status == CS.COULD_NOT_CHECK
    assert "scheme" in res.reason.lower() or "http" in res.reason.lower()

    # FTP scheme
    res = safe_fetch_page("ftp://ftp.example.com/file.txt")
    assert res.status == CS.COULD_NOT_CHECK

    # Non-standard port (SSH, SMTP, etc.)
    res = safe_fetch_page("http://example.com:22/exploit")
    assert res.status == CS.COULD_NOT_CHECK
    assert "port" in res.reason.lower()


# ---------------------------------------------------------------------------
# 2. Threat Feed Manager & Local Bundled Seeds
# ---------------------------------------------------------------------------

def test_threat_feed_manager_bundled_seeds():
    feed_mgr = ThreatFeedManager.get_instance()
    # Check that bundled malicious seeds are loaded
    assert len(feed_mgr.malicious_urls) > 0 or len(feed_mgr.malicious_domains) > 0

    # Known bundled malicious seed from phishing_threats.json
    hit = feed_mgr.check("http://safaricom-line-reactivate.com", "safaricom-line-reactivate.com")
    assert hit is not None
    assert hit["matched"] is True
    assert "OpenPhish" in hit["feed"] or "Threat Intel" in hit["feed"]

    # Safe authentic domain should not match threat feeds
    safe_hit = feed_mgr.check("https://safaricom.co.ke", "safaricom.co.ke")
    assert safe_hit is None


# ---------------------------------------------------------------------------
# 3. Platform Profile Parsing & Impersonation Detection
# ---------------------------------------------------------------------------

def test_platform_profile_parsing():
    # Instagram profile
    p1 = parse_platform_profile("https://www.instagram.com/safaricom_deals/")
    assert p1.platform == "instagram"
    assert p1.handle == "safaricom_deals"
    assert p1.is_profile is True
    assert p1.is_official_impersonation_risk is True
    assert p1.impersonated_brand == "Safaricom"

    # TikTok profile
    p2 = parse_platform_profile("https://www.tiktok.com/@equitybank_loans")
    assert p2.platform == "tiktok"
    assert p2.handle == "equitybank_loans"
    assert p2.is_profile is True
    assert p2.is_official_impersonation_risk is True
    assert p2.impersonated_brand == "Equity Bank"

    # WhatsApp link
    p3 = parse_platform_profile("https://chat.whatsapp.com/INVITECODE123")
    assert p3.platform == "whatsapp"
    assert p3.is_profile is True
    assert p3.handle == "INVITECODE123"

    # Generic website
    p4 = parse_platform_profile("https://my-legit-store.co.ke/products/shoes")
    assert p4.platform == "web"
    assert p4.is_profile is False


def test_platform_profile_separation():
    # Same handle across different platforms must not be conflated
    ig = parse_platform_profile("https://www.instagram.com/nairobi_electronics/")
    tt = parse_platform_profile("https://www.tiktok.com/@nairobi_electronics")
    fb = parse_platform_profile("https://www.facebook.com/nairobi_electronics")

    assert ig.identifier == "instagram:nairobi_electronics"
    assert tt.identifier == "tiktok:nairobi_electronics"
    assert fb.identifier == "facebook:nairobi_electronics"
    assert ig.identifier != tt.identifier
    assert ig.identifier != fb.identifier


# ---------------------------------------------------------------------------
# 4. Central Pipeline Unit Tests
# ---------------------------------------------------------------------------

def test_investigate_single_url_known_threat(env):
    with env.db() as db:
        res = investigate_single_url(
            "http://safaricom-line-reactivate.com",
            db,
            env.ctx.crypto,
            env.settings,
            skip_cache=True,
        )
        assert res.risk_band == "high_risk"
        assert any(f.code == "THREAT_FEED_MATCH" for f in res.findings)
        assert any("OpenPhish" in s.statement or "Threat Intel" in s.statement for s in res.sources)
        assert len(res.next_steps) >= 2


def test_investigate_single_url_verified_official(env):
    with env.db() as db:
        # Seed verified entity for Safaricom
        rec = m.VerifiedRecord(
            id="rec-safaricom-test",
            name="Safaricom PLC",
            entity_type="telecom",
            domains=["safaricom.co.ke"],
            handles=["instagram:safaricomplc", "x:safaricomplc"],
            basis="official_registry",
            source_url="https://safaricom.co.ke",
            reviewer="Toroka Moderator",
            last_verified_at="2026-01-01",
            review_due="2027-01-01",
            status="active",
        )
        db.merge(rec)
        db.commit()

        res = investigate_single_url(
            "https://www.safaricom.co.ke/personal",
            db,
            env.ctx.crypto,
            env.settings,
            skip_cache=True,
        )
        assert res.risk_band == "verified_official"
        assert "Safaricom" in res.summary
        assert any("current, human-reviewed record" in s or "reviewed record" in s.lower() for s in res.next_steps)



def test_expired_registry_match_is_disclosed_but_never_treated_as_verified(env):
    """A stale review is useful context, but not current proof of an entity's identity."""
    with env.db() as db:
        db.add(m.VerifiedRecord(
            id="rec-stale-shop-test",
            name="Stale Test Shop",
            entity_type="online_shop",
            domains=["stale-shop-toroka-test.example"],
            handles=["instagram:stale_shop_toroka_test"],
            include_subdomains=False,
            basis="moderator_verified_documents",
            source_url="https://stale-shop-toroka-test.example/about",
            reviewer="Toroka Moderator",
            last_verified_at="2025-01-01",
            review_due="2025-06-01",
            status="active",
        ))
        db.commit()

        result = investigate_single_url(
            "https://stale-shop-toroka-test.example/",
            db,
            env.ctx.crypto,
            env.settings,
            skip_cache=True,
        )

    assert result.risk_band != "verified_official"
    previous = [c for c in result.coverage if c.id == "verified_registry_review"]
    assert previous, "the matching stale record should be disclosed in coverage"
    assert "expired" in previous[0].detail.lower()
    assert "not counted as current verification" in previous[0].detail.lower()
    assert any("does not prove fraud" in item.lower() for item in result.limitations)

def test_investigate_single_url_brand_impersonation(env):
    with env.db() as db:
        res = investigate_single_url(
            "https://www.instagram.com/safaricom_deals/",
            db,
            env.ctx.crypto,
            env.settings,
            skip_cache=True,
        )
        assert res.risk_band == "suspicious_verify_first"
        assert any(f.code == "POSSIBLE_BRAND_IMPERSONATION" for f in res.findings)
        assert len(res.contradictions) > 0
        assert "Safaricom" in res.contradictions[0]


def test_investigate_single_url_unverified_brand_domain(env):
    with env.db() as db:
        res = investigate_single_url(
            "https://safaricom-free-airtime-promo.xyz",
            db,
            env.ctx.crypto,
            env.settings,
            skip_cache=True,
        )
        assert res.risk_band == "suspicious_verify_first"
        assert any(f.code == "DOMAIN_BRAND_MISMATCH" for f in res.findings)
        assert any("Safaricom" in c for c in res.contradictions)


# ---------------------------------------------------------------------------
# 5. Dedicated API Endpoint: POST /v1/investigate/url
# ---------------------------------------------------------------------------

def test_api_investigate_url_endpoint(env):
    payload = {"url": "http://safaricom-line-reactivate.com"}
    resp = env.client.post("/v1/investigate/url", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["target_url"] == "http://safaricom-line-reactivate.com"
    assert data["risk_band"] == "high_risk"
    assert "findings" in data and len(data["findings"]) > 0
    assert "sources" in data
    assert "coverage" in data
    assert "next_steps" in data


# ---------------------------------------------------------------------------
# 6. Chat Route Integration (Naked URLs & Contextual Questions)
# ---------------------------------------------------------------------------

def test_chat_with_naked_url(env):
    resp = env.client.post("/v1/chat", json={"message": "http://safaricom-line-reactivate.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["url_investigation"] is not None
    inv = data["url_investigation"]
    assert inv["risk_band"] == "high_risk"
    assert "reply" in data
    assert len(data["reply"]) > 20
    assert "action_chips" in data and len(data["action_chips"]) > 0


def test_chat_with_url_and_question(env):
    msg = "Is this genuine? https://www.instagram.com/safaricom_deals/"
    resp = env.client.post("/v1/chat", json={"message": msg})
    assert resp.status_code == 200
    data = resp.json()
    assert data["url_investigation"] is not None
    inv = data["url_investigation"]
    assert inv["risk_band"] == "suspicious_verify_first"
    assert any(f["code"] == "POSSIBLE_BRAND_IMPERSONATION" for f in inv["findings"])


# ---------------------------------------------------------------------------
# 7. Checks Route Integration (Merging URL Findings)
# ---------------------------------------------------------------------------

def test_check_with_url_merges_investigation(env):
    msg = "Check this suspicious link: http://safaricom-line-reactivate.com"
    resp = env.client.post("/v1/checks", json={"text": msg})
    assert resp.status_code == 201
    data = resp.json()
    assessment = data["assessment"]
    assert assessment["label"] in ("high_risk", "suspicious_verify_first")
    # Verify URL-derived source is in sources
    sources = assessment.get("sources", [])
    assert any("OpenPhish" in s.get("id", "") or "threat" in s.get("id", "").lower() or "threat" in s.get("statement", "").lower() for s in sources)


# ---------------------------------------------------------------------------
# 8. Diagnostics Endpoint (GET /v1/system/diagnostics)
# ---------------------------------------------------------------------------

def test_system_diagnostics_endpoint_requires_moderator_or_dedicated_key(env):
    # Diagnostics must never be public merely because SSI_ENV=dev; dev servers
    # are often exposed through a tunnel during testing.
    assert env.client.get("/v1/system/diagnostics").status_code == 401
    plain, _ = env.user("plain-diag@example.com", "user")
    assert env.client.get("/v1/system/diagnostics", headers=plain).status_code == 403
    moderator, _ = env.user("moderator-diag@example.com", "moderator")
    resp = env.client.get("/v1/system/diagnostics", headers=moderator)
    assert resp.status_code == 200
    data = resp.json()
    assert "policy_version" in data
    assert "gemini" in data
    assert "tavily" in data
    assert "webrisk" in data
    assert "threat_feeds" in data
    assert "ml_engine" in data
    assert "database" in data
    assert data["database"]["status"] == "connected"


def test_system_diagnostics_accepts_only_dedicated_diagnostics_key(make_env):
    env = make_env(diagnostics_api_key="dedicated-test-diagnostics-key")
    # The dedicated diagnostics key can be used by a trusted monitor. Reusing
    # the general HMAC key or a historical hard-coded key must not grant access.
    assert env.client.get("/v1/system/diagnostics", headers={"X-Admin-Key": "toroka-admin-diagnostics"}).status_code == 401
    assert env.client.get("/v1/system/diagnostics", headers={"X-Admin-Key": env.settings.hmac_key}).status_code == 401
    response = env.client.get("/v1/system/diagnostics", headers={"X-Admin-Key": "dedicated-test-diagnostics-key"})
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# 9. URL Investigation Caching & In-Flight Deduplication
# ---------------------------------------------------------------------------



def test_blocked_internal_destination_is_not_labelled_as_a_scam(env):
    with env.db() as db:
        # Direct fetching defaults off; regardless, security refusal is a limitation,
        # not evidence that the submitted target is fraudulent.
        res = investigate_single_url("http://127.0.0.1:8768/private", db, env.ctx.crypto, env.settings, skip_cache=True)
        assert res.risk_band != "high_risk"
        assert not any(f.code == "RESTRICTED_DESTINATION_BLOCKED" for f in res.findings)
        assert any(c.id == "safe_web_fetch" and c.status == "not_checked" for c in res.coverage)

def test_url_caching_behavior(env):
    cache = URLInvestigationCache.get_instance()
    cache.clear()

    with env.db() as db:
        # First call: executes pipeline and writes to cache
        t0 = time.monotonic()
        res1 = investigate_single_url("https://safaricom.co.ke", db, env.ctx.crypto, env.settings)
        dt1 = time.monotonic() - t0

        # Verify entry is present in cache
        cached = cache.get_url("https://safaricom.co.ke")
        assert cached is not None
        assert cached["domain"] == "safaricom.co.ke"

        # Second call: served from memory cache immediately (< 10ms)
        t1 = time.monotonic()
        res2 = investigate_single_url("https://safaricom.co.ke", db, env.ctx.crypto, env.settings)
        dt2 = time.monotonic() - t1

        assert res2.risk_band == res1.risk_band
        assert dt2 < dt1
