"""Investigation Quality & Regression Test Suite (Spec Sections 1-8).

Verifies:
1. 9-category fraud classification and specialist detection rules.
2. Target investigation: deep URL inspection, path correlation caution, campaign intelligence discovery.
3. Separation of evidence from conclusions (source, date, verification status, reliability, limitations).
4. Whitlock Financials regression case (Scam Archive report, MalwareTips scan, no e-commerce leakage, urgent protective advice).
5. Safaricom impersonation regression case (brand-domain mismatch, official sender headers, 333 reporting channel).
6. Coverage status consistency (no conflicting statuses, no duplicate search checks).
"""
from __future__ import annotations

import pytest
from app.url_pipeline import investigate_single_url
from app.campaign_intelligence import lookup_campaign
from ssi_rules import assess, Label
from ssi_rules.category import detect_category, InvestigationCategory


# ---------------------------------------------------------------------------
# 1. Investigation Category Identification (Spec Section 1)
# ---------------------------------------------------------------------------

def test_investigation_category_detection():
    # Recruitment & Overseas employment
    rec = detect_category("There is application of difference job in UNITED STATES if you have form four certificate")
    assert rec.investigation_category == InvestigationCategory.RECRUITMENT_OVERSEAS.value
    assert rec.suggested in (InvestigationCategory.RECRUITMENT_OVERSEAS.value, "job")

    # Online shopping / social media seller
    shop = detect_category("Selling Nike sneakers on Instagram @kicks_ke, price KSh 3,500, delivery within Nairobi")
    assert shop.investigation_category in (InvestigationCategory.ONLINE_SHOPPING.value, InvestigationCategory.SOCIAL_SELLER.value)
    assert shop.suggested in ("shop", InvestigationCategory.ONLINE_SHOPPING.value)

    # M-PESA & payment fraud
    mpesa = detect_category("Nimetuma Ksh 3000 kwa namba yako kimakosa tafadhali nirudishie")
    assert mpesa.investigation_category == InvestigationCategory.MPESA_PAYMENT.value
    assert mpesa.suggested in ("payment", InvestigationCategory.MPESA_PAYMENT.value)

    # Government grants
    grant = detect_category("Hustler Fund Grant: apply for Ksh 50,000 presidential empowerment fund")
    assert grant.investigation_category == InvestigationCategory.GOVERNMENT_GRANTS.value
    assert grant.suggested in ("grant", InvestigationCategory.GOVERNMENT_GRANTS.value)

    # Prize & winnings
    prize = detect_category("Congratulations you have won Ksh 1,000,000 in the grand lottery draw")
    assert prize.investigation_category == InvestigationCategory.PRIZE_WINNINGS.value

    # Phishing & credential theft
    phish = detect_category("Your email account has been locked. Enter your Gmail password to reactivate")
    assert phish.investigation_category == InvestigationCategory.PHISHING_CREDENTIAL.value


# ---------------------------------------------------------------------------
# 2. Whitlock Financials Overseas Job Regression Case (Spec Section 2, 4, 6, 8)
# ---------------------------------------------------------------------------

def test_whitlock_financials_campaign_intelligence_lookup():
    match = lookup_campaign("whitlockfinancials.com", "https://whitlockfinancials.com/gceieighojirma")
    assert match is not None
    assert match.campaign_id == "recruitment_phish_whitlock_2026"
    assert match.campaign_type == "recruitment_phishing"
    assert match.source_name == "The Scam Archive"
    assert match.report_date == "2026-10-26"
    assert match.first_observed == "2026-10-02"

    # Must find Scam Archive details
    finding_texts = " ".join(match.detailed_findings)
    assert "Gmail password" in finding_texts
    assert "generic job-opening image" in finding_texts

    # Must find MalwareTips scan
    assert len(match.scanner_findings) > 0
    mt = match.scanner_findings[0]
    assert "MalwareTips" in mt.name
    assert mt.rating == "High Risk"
    assert mt.root_status_code == 404

    # Must have reputation contradiction note
    assert any("ScamAdviser" in c and "Maltiverse" in c for c in match.reputation_contradictions)

    # Must have path correlation caveat (domain-level association cautiousness)
    assert match.path_correlation_caveat
    assert "UK jobs" in match.path_correlation_caveat
    assert "USA jobs" in match.path_correlation_caveat


def test_whitlock_financials_full_check_pipeline(env):
    user_msg = (
        "Hello There is application of difference job in UNITED STATES if you have form four "
        "certificate, to apply you can open the link below to register 👇👇👇 "
        "https://whitlockfinancials.com/gceieighojirma"
    )
    resp = env.client.post("/v1/checks", json={"text": user_msg})
    assert resp.status_code == 201
    data = resp.json()
    assessment = data["assessment"]

    # 1. Authoritative risk verdict must be high_risk
    assert assessment["label"] == "high_risk"

    # 2. Discovered campaign findings
    codes = {f["code"] for f in assessment["findings"]}
    assert "RECRUITMENT_DOMAIN_PHISHING_HISTORY" in codes or "DOCUMENTED_CAMPAIGN_MATCH" in codes
    assert "DOMAIN_REPUTATION_HIGH_RISK" in codes

    # 3. Specialist rules findings for recruitment
    assert "RECRUITMENT_UNNAMED_EMPLOYER" in codes
    assert "RECRUITMENT_NO_VACANCY_DETAILS" in codes
    assert "RECRUITMENT_IMPLAUSIBLE_IMMIGRATION" in codes
    assert "RECRUITMENT_UNLICENSED_AGENCY" in codes
    assert "RANDOM_URL_PATH_PATTERN" in codes

    # 4. Sources must include clickable The Scam Archive and MalwareTips
    sources = assessment.get("sources", [])
    source_urls = [s.get("source_url") for s in sources if s.get("source_url")]
    assert any("scamarchive.org" in u for u in source_urls)
    assert any("malwaretips.com" in u for u in source_urls)

    # 5. Cautious path correlation in limitations
    limitations_blob = " ".join(assessment.get("limitations", []))
    assert "domain-level connection" in limitations_blob or "UK jobs" in limitations_blob

    # 6. Tailored protective advice (no generic e-commerce leakage!)
    next_steps_blob = " ".join(n["text"] for n in assessment["next_steps"])
    # MUST contain recruitment protections:
    assert "password" in next_steps_blob.lower()
    assert "diaspora.go.ke/verify" in next_steps_blob
    assert "uscis.gov" in next_steps_blob
    # MUST NOT contain e-commerce shopping advice:
    assert "delivery terms" not in next_steps_blob.lower()
    assert "return policy" not in next_steps_blob.lower()
    assert "seller" not in next_steps_blob.lower()
    assert "buyer protection" not in next_steps_blob.lower()

    # 7. Coverage status consistency: no duplicate search checks
    coverage_ids = [c["id"] for c in assessment.get("coverage", [])]
    assert coverage_ids.count("public_web_search") + coverage_ids.count("tavily_search") <= 1


# ---------------------------------------------------------------------------
# 3. Safaricom Impersonation Regression Case (Spec Section 2, 4, 8)
# ---------------------------------------------------------------------------

def test_safaricom_impersonation_regression_case(env):
    msg = (
        "Safaricom Alert: Your M-PESA line has been suspended. Reactivate your line immediately "
        "at http://safaricom-line-reactivate.com or call 0722112233"
    )
    resp = env.client.post("/v1/checks", json={"text": msg})
    assert resp.status_code == 201
    data = resp.json()
    assessment = data["assessment"]

    assert assessment["label"] == "high_risk"
    codes = {f["code"] for f in assessment["findings"]}
    assert "OFFICIAL_DOMAIN_MISMATCH" in codes or "DOMAIN_BRAND_MISMATCH" in codes or "DOCUMENTED_CAMPAIGN_MATCH" in codes

    # Must include Safaricom reporting channel 333
    next_steps_blob = " ".join(n["text"] for n in assessment["next_steps"])
    assert "333" in next_steps_blob


# ---------------------------------------------------------------------------
# 4. Evidence Separation & Granular Coverage Statuses (Spec Section 5 & 7)
# ---------------------------------------------------------------------------

def test_evidence_separation_fields():
    user_msg = "Apply for US jobs here https://whitlockfinancials.com/gceieighojirma"
    a = assess(user_msg)

    # Findings must carry evidence separation provenance
    for f in a.findings:
        if f.code.startswith("RECRUITMENT_"):
            assert f.verification_status in ("observed", "unverified", "confirmed", "reported", "contradictory", None)
            assert f.reliability in ("high", "moderate", "low", "unverified", None)

    # Coverage must not claim zero results is proof of safety
    for c in a.coverage:
        if c.status == "not_found":
            assert "not proof" in c.detail.lower()


def test_direct_chat_url_uses_campaign_and_social_intelligence(make_env, monkeypatch):
    """Direct URL chats must not bypass the evidence-led investigation response."""
    from app.url_pipeline import URLInvestigationResult, URLFinding, URLSourceRef, URLCoverageCheck, PlatformProfile

    env = make_env(tavily_api_key="test-tavily-key")
    fake_result = URLInvestigationResult(
        target_url="https://whitlockfinancials.com/gceieighojirma",
        normalized_url="https://whitlockfinancials.com/gceieighojirma",
        domain="whitlockfinancials.com",
        platform_profile=PlatformProfile(False, "web"),
        risk_band="high_risk",
        summary="The domain has a documented recruitment-phishing association.",
        findings=[URLFinding(
            code="RECRUITMENT_DOMAIN_PHISHING_HISTORY",
            plain_text="A documented report describes an overseas recruitment page on this domain asking applicants for a Gmail password.",
            why_it_matters="The report concerns a different URL path; it is a domain-level association and does not prove the exact submitted page is identical.",
            strength="strong",
            evidence_type="threat_intelligence",
            source_url="https://scamarchive.org/reports/whitlock-financials",
        )],
        sources=[
            URLSourceRef(
                id="campaign-report",
                statement="The Scam Archive (2026-10-26): previous overseas recruitment page on this domain reportedly requested Gmail passwords.",
                source_url="https://scamarchive.org/reports/whitlock-financials",
                reviewer="The Scam Archive (Documented Threat Record)",
                last_verified_at="2026-10-26",
            ),
            URLSourceRef(
                id="tavily-lead",
                statement="Tavily result for whitlockfinancials.com: historical job application warning.",
                source_url="https://example.org/whitlockfinancials.com-warning",
                reviewer="Tavily Web Search (unverified, relevance-filtered lead)",
            ),
        ],
        coverage=[URLCoverageCheck(
            id="tavily_search", name="Tavily Live Web Search", status="checked",
            detail="Search retrieved relevant and unrelated results; the exact-target result is an unverified lead.",
            source_url="https://www.google.com/search?q=whitlockfinancials.com",
            provider="Tavily", results_retrieved=5, results_relevant=1,
        )],
        limitations=["The historical report concerns a different URL path; the submitted path was not confirmed to be identical."],
        next_steps=[],
    )
    monkeypatch.setattr("app.routes_core.investigate_single_url", lambda *args, **kwargs: fake_result)
    monkeypatch.setattr("app.routes_core.investigate_social_targets", lambda targets, settings: {
        "sources": [], "statuses": [{"provider": "Weir", "platform": "x/reddit", "status": "not_configured",
                                      "detail": "WEIR_API_KEY is not configured; X and Reddit were not checked.",
                                      "searched_identifier": "whitlockfinancials.com", "results": 0}], "red_flags": []
    })
    monkeypatch.setattr("app.investigation_intelligence._tavily_extract", lambda *args, **kwargs: ("checked", [], None))

    response = env.client.post("/v1/chat", json={
        "message": "Investigate this overseas job offer in the United States: https://whitlockfinancials.com/gceieighojirma",
        "language": "en",
        "history": [],
    })
    assert response.status_code == 200, response.text
    answer = (response.json().get("reply_en") or response.json().get("reply") or "").lower()
    assert "high risk" in answer
    assert "gmail password" in answer
    assert "different url path" in answer
    assert "national employment authority" in answer
    assert "scamarchive.org" in answer
    assert "refund" not in answer
    structured = response.json().get("url_investigation", {}).get("investigation_intelligence")
    assert structured and structured.get("evidence_explanation")
    assert structured["evidence_explanation"]["verdict"] == "high_risk"


def test_first_check_and_followup_chat_include_social_intelligence_context(make_env):
    """The primary /v1/checks flow and its follow-up chat share one evidence record."""
    env = make_env()
    message = (
        "There is application of difference job in UNITED STATES if you have form four certificate, "
        "apply through https://whitlockfinancials.com/gceieighojirma"
    )
    result = env.check(message)
    assessment = result["assessment"]
    assert result["guest_token"]  # no-account use remains intact
    assert assessment["label"] == "high_risk"
    intelligence = assessment.get("investigation_intelligence")
    assert intelligence, "the first check must persist its multi-source investigation context"
    assert any(flag["code"] == "REPORTED_JOB_CREDENTIAL_HARVESTING" for flag in intelligence["red_flags"])
    assert any("Tavily" in str(item.get("name", "")) for item in assessment["coverage"])
    explanation = intelligence.get("evidence_explanation")
    assert explanation and explanation["verdict"] == assessment["label"]
    assert any(reason.get("observed_excerpt") for reason in explanation["reasons"])
    assert all("evidence" in reason for reason in explanation["reasons"])

    followup = env.client.post(
        f"/v1/checks/{result['check_id']}/chat",
        json={"message": "What should I do?", "language": "en", "history": []},
        headers={"X-Guest-Token": result["guest_token"]},
    )
    assert followup.status_code == 200, followup.text
    answer = (followup.json().get("reply_en") or followup.json().get("reply") or "").lower()
    assert "high risk" in answer
    assert "gmail password" in answer
    assert "national employment authority" in answer
    assert "different url path" in answer
    assert "refund" not in answer


def test_shop_location_claims_are_attributed_and_never_auto_verified():
    from app.investigation_intelligence import _normalise_record, build_shop_discovery

    target = {"kind": "handle", "identifier": "@kicks_ke", "platform": "instagram"}
    profile = _normalise_record(
        "Instagram",
        {
            "url": "https://www.instagram.com/kicks_ke/",
            "username": "kicks_ke",
            "biography": "Nairobi based sneaker store. Visit us at Shop F12, Two Rivers Mall, Nairobi. Delivery across Kenya.",
            "location": "Nairobi, Kenya",
            "external_url": "https://kicks.example/",
        },
        target,
        source_type="social_profile_observation",
    )
    assert profile is not None
    discovery = build_shop_discovery([profile], [target])
    assert discovery["status"] == "self_published_location_found"
    assert any("Nairobi" in item["value"] for item in discovery["locations"])
    assert any(item["kind"] == "physical_address" and "Two Rivers Mall" in item["value"] for item in discovery["locations"])
    assert all(item["verification_status"] == "self_declared_not_independently_verified" for item in discovery["locations"])
    assert discovery["online_storefronts"][0]["url"] == "https://www.instagram.com/kicks_ke/"
    assert any(item["url"] == "https://kicks.example/" for item in discovery["online_storefronts"])
    assert any(item["maps_search_url"] for item in discovery["locations"] if item["kind"] == "physical_address")


def test_third_party_shop_location_is_not_misrepresented_as_seller_confirmed():
    from app.investigation_intelligence import _normalise_record, build_shop_discovery

    target = {"kind": "shop_name", "identifier": "Kicks Kenya", "platform": "not specified"}
    result = _normalise_record(
        "Tavily",
        {"url": "https://directory.example/shops/kicks-kenya", "title": "Kicks Kenya contact", "raw_content": "Kicks Kenya is based in Westlands, Nairobi."},
        target,
        source_type="inspected_public_web_page",
    )
    assert result is not None
    discovery = build_shop_discovery([result], [target])
    assert discovery["status"] == "third_party_location_claims_found"
    assert discovery["locations"]
    assert all(item["claim_origin"] == "third_party_source" for item in discovery["locations"])
    assert all(item["verification_status"] == "third_party_claim_not_independently_verified" for item in discovery["locations"])


def test_verdict_explanation_links_reason_to_source_and_quotes_submitted_content():
    from app.investigation_intelligence import analyse_submitted_content, build_verdict_explanation

    flags = analyse_submitted_content("The recruiter says send your Gmail password to apply for jobs in USA", "job")
    assert flags and flags[0]["observed_excerpt"]
    public_evidence = [{
        "evidence_id": "evidence-123", "title": "Public report", "provider": "Tavily",
        "snippet": "A public report states that the application page requested Gmail passwords.",
        "url": "https://reports.example/whitlock", "source_type": "inspected_public_web_page",
        "claim_status": "reported_allegation", "identity_match": "exact_domain_url_match",
    }]
    flags.append({
        "code": "REPORTED_JOB_CREDENTIAL_HARVESTING", "severity": "high",
        "evidence_status": "reported_in_target_matched_public_sources",
        "statement": "A public source reports credential harvesting.",
        "why_it_matters": "This may expose applicant accounts.", "source_ids": ["evidence-123"],
    })
    explanation = build_verdict_explanation("suspicious_verify_first", "Do not use the link.", flags, public_evidence)
    direct = next(item for item in explanation["reasons"] if item["basis"] == "observed_in_submitted_content")
    linked = next(item for item in explanation["reasons"] if item["basis"] == "linked_public_sources")
    assert "Gmail password" in direct["observed_excerpt"]
    assert linked["evidence"][0]["url"] == "https://reports.example/whitlock"
    assert linked["evidence"][0]["claim_status"] == "reported_allegation"


def test_check_response_exposes_shop_location_and_linked_evidence(monkeypatch, make_env):
    from app.investigation_intelligence import build_shop_discovery, build_verdict_explanation

    evidence = [{
        "evidence_id": "shop-profile-1",
        "provider": "Instagram",
        "platform": "Instagram",
        "source_type": "social_profile_observation",
        "content_status": "public_profile_observed",
        "claim_status": "unverified_public_mention",
        "identity_match": "exact_social_profile_match",
        "target_identifier": "@kicks_ke",
        "title": "Kicks Kenya",
        "snippet": "Based in Westlands, Nairobi. Visit us at Shop F12, Two Rivers Mall.",
        "location_claims": [
            {"kind": "profile_location", "value": "Westlands, Nairobi", "field": "location", "excerpt": "Based in Westlands, Nairobi"},
            {"kind": "physical_address", "value": "Shop F12, Two Rivers Mall", "field": "explicit_address", "excerpt": "Visit us at Shop F12, Two Rivers Mall"},
        ],
        "outbound_links": ["https://kicks.example/"],
        "url": "https://www.instagram.com/kicks_ke/",
        "published_at": "",
        "verified": False,
    }]
    shop_discovery = build_shop_discovery(evidence)
    monkeypatch.setattr("app.routes_core.investigate_social_targets", lambda *args, **kwargs: {"sources": [], "statuses": []})
    monkeypatch.setattr("app.routes_core.investigate_public_targets", lambda *args, **kwargs: {
        "category": "shop", "targets": [{"kind": "handle", "identifier": "@kicks_ke", "platform": "instagram"}],
        "providers": [], "evidence": evidence, "red_flags": [], "advice": [], "limitations": [],
        "summary": "A public profile was observed.", "checked_at": "2026-11-03T09:00:00+00:00", "shop_discovery": shop_discovery,
    })
    env = make_env()
    result = env.check("Please investigate this Instagram shop @kicks_ke")
    intelligence = result["assessment"]["investigation_intelligence"]
    assert intelligence["shop_discovery"]["status"] == "self_published_location_found"
    assert any("Two Rivers Mall" in item["value"] for item in intelligence["shop_discovery"]["locations"])
    assert any(item["url"] == "https://kicks.example/" for item in intelligence["shop_discovery"]["online_storefronts"])
    assert intelligence["evidence_explanation"]["verdict"] == result["assessment"]["label"]


def test_social_profile_adapter_preserves_address_and_website_fields():
    from app.social_intelligence import _profile_observation
    from app.investigation_intelligence import _social_item_to_evidence, build_shop_discovery

    target = {"kind": "handle", "identifier": "@kicks_ke", "platform": "instagram"}
    source = _profile_observation(target, {"data": {
        "username": "kicks_ke", "full_name": "Kicks Kenya", "biography": "Nairobi sneaker store",
        "location": "Nairobi, Kenya", "address": "Shop 10, Two Rivers Mall, Nairobi",
        "external_url": "https://kicks.example/",
    }}, "Scrape Creators")
    assert source and source["address"] == "Shop 10, Two Rivers Mall, Nairobi"
    evidence = _social_item_to_evidence(source, target)
    assert evidence and evidence["location_claims"]
    discovery = build_shop_discovery([evidence])
    assert any("Two Rivers Mall" in item["value"] for item in discovery["locations"])
    assert any(item["url"] == "https://kicks.example/" for item in discovery["online_storefronts"])
