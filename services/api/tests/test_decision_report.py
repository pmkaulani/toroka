import json

from app.decision_report import ai_text_ok, build_decision, count_mentions, plain_unknowns


TIKTOK = {
    "kind": "social_account", "platform": "tiktok", "handle": "kicks.nairobi",
    "risk_band": "inconclusive", "mentions": {"total": 0, "negative": 0, "positive": 0},
    "unknowns": [
        {"id": "safe_web_fetch", "status": "not_checked"},
        {"id": "tavily_search", "status": "not_configured"},
        {"id": "social_oembed", "status": "could_not_check"},
    ],
}


def test_tiktok_inconclusive_has_actionable_next_steps():
    report = build_decision(TIKTOK)
    assert report["decision"] == "cant_tell_yet"
    assert "@kicks.nairobi" in report["headline"]
    assert len(report["how_to_find_out"]) == 5
    assert "registered business name" in report["ask_the_seller"]
    assert any("half-payment" in item for item in report["before_you_pay"])
    assert report["could_not_check"]
    blob = json.dumps(report)
    for banned in ("not_configured", "API_KEY", "Tavily", "Gemini", "organisation"):
        assert banned not in blob


def test_decision_mapping_preserves_existing_rules_band():
    for band, decision in (
        ("high_risk", "dont_pay"),
        ("suspicious_verify_first", "pause_and_verify"),
        ("inconclusive", "cant_tell_yet"),
        ("no_known_threats_found", "pay_only_safely"),
        ("verified_official", "pay_only_safely"),
    ):
        report = build_decision({"kind": "shop_site", "domain": "mamamboga-shop.co.ke", "risk_band": band})
        assert report["decision"] == decision
        assert "mamamboga-shop.co.ke" in report["headline"]


def test_mentions_are_leads_and_internal_statuses_are_hidden():
    assert count_mentions(["Never delivered, scam", "I received my order, genuine", "nothing relevant"]) == {
        "total": 3, "negative": 1, "positive": 1,
    }
    assert plain_unknowns([{"id": "tavily_search", "status": "not_configured"}], "tiktok") == []
    assert plain_unknowns([{"id": "safe_web_fetch", "status": "not_checked"}], "instagram") == [
        "Full profile details: outside tools may not be able to read this Instagram page"
    ]


def test_ai_reword_cannot_reverse_risk_or_accuse_a_person():
    assert not ai_text_ok("This shop is safe and you can go ahead and pay.", "dont_pay")
    assert not ai_text_ok("The seller is definitely a scammer.", "cant_tell_yet")
    assert ai_text_ok("Pause before paying. I could not verify the seller yet.", "pause_and_verify")


def test_tiktok_oembed_metadata_does_not_claim_profile_was_inspected():
    from types import SimpleNamespace
    from app.decision_report import facts_from_result, build_decision

    result = SimpleNamespace(
        platform_profile=SimpleNamespace(platform="tiktok", handle="kicks.nairobi", clean_handle="kicks.nairobi"),
        domain="tiktok.com", risk_band="inconclusive", findings=[], contradictions=[], coverage=[],
        page_data={"oembed": {"account_name": "Kicks Nairobi", "handle": "kicks.nairobi", "caption": "Pay half to reserve"}},
    )
    facts = facts_from_result(result)
    assert facts["profile_read"] is False
    report = build_decision(facts)
    assert any("could not independently inspect" in line for line in report["found"])


def test_social_post_without_account_name_asks_for_the_profile_link():
    from types import SimpleNamespace
    from app.decision_report import facts_from_result, build_decision

    result = SimpleNamespace(
        platform_profile=SimpleNamespace(platform="instagram", handle=None, clean_handle=None),
        domain="instagram.com", risk_band="inconclusive", findings=[], contradictions=[], coverage=[],
        page_data={},
    )
    report = build_decision(facts_from_result(result))
    assert any("does not reveal the account name" in item for item in report["found"])
    assert any("Share the seller's profile link" in item for item in report["how_to_find_out"])


def test_shop_page_observations_are_included_in_found_section():
    from types import SimpleNamespace
    from app.decision_report import facts_from_result, build_decision

    result = SimpleNamespace(
        platform_profile=SimpleNamespace(platform="web", handle=None, clean_handle=None),
        domain="mamamboga-shop.co.ke", risk_band="inconclusive", findings=[], contradictions=[], coverage=[],
        page_data={
            "title": "Mama Mboga Shop", "description": "Groceries in Nairobi",
            "visible_text_excerpt": "Fresh groceries. Delivery terms available.",
            "phones": ["+254700000000"], "emails": ["hello@mamamboga-shop.co.ke"],
            "whatsapp_links": ["https://wa.me/254700000000"], "payment_identifiers": ["Till 123456"],
        },
    )
    report = build_decision(facts_from_result(result))
    found = " ".join(report["found"])
    for expected in ("Mama Mboga Shop", "Groceries in Nairobi", "Fresh groceries", "+254700000000", "hello@mamamboga-shop.co.ke", "Till 123456"):
        assert expected in found


def test_private_network_fetch_refusal_is_explained_without_calling_site_fraudulent():
    from app.decision_report import plain_unknowns
    result = plain_unknowns([{
        "id": "safe_web_fetch", "status": "could_not_check",
        "detail": "blocked: private network destination",
    }], None)
    assert len(result) == 1
    assert "private or restricted network destination" in result[0]
    assert "not evidence" in result[0]


def test_internal_fetch_error_details_are_not_echoed_to_shopper():
    from app.decision_report import plain_unknowns
    result = plain_unknowns([{
        "id": "safe_web_fetch", "status": "could_not_check",
        "detail": "blocked: 169.254.169.254 cloud instance metadata endpoint",
    }], None)
    assert "169.254.169.254" not in result[0]
    assert "metadata" not in result[0].casefold()
