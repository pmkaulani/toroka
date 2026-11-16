from app.ai_agent import chat_with_ai_multilingual
from app.config import Settings
from app.public_search import find_public_identifiers, manual_search_url, public_search
from app.routes_core import _attach_grounded_ai_quotes, _is_new_investigation_input
from app.pipeline import _identifiers
from ssi_rules import normalize as nz


BETTING_SMS = (
    "You have been awarded 5 FREE AVIATOR FREEBETS! REGISTER on Chezagame.com "
    "and get your FREEBETS today! You also have a FREE CASINO BONUS! STOP*456*9*5#"
)


def test_public_search_handle_in_url_and_text_is_deduplicated():
    targets = find_public_identifiers("Check https://instagram.com/@clothing.ctrl and @clothing.ctrl")
    handles = [item for item in targets if item["kind"] == "handle"]
    assert len(handles) == 1
    assert handles[0]["identifier"] == "@clothing.ctrl"
    assert handles[0]["platform"] == "instagram"


def test_new_scam_evidence_does_not_inherit_previous_chat_history():
    assert _is_new_investigation_input(BETTING_SMS)
    assert _is_new_investigation_input("look into this store clothingctrl")
    assert _is_new_investigation_input("@clothing.ctrl")
    assert not _is_new_investigation_input("tell me more")


def test_betting_sms_answer_is_neutral_and_does_not_invent_opt_out_claim():
    reply, local_en, local_sw = chat_with_ai_multilingual(
        check_summary="New message check",
        findings=[{"code": "GAMBLING_BONUS_PROMOTION", "plain_text": "The message advertises a betting promotion."}],
        user_message=BETTING_SMS,
        history=[{"role": "assistant", "text": "Earlier unrelated case had a redemption invoice worth EUR 5,000."}],
        settings=Settings(gemini_api_key="fake-key"),
        public_sources=[{
            "source_type": "search_status",
            "status": "not_checked",
            "detail": "Live public-web search was not performed because TAVILY_API_KEY is missing.",
        }],
    )
    assert "does not establish" in local_en.lower() or "does not show" in local_en.lower()
    assert "does not authenticate" in local_en.lower()
    assert "redemption" not in local_en.lower()
    assert "phishing scam" not in local_en.lower()
    assert "maneno ya ofa pekee" in local_sw.lower() or "si uthibitisho" in local_sw.lower()


def test_ai_cannot_override_case_specific_local_result(monkeypatch):
    import app.ai_agent as agent

    def should_not_call_cloud(*args, **kwargs):
        raise AssertionError("cloud AI must not override a case-specific investigation answer")

    monkeypatch.setattr(agent.httpx, "Client", should_not_call_cloud)
    reply, _, _ = chat_with_ai_multilingual(
        check_summary="Payment request investigation",
        findings=[{"code": "ADVANCE_FEE_REQUEST", "plain_text": "The message asks for an upfront fee."}],
        user_message="The invoice says pay a clearance fee before release of the payout.",
        history=[],
        settings=Settings(gemini_api_key="fake-key"),
    )
    assert "fee" in reply.lower()
    assert "do not" in reply.lower() or "not enough" in reply.lower()


def test_ungrounded_model_invoice_story_is_discarded():
    result = {"findings": []}
    ai_result = {
        "findings": [{
            "code": "FAKE_INVOICE",
            "plain_text": "This is a €2,000 invoice from Mike Adamson with a UK phone number.",
            "why_it_matters": "It is a classic scam.",
            "excerpt": "€2,000 invoice from Mike Adamson with a UK phone number",
        }]
    }
    accepted = _attach_grounded_ai_quotes(result, ai_result, "Invoice total EUR 5,000. Pay a clearance fee before payout.")
    assert accepted == 0
    assert result["findings"] == []


def test_grounded_shortcode_quote_is_not_transformed_into_fake_code_claim():
    result = {"findings": []}
    ai_result = {"findings": [{"code": "FAKE_OPT_OUT", "plain_text": "This is a fake opt-out code.", "excerpt": "STOP*456*9*5#"}]}
    accepted = _attach_grounded_ai_quotes(result, ai_result, BETTING_SMS)
    assert accepted == 1
    finding = result["findings"][0]
    assert finding["excerpt"] == "STOP*456*9*5#"
    assert "fake opt-out" not in (finding["plain_text"] + finding["why_it_matters"]).lower()
    assert "not proof of fraud by itself" in finding["why_it_matters"].lower()


def test_plain_shop_name_is_searched_as_a_name_not_mislabeled_as_handle():
    targets = find_public_identifiers("look into this store clothingctrl")
    assert targets
    assert targets[0]["kind"] == "shop_name"
    assert targets[0]["identifier"] == "clothingctrl"
    assert "@clothingctrl" not in targets[0]["query"]


def test_plain_shop_name_response_is_specific_about_unavailable_live_search():
    _, local_en, _ = chat_with_ai_multilingual(
        check_summary="New shop investigation",
        findings=[],
        user_message="look into this store clothingctrl",
        history=[],
        settings=Settings(),
        public_sources=[{
            "source_type": "search_status",
            "searched_identifier": "clothingctrl",
            "status": "not_checked",
            "detail": "Live public-web search is not configured (TAVILY_API_KEY is missing).",
        }],
    )
    assert "shop name **clothingctrl**" in local_en.lower()
    assert "not configured" in local_en.lower()
    assert "not proof" in local_en.lower() or "does not prove" in local_en.lower()
    assert "physical shop" not in local_en.lower()
    assert "pay-on-delivery" not in local_en.lower()


def test_unsolicited_betting_sms_uses_user_context_without_unrelated_history():
    _, local_en, _ = chat_with_ai_multilingual(
        check_summary="New message check",
        findings=[{"code": "GAMBLING_BONUS_PROMOTION", "plain_text": "The message advertises a betting promotion."}],
        user_message=BETTING_SMS,
        history=[
            {"role": "user", "text": "I don't do betting and keep getting random betting agency SMS on my phone."},
            {"role": "assistant", "text": "An unrelated invoice said EUR 5,000."},
        ],
        settings=Settings(),
        public_sources=[{
            "source_type": "search_status",
            "status": "not_checked",
            "detail": "Live public-web search is not configured (TAVILY_API_KEY is missing).",
        }],
    )
    assert "unwanted betting promotion" in local_en.lower()
    assert "you do not use betting" in local_en.lower()
    assert "eur 5,000" not in local_en.lower()
    assert "do not need to click" in local_en.lower()
    assert "not enough to confirm a scam" in local_en.lower()


def test_chat_endpoint_searches_shop_name_and_reports_missing_provider(env):
    response = env.client.post("/v1/chat", json={
        "message": "look into this store clothingctrl",
        "language": "en",
        "history": [],
    })
    assert response.status_code == 200, response.text
    body = response.json()
    answer = body.get("reply_en") or body["reply"]
    assert "shop name **clothingctrl**" in answer.lower()
    assert "tavily_api_key" not in answer.lower()
    assert "tavily" not in answer.lower()


def test_chat_endpoint_keeps_context_for_unsolicited_betting_sms(env):
    response = env.client.post("/v1/chat", json={
        "message": BETTING_SMS,
        "language": "en",
        "history": [
            {"role": "user", "text": "I don't bet and keep getting random betting agencies SMS."},
            {"role": "assistant", "text": "Previous unrelated answer included a redemption invoice."},
        ],
    })
    assert response.status_code == 200, response.text
    body = response.json()
    answer = body.get("reply_en") or body["reply"]
    assert "unwanted betting promotion" in answer.lower()
    assert "redemption invoice" not in answer.lower()


def test_exact_published_shop_handle_is_found_across_chat_flow(env):
    from app import db as models
    from app.routes_community import upsert_subject

    with env.db() as db:
        subject = upsert_subject(db, env.ctx, "handle", "instagram:clothing.ctrl", "@clothing.ctrl (Instagram)")
        db.add(models.Indicator(
            subject_id=subject.id,
            status="published",
            independent_reports=3,
            basis="independent_reports",
            basis_note="Test-only fixture",
        ))
        db.commit()

    response = env.client.post("/v1/chat", json={
        "message": "@clothing.ctrl",
        "language": "en",
        "history": [{"role": "user", "text": "Please investigate this Instagram shop."}],
    })
    assert response.status_code == 200, response.text
    body = response.json()
    answer = body.get("reply_en") or body["reply"]
    assert "matching published toroka record" in answer.lower() or "independent report" in answer.lower()
    assert "3 independent report" in answer.lower()


def test_shop_handle_without_live_search_never_claims_live_profile_was_checked(env):
    response = env.client.post("/v1/chat", json={
        "message": "@clothing.ctrl",
        "language": "en",
        "history": [{"role": "user", "text": "Please investigate this Instagram shop."}],
    })
    assert response.status_code == 200, response.text
    body = response.json()
    answer = body.get("reply_en") or body["reply"]
    assert "not proof the seller is safe" in answer.lower()
    assert "not configured" in answer.lower() or "not independently inspected" in answer.lower()
    assert "verified legitimate" not in answer.lower()


def test_check_pipeline_extracts_exact_social_profile_url_without_flagging_platform_domain():
    text = "Investigate this Instagram shop: https://www.instagram.com/clothing.ctrl/"
    urls = nz.extract_urls(text)
    identifiers = _identifiers(text, urls, [])
    assert ("handle", "instagram:clothing.ctrl") in identifiers
    assert ("domain", "instagram.com") not in identifiers


def test_check_pipeline_marks_bare_handle_as_platform_ambiguous():
    identifiers = _identifiers("Please investigate @clothing.ctrl before I buy", [], [])
    assert ("handle", "social:clothing.ctrl") in identifiers


def test_unconfigured_public_search_offers_safe_manual_search_not_fake_results():
    result = public_search('"clothing.ctrl" Instagram shop seller reviews Kenya', api_key="")
    assert result["status"] == "not_checked"
    assert result["results"] == []
    assert "did not perform" in result["detail"].lower()
    assert result["manual_search_url"].startswith("https://www.google.com/search?q=")
    assert "clothing.ctrl" in result["manual_search_url"]


def test_manual_search_url_rejects_empty_query():
    assert manual_search_url("  ") is None
