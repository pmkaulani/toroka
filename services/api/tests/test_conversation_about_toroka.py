from app.ai_agent import chat_with_ai_multilingual
from app.config import Settings


def reply(message, history=None, language="en"):
    return chat_with_ai_multilingual(
        check_summary="", findings=[], user_message=message,
        history=history or [], language=language, settings=Settings(),
        public_sources=[],
    )


def test_what_do_you_do_returns_a_real_product_explanation_not_generic_fallback():
    _, answer, _ = reply("what do you do?")
    low = answer.lower()
    assert "digital-safety investigator" in low
    assert "emails" in low
    assert "m-pesa" in low
    assert "what would you like to check" not in low
    assert "here is how we can proceed" not in low


def test_tell_me_everything_about_you_returns_full_scope_and_limits():
    _, answer, _ = reply("tell me everything about you")
    low = answer.lower()
    assert "what i can investigate" in low
    assert "how i reach a conclusion" in low
    assert "what i cannot do" in low
    assert "your privacy and safety" in low
    assert "private social accounts" in low
    assert "m-pesa" in low


def test_tell_me_more_after_intro_adds_how_the_investigation_works():
    history = [
        {"role": "user", "text": "what do you do?"},
        {"role": "model", "text": "I am Toroka, a digital safety assistant."},
    ]
    _, answer, _ = reply("tell me more", history)
    low = answer.lower()
    assert "let me explain how i work" in low
    assert "what you provided" in low
    assert "what a source says" in low
    assert "what remains unknown" in low
    assert "here is how we can proceed" not in low


def test_i_need_more_details_after_intro_expands_to_full_explanation():
    history = [
        {"role": "user", "text": "what do you do?"},
        {"role": "model", "text": "I am Toroka..."},
        {"role": "user", "text": "tell me more"},
        {"role": "model", "text": "I explain how the checks work..."},
    ]
    _, answer, _ = reply("i need more details", history)
    low = answer.lower()
    assert "what i can investigate" in low
    assert "what i cannot do" in low
    assert "your privacy and safety" in low


def test_that_is_not_enough_after_toroka_intro_does_not_repeat_the_intro():
    history = [
        {"role": "user", "text": "tell me about yourself"},
        {"role": "model", "text": "I am Toroka..."},
    ]
    _, answer, _ = reply("that not enough", history)
    assert "what i can investigate" in answer.lower()
    assert "what i cannot do" in answer.lower()


def test_more_details_without_about_context_does_not_assume_user_means_toroka():
    history = [
        {"role": "user", "text": "Check this suspicious shop"},
        {"role": "model", "text": "I found a few things to verify."},
    ]
    _, answer, _ = reply("tell me more", history)
    assert "i can help with that" in answer.lower()
    assert "what i can investigate" not in answer.lower()


def test_swahili_about_response_is_substantive():
    active, english, swahili = reply("unafanya nini?", language="sw")
    assert active == swahili
    assert "M-PESA" in swahili
    assert "ushahidi" in swahili.lower()
    assert len(swahili) > 500
    assert "Here is how we can proceed" not in english


def test_chat_endpoint_progressively_expands_about_toroka(env):
    first = env.client.post("/v1/chat", json={
        "message": "what do you do?", "language": "en", "history": [],
    })
    assert first.status_code == 200, first.text
    first_body = first.json()
    first_reply = first_body.get("reply_en") or first_body["reply"]
    assert "digital-safety investigator" in first_reply.lower()

    second = env.client.post("/v1/chat", json={
        "message": "tell me more", "language": "en",
        "history": [
            {"role": "user", "text": "what do you do?"},
            {"role": "model", "text": first_reply},
        ],
    })
    assert second.status_code == 200, second.text
    second_body = second.json()
    second_reply = second_body.get("reply_en") or second_body["reply"]
    assert "what you provided" in second_reply.lower()
    assert "what remains unknown" in second_reply.lower()
    assert second_reply != first_reply

    third = env.client.post("/v1/chat", json={
        "message": "tell me everything about you", "language": "en",
        "history": [
            {"role": "user", "text": "what do you do?"},
            {"role": "model", "text": first_reply},
            {"role": "user", "text": "tell me more"},
            {"role": "model", "text": second_reply},
        ],
    })
    assert third.status_code == 200, third.text
    third_body = third.json()
    third_reply = third_body.get("reply_en") or third_body["reply"]
    assert "what i can investigate" in third_reply.lower()
    assert "what i cannot do" in third_reply.lower()
    assert third_reply != second_reply
