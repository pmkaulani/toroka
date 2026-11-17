"""Test M-PESA accidental transfer / fake reversal scam detection and shopper guidance."""
from app.ai_agent import chat_with_ai_multilingual
from app.config import Settings


def reply(message, language="en"):
    return chat_with_ai_multilingual(
        check_summary="",
        findings=[],
        user_message=message,
        history=[],
        language=language,
        settings=Settings(),
        public_sources=[],
    )


def test_swahili_fake_reversal_message_triggers_authoritative_guidance():
    _, reply_en, reply_sw = reply("Samahani nimetuma pesa kwa makosa, naomba unirudishie kwa namba hii mara moja.", language="sw")
    low_sw = reply_sw.lower()
    assert "*334#" in low_sw
    assert "456" in low_sw
    assert "usirudishe pesa" in low_sw or "kamwe usirudishe" in low_sw


def test_english_accidental_transfer_claim_triggers_authoritative_guidance():
    active, reply_en, _ = reply("Someone texted me: 'I sent money to your number by mistake, please reverse the money to 0712345678'", language="en")
    low_en = reply_en.lower()
    assert "*334#" in low_en
    assert "456" in low_en
    assert "never send money back" in low_en
