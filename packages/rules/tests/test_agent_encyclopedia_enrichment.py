"""Tests verifying that Toroka AI Agent is deeply enriched with the 12-domain Scam Encyclopedia."""
from __future__ import annotations

import pytest
from app.ai_agent import chat_with_ai_multilingual, _local_expert_replies
from ssi_rules.taxonomy import classify_text_threat, ScamDomain, InvestigationWorkflow


def test_agent_sextortion_enrichment():
    msg = "Someone on Instagram has my private photos and is threatening to leak them to my family unless I send Ksh 10,000 via M-Pesa. What do I do?"
    tax = classify_text_threat(msg).as_dict()
    assert tax["primary_domain"] == ScamDomain.ROMANCE_EXTORTION.value
    assert "SEXTORTION_BLACKMAIL" in tax["matched_patterns"]

    reply, reply_en, reply_sw = chat_with_ai_multilingual(
        check_summary="Suspicious message",
        findings=[],
        user_message=msg,
        history=[],
        taxonomy_info=tax,
    )
    # Check English response
    assert "Never Send Any Money" in reply_en or "Do not pay" in reply_en
    assert "DCI" in reply_en
    assert "evidence" in reply_en.lower() or "screenshots" in reply_en.lower()
    # Check Kiswahili response
    assert "Usilipe" in reply_sw
    assert "DCI" in reply_sw or "ushahidi" in reply_sw.lower()
    # Verify zero emojis
    assert not any(ord(c) > 0x1F000 for c in reply_en)
    assert not any(ord(c) > 0x1F000 for c in reply_sw)


def test_agent_ai_voice_cloning_enrichment():
    msg = "I received a phone call sounding exactly like my son crying and saying nimeshikwa na polisi and asking for emergency bail money immediately."
    tax = classify_text_threat(msg).as_dict()
    assert tax["primary_domain"] == ScamDomain.AI_SCAMS.value
    assert "AI_VOICE_CLONING_EMERGENCY" in tax["matched_patterns"]

    reply, reply_en, reply_sw = chat_with_ai_multilingual(
        check_summary="Suspicious distress call",
        findings=[],
        user_message=msg,
        history=[],
        taxonomy_info=tax,
    )
    assert "Voice Cloning" in reply_en or "cellular" in reply_en.lower()
    assert "safe-word" in reply_en.lower() or "challenge" in reply_en.lower() or "normal" in reply_en.lower()
    assert "sauti" in reply_sw.lower()
    # Verify zero emojis
    assert not any(ord(c) > 0x1F000 for c in reply_en)
    assert not any(ord(c) > 0x1F000 for c in reply_sw)


def test_agent_fake_fund_recovery_enrichment():
    msg = "Can a recovery agent or ethical hacker on Telegram recover lost money from an M-Pesa scammer?"
    tax = classify_text_threat(msg).as_dict()
    assert "SCAM_RECOVERY_FEE_FRAUD" in tax["matched_patterns"]

    reply, reply_en, reply_sw = chat_with_ai_multilingual(
        check_summary="Fund recovery query",
        findings=[],
        user_message=msg,
        history=[],
        taxonomy_info=tax,
    )
    assert "Safaricom" in reply_en
    assert "secondary" in reply_en.lower() or "double-dip" in reply_en.lower() or "upfront" in reply_en.lower()
    assert "333" in reply_en or "234" in reply_en
    assert "Safaricom" in reply_sw
    # Verify zero emojis
    assert not any(ord(c) > 0x1F000 for c in reply_en)
    assert not any(ord(c) > 0x1F000 for c in reply_sw)


def test_agent_seller_shield_overpayment_enrichment():
    msg = "A customer bought shoes for Ksh 2,000, sent an M-Pesa screenshot claiming they overpaid Ksh 7,000, and is demanding I refund the Ksh 5,000 difference right now."
    tax = classify_text_threat(msg).as_dict()
    assert "SHOP_BUYER_OVERPAYMENT" in tax["matched_patterns"]

    reply, reply_en, reply_sw = chat_with_ai_multilingual(
        check_summary="Customer overpayment claim",
        findings=[],
        user_message=msg,
        history=[],
        taxonomy_info=tax,
    )
    assert "Never Release Goods" in reply_en or "Never refund" in reply_en or "456" in reply_en
    assert "*334#" in reply_en or "portal" in reply_en.lower()
    assert "456" in reply_sw or "Usirudishe" in reply_sw or "*334#" in reply_sw
    # Verify zero emojis
    assert not any(ord(c) > 0x1F000 for c in reply_en)
    assert not any(ord(c) > 0x1F000 for c in reply_sw)


def test_agent_fake_courier_fee_enrichment():
    msg = "The seller says the parcel is arriving with Speedaf but I have to pay a gate clearance fee of Ksh 800 first before dispatch."
    reply, reply_en, reply_sw = chat_with_ai_multilingual(
        check_summary="Delivery fee request",
        findings=[],
        user_message=msg,
        history=[],
    )
    assert "Courier" in reply_en or "delivery" in reply_en.lower()
    assert "tracking number" in reply_en.lower() or "shipment status" in reply_en.lower()
    assert "courier" in reply_sw.lower() or "usafirishaji" in reply_sw.lower()
    assert "is not automatically fraud" in reply_en.lower()
    # Verify zero emojis
    assert not any(ord(c) > 0x1F000 for c in reply_en)
    assert not any(ord(c) > 0x1F000 for c in reply_sw)


def test_agent_dynamic_taxonomy_classification_when_omitted():
    # If taxonomy_info is omitted, chat_with_ai_multilingual must dynamically classify it
    msg = "I was promised KSh 500 for liking YouTube videos on Telegram, now they want KSh 5,000 to withdraw."
    reply, reply_en, reply_sw = chat_with_ai_multilingual(
        check_summary="Consultation",
        findings=[],
        user_message=msg,
        history=[],
        taxonomy_info=None,
    )
    assert "Task" in reply_en or "VIP" in reply_en
    assert "Telegram" in reply_en or "deposit" in reply_en.lower()
    assert not any(ord(c) > 0x1F000 for c in reply_en)


def test_agent_social_seller_roral_accessories_investigation():
    msg = "look into roral_assesories"
    reply, reply_en, reply_sw = chat_with_ai_multilingual(
        check_summary="Online shop check",
        findings=[],
        user_message=msg,
        history=[],
    )
    assert "roral_assesories" in reply_en
    assert "enough evidence" in reply_en.lower()
    assert "does not prove fraud" in reply_en.lower() or "not proof" in reply_en.lower()
    assert "Public search" in reply_en or "Live profile" in reply_en or "What this means" in reply_en or "What I still need" in reply_en
    assert "verify" in reply_en.lower() or "check" in reply_en.lower()
    assert "Pay on Delivery" not in reply_en or "universal requirement" in reply_en
    # Kiswahili checks
    assert "roral_assesories" in reply_sw
    assert "thibitisha" in reply_sw.lower() or "ushahidi" in reply_sw.lower()
    # Zero emojis
    assert not any(ord(c) > 0x1F000 for c in reply_en)
    assert not any(ord(c) > 0x1F000 for c in reply_sw)


def test_agent_ponzi_crypto_cma_enrichment():
    msg = "Is this Telegram crypto pool safe? They guarantee 30% daily returns on Bitcoin arbitrage."
    tax = classify_text_threat(msg).as_dict()
    assert tax["primary_domain"] == ScamDomain.INVESTMENT.value
    assert "INVEST_PONZI_CRYPTO_FOREX" in tax["matched_patterns"]

    reply, reply_en, reply_sw = chat_with_ai_multilingual(
        check_summary="Investment check",
        findings=[],
        user_message=msg,
        history=[],
        taxonomy_info=tax,
    )
    assert "Ponzi" in reply_en or "Guaranteed Returns" in reply_en or "Crypto" in reply_en
    assert "CMA" in reply_en or "cma.or.ke" in reply_en or "Central Bank" in reply_en
    assert "Ponzi" in reply_sw or "Faida" in reply_sw or "CMA" in reply_sw
    assert not any(ord(c) > 0x1F000 for c in reply_en)
    assert not any(ord(c) > 0x1F000 for c in reply_sw)


def test_agent_house_hunting_viewing_fee_enrichment():
    msg = "I found a bedsitter in Roysambu for Ksh 8,000 but the caretaker wants Ksh 1,500 viewing fee before showing me the room."
    tax = classify_text_threat(msg).as_dict()
    assert tax["primary_domain"] == ScamDomain.PROPERTY_TRAVEL.value
    assert "PROPERTY_RENTAL_VIEWING_FEE" in tax["matched_patterns"]

    reply, reply_en, reply_sw = chat_with_ai_multilingual(
        check_summary="Apartment search check",
        findings=[],
        user_message=msg,
        history=[],
        taxonomy_info=tax,
    )
    assert "Viewing Fee" in reply_en or "Bedsitter" in reply_en
    assert "free" in reply_en.lower() or "Never Pay" in reply_en
    assert "viewing fee" in reply_sw.lower() or "Kodi" in reply_sw
    assert not any(ord(c) > 0x1F000 for c in reply_en)
    assert not any(ord(c) > 0x1F000 for c in reply_sw)


def test_agent_romance_jkia_customs_enrichment():
    msg = "A doctor abroad sent me a diplomatic parcel with gold and dollars, but someone from JKIA customs called asking for Ksh 30,000 clearance fee."
    tax = classify_text_threat(msg).as_dict()
    assert tax["primary_domain"] == ScamDomain.ROMANCE_EXTORTION.value
    assert "ROMANCE_PARCEL_CUSTOMS" in tax["matched_patterns"]

    reply, reply_en, reply_sw = chat_with_ai_multilingual(
        check_summary="JKIA parcel enquiry",
        findings=[],
        user_message=msg,
        history=[],
        taxonomy_info=tax,
    )
    assert "JKIA" in reply_en or "Romance" in reply_en or "Customs" in reply_en
    assert "222222" in reply_en or "222 222" in reply_en or "KRA" in reply_en or "PRN" in reply_en
    assert "JKIA" in reply_sw or "Forodha" in reply_sw or "222 222" in reply_sw or "222222" in reply_sw
    assert not any(ord(c) > 0x1F000 for c in reply_en)
    assert not any(ord(c) > 0x1F000 for c in reply_sw)


def test_agent_language_switching_swahili():
    msg = "Habari, naomba kujua jinsi ya kutambua sms feki za mpesa."
    reply, reply_en, reply_sw = chat_with_ai_multilingual(
        check_summary="Swahili enquiry",
        findings=[],
        user_message=msg,
        history=[],
        language="sw",
    )
    # The active reply must equal the Swahili reply
    assert reply == reply_sw
    assert "Safaricom" in reply or "M-PESA" in reply or "*334#" in reply
    assert "*334#" in reply_sw
    assert not any(ord(c) > 0x1F000 for c in reply)

