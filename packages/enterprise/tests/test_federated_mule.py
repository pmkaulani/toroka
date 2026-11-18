"""Unit tests for Phase 14.2: Federated Mule Directory & Blinded Token Cryptography."""
from datetime import datetime, timedelta, timezone
import pytest
from toroka_enterprise.integrations.federated_mule import (
    FederatedMuleEngine,
    FederatedMuleQuery,
    MuleEntityType,
    MuleEntryStatus,
    MuleSeverityTier,
)


def test_normalize_identifiers():
    # Bank accounts
    assert FederatedMuleEngine.normalize_identifier(" 0110-099-8877 ", MuleEntityType.BANK_ACCOUNT) == "01100998877"
    assert FederatedMuleEngine.normalize_identifier("acc_123_456", MuleEntityType.BANK_ACCOUNT) == "ACC123456"

    # MSISDNs
    assert FederatedMuleEngine.normalize_identifier("0712345678", MuleEntityType.MSISDN) == "+254712345678"
    assert FederatedMuleEngine.normalize_identifier("+254 712-345-678", MuleEntityType.MSISDN) == "+254712345678"
    assert FederatedMuleEngine.normalize_identifier("254712345678", MuleEntityType.MSISDN) == "+254712345678"

    # National IDs
    assert FederatedMuleEngine.normalize_identifier(" 1234 5678 ", MuleEntityType.NATIONAL_ID) == "12345678"


def test_compute_blinded_token_deterministic():
    token1 = FederatedMuleEngine.compute_blinded_token("01100998877", MuleEntityType.BANK_ACCOUNT, salt="TEST_SALT_1")
    token2 = FederatedMuleEngine.compute_blinded_token(" 0110-099-8877 ", MuleEntityType.BANK_ACCOUNT, salt="TEST_SALT_1")
    assert token1 == token2
    assert len(token1) == 64

    # Different salt
    token_diff_salt = FederatedMuleEngine.compute_blinded_token("01100998877", MuleEntityType.BANK_ACCOUNT, salt="DIFF_SALT")
    assert token1 != token_diff_salt

    # Different account
    token_diff_acct = FederatedMuleEngine.compute_blinded_token("01100998899", MuleEntityType.BANK_ACCOUNT, salt="TEST_SALT_1")
    assert token1 != token_diff_acct


def test_mask_identifier_privacy():
    assert FederatedMuleEngine.mask_identifier("01100998877", MuleEntityType.BANK_ACCOUNT) == "0110****877"
    assert FederatedMuleEngine.mask_identifier("+254712345678", MuleEntityType.MSISDN) == "+254****678"
    assert FederatedMuleEngine.mask_identifier("123456", MuleEntityType.NATIONAL_ID) == "12****56"
    assert FederatedMuleEngine.mask_identifier("123", MuleEntityType.NATIONAL_ID) == "****"


def test_federated_mule_match_corroborated():
    salt = "CONSORTIUM_SALT_ALPHA"
    token = FederatedMuleEngine.compute_blinded_token("01100998877", MuleEntityType.BANK_ACCOUNT, salt=salt)

    entries = [
        {
            "blinded_token": token,
            "cleartext_preview": "0110****877",
            "entity_type": MuleEntityType.BANK_ACCOUNT.value,
            "severity_tier": MuleSeverityTier.CORROBORATED_MULE.value,
            "originating_bank_bic": "EQBLKENA",
            "reason_code": "VERIFIED_VICTIM_FRAUD_COMPLAINT",
            "dossier_reference": "DOS-2026-0042",
            "status": MuleEntryStatus.ACTIVE.value,
            "registered_at": datetime.now(timezone.utc),
        }
    ]

    query = FederatedMuleQuery(value="0110-099-8877", entity_type=MuleEntityType.BANK_ACCOUNT)
    match = FederatedMuleEngine.evaluate_mule_query(query, entries, salt=salt)

    assert match.is_match is True
    assert match.severity_tier == MuleSeverityTier.CORROBORATED_MULE
    assert match.originating_bank_bic == "EQBLKENA"
    assert "RECOMMEND_BLOCK" in match.recommended_action
    assert match.cleartext_preview == "0110****877"


def test_federated_mule_match_syndicate_controller():
    salt = "CONSORTIUM_SALT_ALPHA"
    token = FederatedMuleEngine.compute_blinded_token("+254711000999", MuleEntityType.MSISDN, salt=salt)

    entries = [
        {
            "blinded_token": token,
            "cleartext_preview": "+254****999",
            "entity_type": MuleEntityType.MSISDN.value,
            "severity_tier": MuleSeverityTier.CONFIRMED_SYNDICATE_CONTROLLER.value,
            "originating_bank_bic": "KCBKKENA",
            "reason_code": "POLICE_FREEZE_NOTICE_DCI",
            "status": MuleEntryStatus.ACTIVE.value,
        }
    ]

    query = FederatedMuleQuery(value="0711000999", entity_type=MuleEntityType.MSISDN)
    match = FederatedMuleEngine.evaluate_mule_query(query, entries, salt=salt)

    assert match.is_match is True
    assert match.severity_tier == MuleSeverityTier.CONFIRMED_SYNDICATE_CONTROLLER
    assert "syndicate controller" in match.recommended_action.lower()


def test_federated_mule_match_suspect_mule():
    salt = "CONSORTIUM_SALT_ALPHA"
    token = FederatedMuleEngine.compute_blinded_token("222333444", MuleEntityType.BANK_ACCOUNT, salt=salt)

    entries = [
        {
            "blinded_token": token,
            "cleartext_preview": "2223****444",
            "entity_type": MuleEntityType.BANK_ACCOUNT.value,
            "severity_tier": MuleSeverityTier.SUSPECT_MULE.value,
            "originating_bank_bic": "SCBLKENA",
            "reason_code": "HIGH_VELOCITY_RAPID_CASHOUT",
            "status": MuleEntryStatus.ACTIVE.value,
        }
    ]

    query = FederatedMuleQuery(value="222333444", entity_type=MuleEntityType.BANK_ACCOUNT)
    match = FederatedMuleEngine.evaluate_mule_query(query, entries, salt=salt)

    assert match.is_match is True
    assert match.severity_tier == MuleSeverityTier.SUSPECT_MULE
    assert "RECOMMEND_DELAY_SETTLEMENT_15M" in match.recommended_action


def test_federated_mule_expunged_entry_ignored():
    salt = "CONSORTIUM_SALT_ALPHA"
    token = FederatedMuleEngine.compute_blinded_token("01100998877", MuleEntityType.BANK_ACCOUNT, salt=salt)

    entries = [
        {
            "blinded_token": token,
            "status": MuleEntryStatus.EXPUNGED.value,
        }
    ]

    query = FederatedMuleQuery(value="01100998877", entity_type=MuleEntityType.BANK_ACCOUNT)
    match = FederatedMuleEngine.evaluate_mule_query(query, entries, salt=salt)

    assert match.is_match is False
    assert "NO_MULE_RECORD" in match.recommended_action


def test_federated_mule_expired_entry_ignored():
    salt = "CONSORTIUM_SALT_ALPHA"
    token = FederatedMuleEngine.compute_blinded_token("01100998877", MuleEntityType.BANK_ACCOUNT, salt=salt)

    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    entries = [
        {
            "blinded_token": token,
            "status": MuleEntryStatus.ACTIVE.value,
            "expires_at": yesterday,
        }
    ]

    query = FederatedMuleQuery(value="01100998877", entity_type=MuleEntityType.BANK_ACCOUNT)
    match = FederatedMuleEngine.evaluate_mule_query(query, entries, salt=salt)

    assert match.is_match is False


def test_federated_mule_blinded_query():
    salt = "CONSORTIUM_SALT_ALPHA"
    token = FederatedMuleEngine.compute_blinded_token("01100998877", MuleEntityType.BANK_ACCOUNT, salt=salt)

    entries = [
        {
            "blinded_token": token,
            "cleartext_preview": "0110****877",
            "entity_type": MuleEntityType.BANK_ACCOUNT.value,
            "severity_tier": MuleSeverityTier.CORROBORATED_MULE.value,
            "status": MuleEntryStatus.ACTIVE.value,
        }
    ]

    query = FederatedMuleQuery(value=token, entity_type=MuleEntityType.BANK_ACCOUNT, is_already_blinded=True)
    match = FederatedMuleEngine.evaluate_mule_query(query, entries, salt=salt)

    assert match.is_match is True
    assert match.blinded_token == token
