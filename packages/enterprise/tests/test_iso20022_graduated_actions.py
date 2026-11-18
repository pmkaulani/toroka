"""Unit and integration tests for ISO 20022 Graduated Actions & CoP Risk Scoring."""
from decimal import Decimal
import pytest
from toroka_enterprise.integrations.cop import CopStatus
from toroka_enterprise.integrations.iso20022 import (
    ClearingRail,
    ISO20022Engine,
    Pacs008CreditTransfer,
    PartyIdentification,
    PaymentDecision,
    RiskTier,
)


@pytest.fixture
def base_transfer() -> Pacs008CreditTransfer:
    return Pacs008CreditTransfer(
        msg_id="MSG-GRAD-01",
        end_to_end_id="E2E-GRAD-01",
        tx_id="TX-GRAD-01",
        amount=Decimal("300000.00"),
        currency="KES",
        debtor=PartyIdentification(name="Alice Payer", account_number="111000", agent_bic="KCBKKENA"),
        creditor=PartyIdentification(name="Bob Creditor", account_number="222000", agent_bic="EQBLKENA"),
        clearing_rail=ClearingRail.PESALINK,
        remittance_narrative="Standard service payment",
    )


def test_graduated_action_15m_reversible_escrow_delay(base_transfer):
    # Large round sum (+0.25) + first-time fast rail (+0.20) + base (0.05) = 0.50
    # On PesaLink instant rail -> DELAY_SETTLEMENT_15M
    eval_res = ISO20022Engine.evaluate_inflight_payment(
        base_transfer,
        account_prior_transfers_count=0,
        enable_graduated_controls=True,
    )
    assert eval_res.decision == PaymentDecision.DELAY_SETTLEMENT_15M
    assert eval_res.risk_tier == RiskTier.HIGH
    assert "RECOMMEND_DELAY_SETTLEMENT_15M" in eval_res.recommended_action
    assert any("RULE_LARGE_ROUND_SUM" in r for r in eval_res.triggered_rules)


def test_graduated_action_inflow_only_restriction(base_transfer):
    # Suspect mule beneficiary marked for inflow-only (PBOC Art. 18)
    eval_res = ISO20022Engine.evaluate_inflight_payment(
        base_transfer,
        account_prior_transfers_count=10,
        beneficiary_inflow_restriction=True,
    )
    assert eval_res.decision == PaymentDecision.INFLOW_ONLY
    assert eval_res.risk_tier == RiskTier.HIGH
    assert "RECOMMEND_INFLOW_ONLY" in eval_res.recommended_action
    assert any("RULE_BENEFICIARY_INFLOW_RESTRICTION" in r for r in eval_res.triggered_rules)


def test_graduated_action_restrict_non_counter(base_transfer):
    # Debtor account exhibits channel anomaly / ATO indicator (PBOC Art. 18)
    eval_res = ISO20022Engine.evaluate_inflight_payment(
        base_transfer,
        account_prior_transfers_count=10,
        debtor_channel_anomaly=True,
    )
    assert eval_res.decision == PaymentDecision.RESTRICT_NON_COUNTER
    assert eval_res.risk_tier == RiskTier.HIGH
    assert "RECOMMEND_RESTRICT_NON_COUNTER" in eval_res.recommended_action
    assert any("RULE_NON_COUNTER_RESTRICTION" in r for r in eval_res.triggered_rules)


def test_cop_no_match_escalates_to_block(base_transfer):
    # Base (0.05) + Round Sum (+0.25) + First time (+0.20) + CoP No Match (+0.45) = 0.95 -> BLOCK
    eval_res = ISO20022Engine.evaluate_inflight_payment(
        base_transfer,
        account_prior_transfers_count=0,
        cop_status=CopStatus.NO_MATCH,
        cop_match_score=0.15,
    )
    assert eval_res.decision == PaymentDecision.BLOCK
    assert eval_res.risk_tier == RiskTier.CRITICAL
    assert any("RULE_COP_NO_MATCH" in r for r in eval_res.triggered_rules)
    assert eval_res.cop_status == "NO_MATCH"
    assert eval_res.cop_match_score == 0.15


def test_cop_match_reduces_risk():
    clean_transfer = Pacs008CreditTransfer(
        msg_id="MSG-CLEAN-02",
        end_to_end_id="E2E-CLEAN-02",
        tx_id="TX-CLEAN-02",
        amount=Decimal("1500.00"),
        currency="KES",
        debtor=PartyIdentification(name="David", account_number="111", agent_bic="KCBKKENA"),
        creditor=PartyIdentification(name="Supermarket", account_number="222", agent_bic="EQBLKENA"),
        clearing_rail=ClearingRail.PESALINK,
        remittance_narrative="Groceries",
    )
    eval_res = ISO20022Engine.evaluate_inflight_payment(
        clean_transfer,
        account_prior_transfers_count=20,
        cop_status=CopStatus.MATCH,
        cop_match_score=1.0,
    )
    assert eval_res.decision == PaymentDecision.ALLOW
    assert eval_res.risk_tier == RiskTier.LOW
    assert eval_res.risk_score == 0.0
