from datetime import datetime, timezone
from decimal import Decimal
import pytest

from toroka_enterprise.governance.srf_liability import (
    CustomerKillSwitchChannel,
    CustomerKillSwitchDeactivationError,
    CustomerKillSwitchEngine,
    CustomerKillSwitchStatus,
    CustomerKillSwitchViolationError,
    SrfAdjudicationResult,
    SrfBankDuties,
    SrfLiabilityTier,
    SrfTelcoDuties,
    SrfWaterfallAdjudicator,
)


def test_srf_waterfall_bank_breach_first_in_line():
    """If Bank breaches any duty (e.g. failure to cool token), Bank bears 100% loss."""
    bank_duties = SrfBankDuties(
        enforced_token_cooling_12h=False,  # Failed cooling
        real_time_alert_dispatched=True,
        kill_switch_available_24_7=True,
        fraud_surveillance_active=True,
    )
    telco_duties = SrfTelcoDuties(
        checked_ssir_registry=True,
        blocked_sender_id_spoofing=True,
        filtered_malicious_urls=True,
    )
    res = SrfWaterfallAdjudicator.adjudicate_phishing_loss(
        account_id="ACC-001",
        disputed_amount=Decimal("150000.00"),
        bank_duties=bank_duties,
        telco_duties=telco_duties,
    )
    assert res.liability_verdict == SrfLiabilityTier.BANK_100_PERCENT
    assert res.reimbursement_bank_amount == Decimal("150000.00")
    assert res.reimbursement_telco_amount == Decimal("0.0")
    assert res.consumer_liability_amount == Decimal("0.0")
    assert "TOKEN_COOLING_VIOLATION" in res.identified_breaches


def test_srf_waterfall_telco_breach_second_in_line():
    """If Bank complied but Telco allowed spoofed sender ID, Telco bears 100% loss."""
    bank_duties = SrfBankDuties(
        enforced_token_cooling_12h=True,
        real_time_alert_dispatched=True,
        kill_switch_available_24_7=True,
        fraud_surveillance_active=True,
    )
    telco_duties = SrfTelcoDuties(
        checked_ssir_registry=False,  # Telco breach
        blocked_sender_id_spoofing=False,
        filtered_malicious_urls=True,
    )
    res = SrfWaterfallAdjudicator.adjudicate_phishing_loss(
        account_id="ACC-002",
        disputed_amount=Decimal("80000.00"),
        bank_duties=bank_duties,
        telco_duties=telco_duties,
    )
    assert res.liability_verdict == SrfLiabilityTier.TELCO_100_PERCENT
    assert res.reimbursement_bank_amount == Decimal("0.0")
    assert res.reimbursement_telco_amount == Decimal("80000.00")
    assert res.consumer_liability_amount == Decimal("0.0")


def test_srf_waterfall_joint_breach_split():
    """If both Bank and Telco failed duties, liability is split 50/50."""
    bank_duties = SrfBankDuties(enforced_token_cooling_12h=False)
    telco_duties = SrfTelcoDuties(blocked_sender_id_spoofing=False)
    res = SrfWaterfallAdjudicator.adjudicate_phishing_loss(
        account_id="ACC-003",
        disputed_amount=Decimal("100000.00"),
        bank_duties=bank_duties,
        telco_duties=telco_duties,
    )
    assert res.liability_verdict == SrfLiabilityTier.SHARED_50_50_BANK_TELCO
    assert res.reimbursement_bank_amount == Decimal("50000.00")
    assert res.reimbursement_telco_amount == Decimal("50000.00")
    assert res.consumer_liability_amount == Decimal("0.0")


def test_srf_waterfall_both_compliant_consumer_bears_loss():
    """If both Bank and Telco fulfilled all duties, consumer bears loss."""
    bank_duties = SrfBankDuties()
    telco_duties = SrfTelcoDuties()
    res = SrfWaterfallAdjudicator.adjudicate_phishing_loss(
        account_id="ACC-004",
        disputed_amount=Decimal("25000.00"),
        bank_duties=bank_duties,
        telco_duties=telco_duties,
        consumer_gross_negligence=True,
    )
    assert res.liability_verdict == SrfLiabilityTier.CONSUMER_100_PERCENT
    assert res.consumer_liability_amount == Decimal("25000.00")


def test_customer_kill_switch_activation_and_blocking():
    """Tests Singapore 24/7 self-service kill switch activation and payment block."""
    engine = CustomerKillSwitchEngine()
    acc = engine.activate_kill_switch(
        account_id="ACC-PANIC-1",
        customer_id="CUST-1",
        channel=CustomerKillSwitchChannel.MOBILE_PANIC_BUTTON,
        reason="Device stolen / active unauthorized access",
        active_sessions_to_revoke=3,
    )
    assert acc.status == CustomerKillSwitchStatus.ACTIVE
    assert acc.revoked_sessions_count == 3

    # Outbound payment clearing must fail closed
    with pytest.raises(CustomerKillSwitchViolationError) as exc_info:
        engine.validate_outbound_payment_clearance("ACC-PANIC-1")
    assert "24/7 Customer Emergency Kill Switch is ACTIVE" in str(exc_info.value)


def test_customer_kill_switch_deactivation_maker_checker():
    """Tests dual-officer branch maker-checker deactivation rules."""
    engine = CustomerKillSwitchEngine()
    engine.activate_kill_switch(
        account_id="ACC-PANIC-2",
        customer_id="CUST-2",
        channel=CustomerKillSwitchChannel.WEB_EMERGENCY_PORTAL,
        reason="Phishing link clicked",
    )

    # Identical maker and checker must be rejected
    with pytest.raises(CustomerKillSwitchDeactivationError):
        engine.deactivate_kill_switch_branch_dual_custody(
            account_id="ACC-PANIC-2",
            maker_officer="OFFICER-ALICE",
            checker_officer="OFFICER-ALICE",
            branch_code="BR-CBD-01",
            notes="Customer present",
        )

    # Missing branch code must be rejected
    with pytest.raises(CustomerKillSwitchDeactivationError):
        engine.deactivate_kill_switch_branch_dual_custody(
            account_id="ACC-PANIC-2",
            maker_officer="OFFICER-ALICE",
            checker_officer="OFFICER-BOB",
            branch_code="",
            notes="Customer present",
        )

    # Valid dual-officer branch release
    acc = engine.deactivate_kill_switch_branch_dual_custody(
        account_id="ACC-PANIC-2",
        maker_officer="OFFICER-ALICE",
        checker_officer="OFFICER-BOB",
        branch_code="BR-CBD-01",
        notes="Physical biometric verification successful",
    )
    assert acc.status == CustomerKillSwitchStatus.INACTIVE
    assert acc.deactivation_maker_officer == "OFFICER-ALICE"
    assert acc.deactivation_checker_officer == "OFFICER-BOB"

    # Subsequent clearing validation must pass cleanly
    engine.validate_outbound_payment_clearance("ACC-PANIC-2")
