"""Unit tests for Precautionary Block (Bloqueio Cautelar) & Nighttime Limits."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import pytest

from toroka_enterprise.integrations.precautionary_hold import (
    DelayedTransferRecallPolicy,
    NighttimeWindowPolicy,
    PrecautionaryHoldEngine,
    PrecautionaryHoldState,
)


def test_bloqueio_cautelar_hold_lifecycle():
    directive = PrecautionaryHoldEngine.create_precautionary_hold(
        installation_id="inst-test-01",
        tx_id="TX-PIX-9901",
        amount=Decimal("75000.00"),
        debtor_account="ACC-DEBTOR-01",
        creditor_account="ACC-MULE-TIER1",
        reason="Severe anomaly in beneficiary velocity and high-risk clearing path.",
    )
    assert directive.state == PrecautionaryHoldState.ACTIVE_HOLD_72H
    assert directive.statutory_basis == "RESOLUCAO_BCB_493_2025_ART_39"
    assert directive.is_expired is False

    # Release cleared funds
    cleared = PrecautionaryHoldEngine.release_hold(
        directive=directive,
        officer_id="officer-fraud-01",
        notes="Legitimate commercial transaction verified via invoice.",
    )
    assert cleared.state == PrecautionaryHoldState.RELEASED_CLEARED
    assert cleared.decision_officer_id == "officer-fraud-01"


def test_bloqueio_cautelar_escalate_to_camt056():
    directive = PrecautionaryHoldEngine.create_precautionary_hold(
        installation_id="inst-test-01",
        tx_id="TX-PIX-9902",
        amount=Decimal("120000.00"),
        debtor_account="ACC-DEBTOR-02",
        creditor_account="ACC-MULE-TIER1",
        reason="Confirmed synthetic mule account.",
    )
    escalated = PrecautionaryHoldEngine.escalate_to_camt056_clawback(
        directive=directive,
        officer_id="officer-fraud-02",
        notes="Confirmed mule syndicate. Initiating automated clawback.",
    )
    assert escalated.state == PrecautionaryHoldState.ESCALATED_CLAWBACK_CAMT056
    assert escalated.camt056_xml is not None
    assert "FIToFIPmtCxlReq" in escalated.camt056_xml
    assert "<Cd>FRAD</Cd>" in escalated.camt056_xml
    assert "BCB_BLOQUEIO_CAUTELAR_CONFIRMED_FRAUD" in escalated.camt056_xml


def test_nighttime_window_policy():
    policy = NighttimeWindowPolicy(
        night_start_hour=20,
        night_end_hour=6,
        max_nighttime_amount=Decimal("20000.00"),
    )
    # 23:00 UTC is night
    night_time = datetime(2026, 11, 19, 23, 15, tzinfo=timezone.utc)
    assert policy.is_nighttime(night_time) is True

    # 14:00 UTC is day
    day_time = datetime(2026, 11, 19, 14, 0, tzinfo=timezone.utc)
    assert policy.is_nighttime(day_time) is False

    # Day transfer of 50,000 -> No breach
    eval_day = policy.evaluate_nighttime_ceiling(Decimal("50000.00"), day_time)
    assert eval_day["is_breach"] is False
    assert eval_day["recommended_action"] == "PROCEED"

    # Night transfer of 50,000 > 20,000 -> Breach
    eval_night = policy.evaluate_nighttime_ceiling(Decimal("50000.00"), night_time)
    assert eval_night["is_breach"] is True
    assert eval_night["recommended_action"] == "DELAY_UNTIL_DAYLIGHT_CLEARING"


def test_delayed_transfer_recall_window():
    policy = DelayedTransferRecallPolicy(delay_duration_hours=3, recall_cutoff_minutes=30)
    start_time = datetime(2026, 11, 19, 10, 0, tzinfo=timezone.utc)

    # Requested at 11:30 (1.5 hours in, 1 hour before cutoff) -> Allowed
    req_allowed = datetime(2026, 11, 19, 11, 30, tzinfo=timezone.utc)
    can_recall, msg = policy.evaluate_recall(start_time, req_allowed)
    assert can_recall is True
    assert "accepted" in msg

    # Requested at 12:45 (2h 45m in, 15m before execution, past 30m cutoff) -> Denied
    req_denied = datetime(2026, 11, 19, 12, 45, tzinfo=timezone.utc)
    can_recall, msg = policy.evaluate_recall(start_time, req_denied)
    assert can_recall is False
    assert "within final 30-minute" in msg
