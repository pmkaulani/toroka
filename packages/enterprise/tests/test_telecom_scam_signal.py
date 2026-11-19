"""Unit tests for Telecom Scam Signal Gateway and Coercion Telemetry."""
import pytest
from toroka_enterprise.integrations.telecom_signal import (
    CallStatus,
    SimSwapStatus,
    TelecomCarrier,
    TelecomScamSignalGateway,
    TelecomSignalQuery,
    TelecomSignalResponse,
)


def test_msisdn_e164_normalization():
    assert TelecomScamSignalGateway.normalize_msisdn("0712345678") == "+254712345678"
    assert TelecomScamSignalGateway.normalize_msisdn("254712345678") == "+254712345678"
    assert TelecomScamSignalGateway.normalize_msisdn("+254712345678") == "+254712345678"
    assert TelecomScamSignalGateway.normalize_msisdn("  0799 112 233  ") == "+254799112233"


def test_telecom_signal_active_call_detection():
    # Number ending in 0001 triggers CALL_IN_PROGRESS
    query = TelecomSignalQuery(
        msisdn="+254711000001",
        carrier=TelecomCarrier.SAFARICOM,
        transfer_amount=150000.0,
    )
    resp = TelecomScamSignalGateway.evaluate_telecom_signal(query)

    assert resp.call_status == CallStatus.CALL_IN_PROGRESS
    assert resp.call_duration_seconds == 340
    assert resp.is_high_coercion_risk is True
    assert resp.scam_signal_score >= 0.50
    assert any("ACTIVE_PHONE_CALL" in ind for ind in resp.coercion_indicators)
    assert resp.statutory_warning is not None
    assert "currently engaged on a live telephone call" in resp.statutory_warning
    assert "RECOMMEND_DELAY_SETTLEMENT_15M" in resp.advisory_action
    assert len(resp.query_digest) == 64


def test_telecom_signal_sim_swap_24h_detection():
    # Number ending in 0002 triggers SWAPPED_LAST_24H
    query = TelecomSignalQuery(
        msisdn="+254722000002",
        carrier=TelecomCarrier.SAFARICOM,
    )
    resp = TelecomScamSignalGateway.evaluate_telecom_signal(query)

    assert resp.sim_swap_status == SimSwapStatus.SWAPPED_LAST_24H
    assert resp.sim_swap_age_hours == 3.5
    assert resp.is_high_coercion_risk is True
    assert resp.scam_signal_score >= 0.60
    assert any("CRITICAL_SIM_SWAP_24H" in ind for ind in resp.coercion_indicators)


def test_telecom_signal_compound_coercion_critical():
    # Number ending in 0003 triggers both active call and swap
    query = TelecomSignalQuery(
        msisdn="+254733000003",
        carrier=TelecomCarrier.AIRTEL_KENYA,
        transfer_amount=500000.0,
    )
    resp = TelecomScamSignalGateway.evaluate_telecom_signal(query)

    assert resp.call_status == CallStatus.CALL_IN_PROGRESS
    assert resp.sim_swap_status == SimSwapStatus.SWAPPED_LAST_48H
    assert resp.scam_signal_score >= 0.85
    assert resp.is_high_coercion_risk is True
    assert "RECOMMEND_BLOCK" in resp.advisory_action


def test_telecom_signal_idle_clean():
    # Regular clean number
    query = TelecomSignalQuery(
        msisdn="+254712345678",
        carrier=TelecomCarrier.SAFARICOM,
    )
    resp = TelecomScamSignalGateway.evaluate_telecom_signal(query)

    assert resp.call_status == CallStatus.IDLE
    assert resp.sim_swap_status == SimSwapStatus.NO_SWAP_RECENT
    assert resp.is_high_coercion_risk is False
    assert resp.scam_signal_score < 0.10
    assert resp.statutory_warning is None
    assert "NO_TELECOM_ANOMALY" in resp.advisory_action


def test_telecom_signal_simulated_override():
    # Explicit simulation parameters
    query = TelecomSignalQuery(
        msisdn="+254700999999",
        carrier=TelecomCarrier.SAFARICOM,
    )
    resp = TelecomScamSignalGateway.evaluate_telecom_signal(
        query,
        simulated_call_status=CallStatus.CALL_RECENTLY_ENDED_5M,
        simulated_call_duration_seconds=180,
    )
    assert resp.call_status == CallStatus.CALL_RECENTLY_ENDED_5M
    assert resp.call_duration_seconds == 180
    assert any("CALL_RECENTLY_DISCONNECTED_5M" in ind for ind in resp.coercion_indicators)
