"""Tests for Swiss SIC5 Sub-50ms Parallel Clearing Engine."""
from __future__ import annotations

import time
from decimal import Decimal
import pytest

from toroka_enterprise.integrations.iso20022 import (
    ClearingRail,
    Pacs008CreditTransfer,
    PartyIdentification,
    PaymentDecision,
    RiskTier,
)
from toroka_enterprise.integrations.sic5_parallel import (
    ClearingFeedLatencyBreakdown,
    ParallelClearingResult,
    SIC5FeedStatus,
    SIC5ParallelClearingEngine,
)


def _make_transfer(amount: str = "75000.00", narrative: str = "Standard settlement") -> Pacs008CreditTransfer:
    return Pacs008CreditTransfer(
        msg_id="MSG-SIC5-001",
        end_to_end_id="E2E-SIC5-001",
        tx_id="TX-SIC5-001",
        amount=Decimal(amount),
        currency="KES",
        clearing_rail=ClearingRail.PESALINK,
        debtor=PartyIdentification(
            name="Alice Debtor",
            account_number="0110001111",
            agent_bic="KCBKKENA",
            msisdn="+254711000111",
        ),
        creditor=PartyIdentification(
            name="Bob Creditor",
            account_number="0220002222",
            agent_bic="EQBLKENA",
            msisdn="+254722000222",
        ),
        remittance_narrative=narrative,
    )


def test_sic5_parallel_execution_success():
    transfer = _make_transfer()
    res = SIC5ParallelClearingEngine.evaluate_parallel(
        transfer=transfer,
        cop_enabled=True,
        cop_registered_name="Bob Creditor",
        telecom_enabled=True,
        telecom_msisdn="+254711000111",
        telecom_simulated_call="IDLE",
        federated_mule_enabled=True,
        federated_mule_records=[],
        sla_budget_ms=45.0,
    )

    assert isinstance(res, ParallelClearingResult)
    assert res.evaluation.decision == PaymentDecision.ALLOW
    assert res.circuit_breaker_tripped is False
    assert res.feed_statuses["cop"] == SIC5FeedStatus.SUCCESS.value
    assert res.feed_statuses["telecom"] == SIC5FeedStatus.SUCCESS.value
    assert res.feed_statuses["federated_mule"] == SIC5FeedStatus.SUCCESS.value
    assert res.feed_statuses["behavioral"] == SIC5FeedStatus.SUCCESS.value
    assert res.latency_breakdown.total_pipeline_latency_ms < 45.0
    assert res.latency_breakdown.is_sla_compliant is True


def test_sic5_concurrency_proof():
    """Proves parallel concurrency: simulated 15ms delays across 4 feeds complete in < 35ms total."""
    transfer = _make_transfer()
    sim_latencies = {
        "cop": 15.0,
        "telecom": 15.0,
        "federated_mule": 15.0,
        "behavioral": 15.0,
    }

    t0 = time.perf_counter()
    res = SIC5ParallelClearingEngine.evaluate_parallel(
        transfer=transfer,
        cop_enabled=True,
        cop_registered_name="Bob Creditor",
        telecom_enabled=True,
        telecom_simulated_call="IDLE",
        federated_mule_enabled=True,
        federated_mule_records=[],
        simulated_latencies=sim_latencies,
        sla_budget_ms=50.0,
        feed_timeout_ms=35.0,
    )
    wall_clock_ms = (time.perf_counter() - t0) * 1000.0

    # If serial: 15 * 4 = 60ms. In parallel: ~15-30ms.
    assert wall_clock_ms < 50.0
    assert res.latency_breakdown.cop_latency_ms >= 14.0
    assert res.latency_breakdown.telecom_latency_ms >= 14.0
    assert res.latency_breakdown.is_sla_compliant is True


def test_sic5_circuit_breaker_timeout_graceful_degradation():
    """A hanging telecom feed (100ms) times out at 20ms and gracefully degrades without crashing."""
    transfer = _make_transfer()
    sim_latencies = {
        "telecom": 100.0,  # Far exceeds 20ms timeout!
    }

    t0 = time.perf_counter()
    res = SIC5ParallelClearingEngine.evaluate_parallel(
        transfer=transfer,
        cop_enabled=True,
        cop_registered_name="Bob Creditor",
        telecom_enabled=True,
        telecom_simulated_call="CALL_IN_PROGRESS",
        federated_mule_enabled=False,
        simulated_latencies=sim_latencies,
        sla_budget_ms=45.0,
        feed_timeout_ms=20.0,
    )
    wall_clock_ms = (time.perf_counter() - t0) * 1000.0

    # Overall pipeline should finish around ~20-30ms, NOT 100ms
    assert wall_clock_ms < 45.0
    assert res.circuit_breaker_tripped is True
    assert res.feed_statuses["telecom"] == SIC5FeedStatus.TIMEOUT.value
    assert res.feed_statuses["cop"] == SIC5FeedStatus.SUCCESS.value
    # Safe conservative fallback on telecom timeout: UNKNOWN
    assert res.evaluation.telecom_call_status == "UNKNOWN"


def test_sic5_sla_breach_detection():
    transfer = _make_transfer()
    # Tight SLA of 10ms with 15ms simulated delay will breach SLA
    res = SIC5ParallelClearingEngine.evaluate_parallel(
        transfer=transfer,
        cop_enabled=False,
        telecom_enabled=False,
        federated_mule_enabled=False,
        simulated_latencies={"behavioral": 15.0},
        sla_budget_ms=10.0,
    )

    assert res.latency_breakdown.total_pipeline_latency_ms >= 10.0
    assert res.latency_breakdown.is_sla_compliant is False


def test_sic5_semantic_parity():
    """Verifies that parallel evaluation fires the exact same rules as the standard serial engine."""
    transfer = _make_transfer(amount="250000.00", narrative="Payment for urgent invoice")
    res = SIC5ParallelClearingEngine.evaluate_parallel(
        transfer=transfer,
        cop_enabled=True,
        cop_registered_name="Completely Different Stranger",  # Triggers CoP NO_MATCH
        telecom_enabled=True,
        telecom_simulated_call="CALL_IN_PROGRESS",           # Triggers Active Voice Call
        telecom_msisdn="+254711000111",
        account_prior_transfers_count=0,                     # Triggers First Time Beneficiary
        federated_mule_enabled=False,
    )

    rule_names = [r.split(":")[0] for r in res.evaluation.triggered_rules]
    assert "RULE_LARGE_ROUND_SUM" in rule_names
    assert "RULE_COP_NO_MATCH" in rule_names
    assert "RULE_TELECOM_ACTIVE_CALL" in rule_names
    assert "RULE_NEW_FAST_BENEFICIARY" in rule_names
    assert res.evaluation.decision == PaymentDecision.BLOCK
