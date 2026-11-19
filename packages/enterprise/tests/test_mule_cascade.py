"""Tests for Phase 14.3 Multi-Tiered Mule Tracing & Graph Cascade Engine."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from toroka_enterprise.intelligence.mule_cascade import (
    CascadeHoldDirectiveType,
    MuleCascadeEdge,
    MuleCascadeNode,
    MuleCascadeTier,
    MuleCascadeTraceResult,
    MuleCascadeTracerEngine,
)


def test_single_hop_root_trace():
    engine = MuleCascadeTracerEngine(local_bank_bic="KCBKKENA")
    now = datetime(2026, 11, 19, 10, 0, 0, tzinfo=timezone.utc)

    result = engine.trace_cascade(
        installation_id="inst_test",
        root_account="1100223344",
        root_fraud_amount=Decimal("250000.00"),
        currency="KES",
        root_transaction_id="TX_ROOT_001",
        anchor_time=now,
        transfers=[],
        max_hops=3,
    )

    assert result.total_nodes_identified == 1
    assert result.max_depth_reached == 1
    assert len(result.edges) == 0
    assert result.root_fraud_amount == Decimal("250000.00")

    root_node = result.nodes[0]
    assert root_node.node_key == "1100223344"
    assert root_node.tier_level == MuleCascadeTier.TIER_1_DIRECT_BENEFICIARY
    assert root_node.retained_balance_estimate == Decimal("250000.00")
    assert root_node.recommended_directive == CascadeHoldDirectiveType.IMMEDIATE_FREEZE
    assert result.total_frozen_or_held_amount == Decimal("250000.00")
    assert result.recovery_potential_ratio == 1.0


def test_multi_hop_dispersion_cascade():
    engine = MuleCascadeTracerEngine(local_bank_bic="KCBKKENA")
    t0 = datetime(2026, 11, 19, 10, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(minutes=5)
    t2 = t0 + timedelta(minutes=8)
    t3 = t0 + timedelta(minutes=15)

    transfers = [
        # Hop 1 -> Hop 2
        {
            "source_account": "ACC_TIER1",
            "target_account": "ACC_TIER2_A",
            "amount": Decimal("150000.00"),
            "timestamp": t1,
            "transaction_id": "TX_HOP1_A",
            "payment_rail": "PESALINK",
            "target_bic": "KCBKKENA",
        },
        {
            "source_account": "ACC_TIER1",
            "target_account": "ACC_TIER2_B",
            "amount": Decimal("250000.00"),
            "timestamp": t2,
            "transaction_id": "TX_HOP1_B",
            "payment_rail": "PESALINK",
            "target_bic": "EQUAKENA",  # External bank
        },
        # Hop 2 -> Hop 3
        {
            "source_account": "ACC_TIER2_A",
            "target_account": "ACC_TIER3_CASHOUT",
            "amount": Decimal("100000.00"),
            "timestamp": t3,
            "transaction_id": "TX_HOP2_C",
            "payment_rail": "MPESA",
            "target_bic": "KCBKKENA",
        },
    ]

    result = engine.trace_cascade(
        installation_id="inst_test",
        root_account="ACC_TIER1",
        root_fraud_amount=Decimal("500000.00"),
        currency="KES",
        anchor_time=t0,
        transfers=transfers,
        max_hops=3,
    )

    assert result.total_nodes_identified == 4
    assert result.max_depth_reached == 3
    assert len(result.edges) == 3

    nodes_by_key = {n.node_key: n for n in result.nodes}

    # Verify Tier 1
    t1_node = nodes_by_key["ACC_TIER1"]
    assert t1_node.tier_level == MuleCascadeTier.TIER_1_DIRECT_BENEFICIARY
    assert t1_node.total_inflow == Decimal("500000.00")
    assert t1_node.total_outflow == Decimal("400000.00")
    assert t1_node.retained_balance_estimate == Decimal("100000.00")
    assert t1_node.recommended_directive == CascadeHoldDirectiveType.IMMEDIATE_FREEZE

    # Verify Tier 2
    t2_node_a = nodes_by_key["ACC_TIER2_A"]
    assert t2_node_a.tier_level == MuleCascadeTier.TIER_2_SECONDARY_DISPERSION
    assert t2_node_a.total_inflow == Decimal("150000.00")
    assert t2_node_a.total_outflow == Decimal("100000.00")
    assert t2_node_a.retained_balance_estimate == Decimal("50000.00")
    assert t2_node_a.recommended_directive == CascadeHoldDirectiveType.INFLOW_ONLY_RESTRICTION

    # Verify Tier 2 External bank
    t2_node_b = nodes_by_key["ACC_TIER2_B"]
    assert t2_node_b.bank_bic == "EQUAKENA"
    assert t2_node_b.recommended_directive == CascadeHoldDirectiveType.INTERBANK_CAMT056_DISPATCH

    # Verify Tier 3
    t3_node = nodes_by_key["ACC_TIER3_CASHOUT"]
    assert t3_node.tier_level == MuleCascadeTier.TIER_3_CASHOUT_GATEWAY
    assert t3_node.recommended_directive == CascadeHoldDirectiveType.ESCROW_DELAY_HOLD_48H


def test_causal_temporality_enforcement():
    """Ensure that transfers occurring BEFORE the fraud inflow are strictly excluded."""
    engine = MuleCascadeTracerEngine(local_bank_bic="KCBKKENA")
    t_fraud = datetime(2026, 11, 19, 12, 0, 0, tzinfo=timezone.utc)
    t_prior = t_fraud - timedelta(hours=2)  # Occurred before fraud!
    t_post = t_fraud + timedelta(minutes=10)

    transfers = [
        {
            "source_account": "ACC_MULE",
            "target_account": "ACC_OLD_LEGIT",
            "amount": Decimal("50000.00"),
            "timestamp": t_prior,
            "transaction_id": "TX_BEFORE",
        },
        {
            "source_account": "ACC_MULE",
            "target_account": "ACC_DOWNSTREAM_CASHOUT",
            "amount": Decimal("180000.00"),
            "timestamp": t_post,
            "transaction_id": "TX_AFTER",
        },
    ]

    result = engine.trace_cascade(
        installation_id="inst_test",
        root_account="ACC_MULE",
        root_fraud_amount=Decimal("200000.00"),
        anchor_time=t_fraud,
        transfers=transfers,
    )

    # ACC_OLD_LEGIT should NOT be visited or included in edges
    assert len(result.edges) == 1
    assert result.edges[0].target_node == "ACC_DOWNSTREAM_CASHOUT"
    assert "ACC_OLD_LEGIT" not in {n.node_key for n in result.nodes}


def test_velocity_and_dispersion_calculations():
    engine = MuleCascadeTracerEngine(local_bank_bic="KCBKKENA")
    t0 = datetime(2026, 11, 19, 14, 0, 0, tzinfo=timezone.utc)
    t_out = t0 + timedelta(minutes=4, seconds=30)  # 4.5 minutes

    transfers = [
        {
            "source_account": "ACC_RAPID",
            "target_account": "ACC_TARGET",
            "amount": Decimal("95000.00"),
            "timestamp": t_out,
            "transaction_id": "TX_RAPID",
        }
    ]

    result = engine.trace_cascade(
        installation_id="inst_test",
        root_account="ACC_RAPID",
        root_fraud_amount=Decimal("100000.00"),
        anchor_time=t0,
        transfers=transfers,
    )

    root_node = next(n for n in result.nodes if n.node_key == "ACC_RAPID")
    assert pytest.approx(root_node.velocity_minutes, 0.1) == 4.5
    assert pytest.approx(root_node.dispersion_ratio, 0.01) == 0.95
    assert root_node.risk_score >= 0.95


def test_generate_camt056_xml():
    engine = MuleCascadeTracerEngine(local_bank_bic="KCBKKENA")
    xml_str = engine.generate_camt056_xml(
        trace_id="casc_abc123",
        original_txn_id="TX_FRAUD_9988",
        instructed_amount=Decimal("450000.00"),
        currency="KES",
        counterparty_bic="EQUAKENA",
        mule_account="01188899900",
        cancellation_reason_code="FRAD",
    )

    assert "camt.056.001.10" in xml_str
    assert "FIToFIPmtCxlReq" in xml_str
    assert "<BICFI>KCBKKENA</BICFI>" in xml_str
    assert "<BICFI>EQUAKENA</BICFI>" in xml_str
    assert "<Cd>FRAD</Cd>" in xml_str
    assert "450000.00" in xml_str
    assert "01188899900" in xml_str

    # Validate XML parsability
    root = ET.fromstring(xml_str)
    assert root.tag.endswith("Document")
