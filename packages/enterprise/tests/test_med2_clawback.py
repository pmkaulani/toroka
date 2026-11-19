from datetime import datetime, timedelta, timezone
from decimal import Decimal

from toroka_enterprise.integrations.med2_clawback import (
    Med2CascadingClawbackEngine,
    Med2ClawbackStatus,
    Med2DisbursementEdge,
    Med2HopTier,
)


def test_med2_5layer_cascading_clawback_trace():
    """Brazil BCB Pix MED 2.0 (Resolução BCB nº 493/2025) 5-layer cascading clawback."""
    now = datetime.now(timezone.utc)
    incident_time = now - timedelta(days=2)  # Well within 80-day window

    # 5 hops of dispersion from original 100,000 BRL victim fraud
    edges = [
        Med2DisbursementEdge(
            edge_id="E-1",
            source_account="ACC-VICTIM",
            target_account="ACC-MULE-TIER1",
            target_institution_bic="ITAU0001",
            amount=Decimal("100000.00"),
            timestamp=incident_time,
            hop_tier=Med2HopTier.TIER_1_DIRECT_RECIPIENT,
        ),
        Med2DisbursementEdge(
            edge_id="E-2",
            source_account="ACC-MULE-TIER1",
            target_account="ACC-MULE-TIER2",
            target_institution_bic="BRAD0002",
            amount=Decimal("60000.00"),
            timestamp=incident_time + timedelta(minutes=5),
            hop_tier=Med2HopTier.TIER_2_SECONDARY_SPLIT,
        ),
        Med2DisbursementEdge(
            edge_id="E-3",
            source_account="ACC-MULE-TIER2",
            target_account="ACC-MULE-TIER3",
            target_institution_bic="NUBK0003",
            amount=Decimal("30000.00"),
            timestamp=incident_time + timedelta(minutes=10),
            hop_tier=Med2HopTier.TIER_3_TERTIARY_DISPERSION,
        ),
        Med2DisbursementEdge(
            edge_id="E-4",
            source_account="ACC-MULE-TIER3",
            target_account="ACC-MULE-TIER4",
            target_institution_bic="C6BK0004",
            amount=Decimal("20000.00"),
            timestamp=incident_time + timedelta(minutes=15),
            hop_tier=Med2HopTier.TIER_4_QUATERNARY_LAYER,
        ),
        Med2DisbursementEdge(
            edge_id="E-5",
            source_account="ACC-MULE-TIER4",
            target_account="ACC-MULE-TIER5",
            target_institution_bic="PAGS0005",
            amount=Decimal("10000.00"),
            timestamp=incident_time + timedelta(minutes=20),
            hop_tier=Med2HopTier.TIER_5_TERMINAL_GATEWAY,
        ),
    ]

    # Residual balances found across the mule nodes
    balances = {
        "ACC-MULE-TIER1": Decimal("10000.00"),  # Partial
        "ACC-MULE-TIER2": Decimal("25000.00"),  # Partial
        "ACC-MULE-TIER3": Decimal("0.00"),      # Cleaned out
        "ACC-MULE-TIER4": Decimal("15000.00"),  # Partial
        "ACC-MULE-TIER5": Decimal("10000.00"),  # Full
    }

    report = Med2CascadingClawbackEngine.execute_med2_cascade_clawback(
        original_tx_id="PIX-TX-FRAUD-123",
        victim_account="ACC-VICTIM",
        total_stolen_amount=Decimal("100000.00"),
        incident_timestamp=incident_time,
        edges=edges,
        account_balances=balances,
        now=now,
    )

    assert report.is_within_80_day_window is True
    assert len(report.hops) == 5
    # Total holds = 10,000 + 25,000 + 0 + 15,000 + 10,000 = 60,000
    assert report.total_clawback_holds_placed == Decimal("60000.00")
    assert report.recovery_rate_pct == 60.0

    # Verify generated ISO 20022 camt.056 XML on Tier 1
    t1_hop = report.hops[0]
    assert t1_hop.status == Med2ClawbackStatus.HOLD_PLACED_PARTIAL
    assert "FIToFIPmtCxlReq" in t1_hop.camt056_xml
    assert "ITAU0001" in t1_hop.camt056_xml

    # Verify Tier 3 zero balance node
    t3_hop = report.hops[2]
    assert t3_hop.status == Med2ClawbackStatus.INSUFFICIENT_FUNDS
