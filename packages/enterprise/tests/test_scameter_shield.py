from decimal import Decimal
import pytest

from toroka_enterprise.governance.scameter_shield import (
    FpsScameterShieldEngine,
    ScameterRiskLevel,
)


def test_scameter_high_risk_police_warning_and_waiver():
    """Hong Kong FPS Scameter high-risk proxy alert & statutory liability waiver."""
    engine = FpsScameterShieldEngine()
    engine.register_police_proxy("0712345678", ScameterRiskLevel.HIGH_RISK_POLICE_RECORD, "HKPF-CYBER-9912")

    # 1. Lookup flagged proxy
    lookup = engine.lookup_proxy("0712345678", "PHONE")
    assert lookup.risk_level == ScameterRiskLevel.HIGH_RISK_POLICE_RECORD
    assert lookup.unskippable_warning_required is True
    assert lookup.requires_liability_waiver is True
    assert "HKPF-CYBER-9912" in lookup.warning_body

    # 2. Rejection if customer attempts to waive without consent ack
    with pytest.raises(PermissionError):
        engine.execute_statutory_waiver(
            account_id="ACC-HK-01",
            customer_id="CUST-HK-01",
            proxy_id="0712345678",
            risk_level=lookup.risk_level,
            transfer_amount=Decimal("50000.00"),
            customer_consent_ack=False,
        )

    # 3. Valid executed waiver legally shielding the bank
    waiver = engine.execute_statutory_waiver(
        account_id="ACC-HK-01",
        customer_id="CUST-HK-01",
        proxy_id="0712345678",
        risk_level=lookup.risk_level,
        transfer_amount=Decimal("50000.00"),
        customer_consent_ack=True,
    )
    assert waiver.is_institution_shielded is True
    assert len(waiver.waiver_hash) == 64  # SHA-256 hash


def test_scameter_clean_proxy():
    """Clean proxy returns normal risk without mandatory waiver."""
    engine = FpsScameterShieldEngine()
    lookup = engine.lookup_proxy("0799999999", "PHONE")
    assert lookup.risk_level == ScameterRiskLevel.CLEAR
    assert lookup.unskippable_warning_required is False
    assert lookup.requires_liability_waiver is False
