from datetime import datetime, timedelta, timezone
from decimal import Decimal
import pytest

from toroka_enterprise.governance.safe_accounts_and_limits import (
    AtmDelayedWithdrawalError,
    DelayedAtmCashoutEngine,
    DesignatedSafeAccountEngine,
    IngressShieldTelemetry,
    IngressShieldVerdict,
    IpIngressShieldEngine,
    LimitCoolingEngine,
    PayeeFrictionEngine,
    SafeAccountsPolicyError,
)


def test_designated_safe_accounts_policy():
    """South Korea FSS Designated Safe Accounts registry & micro-limit enforcement."""
    engine = DesignatedSafeAccountEngine(default_non_designated_cap=Decimal("10000.00"))

    # Register safe payee (family member)
    safe_reg = engine.register_safe_account(
        account_id="ACC-KOR-1",
        payee_account="PAYEE-FAMILY-01",
        payee_institution="KCBKKENA",
        label="Family Member Safe Payee",
    )
    assert safe_reg.is_active is True

    # 1. Transfer to safe payee allowed at full high amount
    ok, msg = engine.evaluate_outbound_transfer("ACC-KOR-1", "PAYEE-FAMILY-01", Decimal("500000.00"))
    assert ok is True
    assert "pre-authorized" in msg

    # 2. Transfer to non-designated payee under micro-limit (e.g. 5,000) allowed
    ok, msg = engine.evaluate_outbound_transfer("ACC-KOR-1", "PAYEE-UNKNOWN-99", Decimal("5000.00"))
    assert ok is True
    assert "non-designated daily micro-limit" in msg

    # 3. Second transfer to non-designated payee that breaches 10,000 daily cap must be rejected
    with pytest.raises(SafeAccountsPolicyError) as exc_info:
        engine.evaluate_outbound_transfer("ACC-KOR-1", "PAYEE-UNKNOWN-99", Decimal("7000.00"))
    assert "South Korea FSS Designated Safe Account Policy violation" in str(exc_info.value)


def test_delayed_atm_cashout_engine():
    """South Korea FSS Delayed ATM Cash-Out holds on electronic deposits >= threshold."""
    engine = DelayedAtmCashoutEngine(threshold=Decimal("50000.00"))
    now = datetime.now(timezone.utc)

    # Inbound deposit of 100,000 initiates 30-minute hold
    hold = engine.register_electronic_inbound(
        account_id="ACC-MULE-CANDIDATE",
        amount=Decimal("100000.00"),
        reference="TX-ELEC-INFLOW-01",
        now=now,
    )
    assert hold is not None
    assert hold.is_active is True

    # Withdrawal at +10 minutes must be rejected
    at_10m = now + timedelta(minutes=10)
    with pytest.raises(AtmDelayedWithdrawalError) as exc_info:
        engine.evaluate_atm_withdrawal("ACC-MULE-CANDIDATE", Decimal("50000.00"), now=at_10m)
    assert "South Korea FSS Delayed Withdrawal Service" in str(exc_info.value)

    # Withdrawal at +35 minutes (quarantine elapsed) must pass cleanly
    at_35m = now + timedelta(minutes=35)
    allowed, msg, _ = engine.evaluate_atm_withdrawal("ACC-MULE-CANDIDATE", Decimal("50000.00"), now=at_35m)
    assert allowed is True
    assert "quarantine period elapsed" in msg


def test_ip_ingress_shield_engine():
    """Overseas & VPN/Tor IP Shield rejecting anonymizers and foreign IP ranges."""
    # 1. Clean Domestic Connection
    clean_tel = IngressShieldTelemetry(client_ip="197.232.1.5", country_code="KE", customer_home_country="KE")
    v, msg = IpIngressShieldEngine.evaluate_ingress(clean_tel)
    assert v == IngressShieldVerdict.ALLOW

    # 2. Commercial VPN connection
    vpn_tel = IngressShieldTelemetry(client_ip="185.220.101.5", country_code="KE", is_vpn=True)
    v, msg = IpIngressShieldEngine.evaluate_ingress(vpn_tel)
    assert v == IngressShieldVerdict.BLOCK_VPN_OR_TOR
    assert "VPN/Tor exit node" in msg

    # 3. Datacenter Proxy
    dc_tel = IngressShieldTelemetry(client_ip="34.120.50.2", country_code="KE", is_datacenter_proxy=True)
    v, msg = IpIngressShieldEngine.evaluate_ingress(dc_tel)
    assert v == IngressShieldVerdict.BLOCK_DATACENTER_PROXY

    # 4. Unregistered Overseas IP (e.g. Russia / Nigeria)
    overseas_tel = IngressShieldTelemetry(client_ip="95.173.136.5", country_code="RU", customer_home_country="KE")
    v, msg = IpIngressShieldEngine.evaluate_ingress(overseas_tel)
    assert v == IngressShieldVerdict.BLOCK_OVERSEAS_UNREGISTERED

    # 5. Registered Overseas Travel
    travel_tel = IngressShieldTelemetry(
        client_ip="95.173.136.5",
        country_code="RU",
        customer_home_country="KE",
        registered_overseas_travel=True,
    )
    v, msg = IpIngressShieldEngine.evaluate_ingress(travel_tel)
    assert v == IngressShieldVerdict.ALLOW


def test_limit_increase_cooling_engine():
    """Brazil BCB 24-48 hour cooling-off period on transfer limit increases."""
    engine = LimitCoolingEngine(cooling_hours=24)
    engine.set_baseline_limit("ACC-USER-1", "DAILY_P2P", Decimal("50000.00"))
    now = datetime.now(timezone.utc)

    # Request limit hike to 200,000
    req = engine.request_limit_increase("ACC-USER-1", "DAILY_P2P", Decimal("200000.00"), now=now)
    assert req.requested_limit == Decimal("200000.00")

    # Inquiries at +2 hours must still return the baseline 50,000 limit with cooling flag
    at_2h = now + timedelta(hours=2)
    eff_limit, is_cooling, msg = engine.get_effective_limit("ACC-USER-1", "DAILY_P2P", now=at_2h)
    assert eff_limit == Decimal("50000.00")
    assert is_cooling is True
    assert "statutory cooling-off active" in msg

    # Inquiries at +25 hours must activate the requested 200,000 limit
    at_25h = now + timedelta(hours=25)
    eff_limit, is_cooling, msg = engine.get_effective_limit("ACC-USER-1", "DAILY_P2P", now=at_25h)
    assert eff_limit == Decimal("200000.00")
    assert is_cooling is False


def test_australia_nasc_accord_friction():
    """Australia NASC Scam-Safe Accord settlement delays on first-time payees."""
    # First-time payee under high-value threshold (2h delay)
    res_2h = PayeeFrictionEngine.evaluate_settlement_delay(
        account_id="ACC-AUS-1",
        payee_account="PAYEE-NEW-01",
        amount=Decimal("20000.00"),
        is_first_time_payee=True,
    )
    assert res_2h.is_delayed is True
    assert res_2h.delay_hours == 2

    # First-time payee exceeding 100,000 high-value threshold (24h delay)
    res_24h = PayeeFrictionEngine.evaluate_settlement_delay(
        account_id="ACC-AUS-1",
        payee_account="PAYEE-NEW-02",
        amount=Decimal("150000.00"),
        is_first_time_payee=True,
    )
    assert res_24h.is_delayed is True
    assert res_24h.delay_hours == 24

    # Existing frequent payee (0 delay)
    res_clean = PayeeFrictionEngine.evaluate_settlement_delay(
        account_id="ACC-AUS-1",
        payee_account="PAYEE-EXISTING",
        amount=Decimal("150000.00"),
        is_first_time_payee=False,
    )
    assert res_clean.is_delayed is False
