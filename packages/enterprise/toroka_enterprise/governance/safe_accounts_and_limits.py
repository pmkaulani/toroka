"""South Korea FSS & Global Frontier Defensive Suite:
- South Korea FSS Designated Safe Accounts (입금계좌지정서비스)
- South Korea FSS Delayed ATM Cash-Out (지연인출제도)
- Overseas & Commercial VPN / Tor IP Ingress Shield (해외IP차단서비스)
- Brazil BCB Transfer Limit Increase Cooling-Off Period (24h to 48h)
- Australia NASC Scam-Safe Accord First-Time Payee Settlement Delays (2h to 24h)
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import StrEnum
from typing import Any


def _ensure_utc(dt: datetime | None) -> datetime:
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


# ---------------------------------------------------------------------------
# 1. South Korea FSS Designated Safe Accounts (입금계좌지정서비스)
# ---------------------------------------------------------------------------

@dataclass
class DesignatedSafeAccount:
    registration_id: str
    account_id: str
    payee_account: str
    payee_institution: str
    label: str
    registered_at: datetime
    is_active: bool = True


class SafeAccountsPolicyError(PermissionError):
    """Raised when transfer to non-designated payee exceeds statutory micro-limit."""
    pass


class DesignatedSafeAccountEngine:
    """Manages pre-authorized designated recipient accounts and micro-limit caps."""

    DEFAULT_NON_DESIGNATED_DAILY_CAP = Decimal("10000.00")  # KES 10,000 or $100 equivalent

    def __init__(self, default_non_designated_cap: Decimal | None = None) -> None:
        self.non_designated_cap = default_non_designated_cap or self.DEFAULT_NON_DESIGNATED_DAILY_CAP
        # mapping: account_id -> dict of payee_account -> DesignatedSafeAccount
        self._safe_directory: dict[str, dict[str, DesignatedSafeAccount]] = {}
        # account_id -> daily non-designated total utilized
        self._non_designated_usage: dict[str, Decimal] = {}

    def register_safe_account(
        self,
        account_id: str,
        payee_account: str,
        payee_institution: str,
        label: str,
        now: datetime | None = None,
    ) -> DesignatedSafeAccount:
        now_utc = _ensure_utc(now)
        reg_id = f"SAFE-REG-{uuid.uuid4().hex[:10].upper()}"
        safe_acc = DesignatedSafeAccount(
            registration_id=reg_id,
            account_id=account_id,
            payee_account=payee_account.strip(),
            payee_institution=payee_institution.strip(),
            label=label.strip(),
            registered_at=now_utc,
            is_active=True,
        )
        if account_id not in self._safe_directory:
            self._safe_directory[account_id] = {}
        self._safe_directory[account_id][payee_account.strip()] = safe_acc
        return safe_acc

    def deactivate_safe_account(self, account_id: str, payee_account: str) -> bool:
        if account_id in self._safe_directory and payee_account.strip() in self._safe_directory[account_id]:
            self._safe_directory[account_id][payee_account.strip()].is_active = False
            return True
        return False

    def list_safe_accounts(self, account_id: str) -> list[DesignatedSafeAccount]:
        if account_id not in self._safe_directory:
            return []
        return [acc for acc in self._safe_directory[account_id].values() if acc.is_active]

    def is_designated_safe_payee(self, account_id: str, payee_account: str) -> bool:
        if account_id not in self._safe_directory:
            return False
        acc = self._safe_directory[account_id].get(payee_account.strip())
        return acc is not None and acc.is_active

    def evaluate_outbound_transfer(
        self,
        account_id: str,
        payee_account: str,
        amount: Decimal | float,
        enforce_safe_account_policy: bool = True,
    ) -> tuple[bool, str]:
        """Validates transfer amount against designated accounts policy.
        
        Returns (is_approved, explanation).
        """
        if not enforce_safe_account_policy:
            return True, "Designated safe account policy not enforced for this account"

        amt = Decimal(str(amount))
        if self.is_designated_safe_payee(account_id, payee_account):
            return True, f"Payee {payee_account} is pre-authorized in Designated Safe Accounts registry"

        # Non-designated payee check against statutory ceiling
        current_daily = self._non_designated_usage.get(account_id, Decimal("0.00"))
        if (current_daily + amt) > self.non_designated_cap:
            raise SafeAccountsPolicyError(
                f"Transfer rejected: South Korea FSS Designated Safe Account Policy violation. "
                f"Payee {payee_account} is not pre-registered as a designated safe recipient. "
                f"Transfer of {amt} exceeds remaining non-designated daily micro-limit "
                f"({self.non_designated_cap - current_daily} available of {self.non_designated_cap} cap). "
                f"Pre-register recipient in mobile banking or visit physical branch to raise limit."
            )

        self._non_designated_usage[account_id] = current_daily + amt
        return True, f"Approved under non-designated daily micro-limit cap ({amt} <= {self.non_designated_cap})"


# ---------------------------------------------------------------------------
# 2. South Korea FSS Delayed ATM Cash-Out (지연인출제도)
# ---------------------------------------------------------------------------

class AtmHoldState(StrEnum):
    ACTIVE_HOLD = "ACTIVE_HOLD"
    EXPIRED_RELEASED = "EXPIRED_RELEASED"
    CANCELLED_FRAUD_BLOCK = "CANCELLED_FRAUD_BLOCK"


@dataclass
class AtmDelayedWithdrawalHold:
    hold_id: str
    account_id: str
    inbound_amount: Decimal
    inbound_reference: str
    credit_timestamp: datetime
    hold_expiry_timestamp: datetime
    status: AtmHoldState = AtmHoldState.ACTIVE_HOLD

    @property
    def is_active(self) -> bool:
        if self.status != AtmHoldState.ACTIVE_HOLD:
            return False
        return datetime.now(timezone.utc) < self.hold_expiry_timestamp


class AtmDelayedWithdrawalError(PermissionError):
    """Raised when an ATM withdrawal is attempted during the 30-minute electronic deposit hold."""
    pass


class DelayedAtmCashoutEngine:
    """Implements South Korea FSS 30-minute ATM cash withdrawal hold on large electronic inflows."""

    DEFAULT_THRESHOLD = Decimal("50000.00")  # Deposits >= KES 50,000 / $500 trigger hold
    HOLD_DURATION_MINUTES = 30

    def __init__(self, threshold: Decimal | None = None) -> None:
        self.threshold = threshold or self.DEFAULT_THRESHOLD
        self._holds: dict[str, list[AtmDelayedWithdrawalHold]] = {}

    def register_electronic_inbound(
        self,
        account_id: str,
        amount: Decimal | float,
        reference: str,
        now: datetime | None = None,
    ) -> AtmDelayedWithdrawalHold | None:
        amt = Decimal(str(amount))
        now_utc = _ensure_utc(now)

        if amt < self.threshold:
            return None

        expiry = now_utc + timedelta(minutes=self.HOLD_DURATION_MINUTES)
        hold_id = f"ATM-HOLD-{uuid.uuid4().hex[:10].upper()}"
        hold = AtmDelayedWithdrawalHold(
            hold_id=hold_id,
            account_id=account_id,
            inbound_amount=amt,
            inbound_reference=reference,
            credit_timestamp=now_utc,
            hold_expiry_timestamp=expiry,
            status=AtmHoldState.ACTIVE_HOLD,
        )
        if account_id not in self._holds:
            self._holds[account_id] = []
        self._holds[account_id].append(hold)
        return hold

    def evaluate_atm_withdrawal(
        self,
        account_id: str,
        withdrawal_amount: Decimal | float,
        now: datetime | None = None,
    ) -> tuple[bool, str, AtmDelayedWithdrawalHold | None]:
        now_utc = _ensure_utc(now)
        if account_id not in self._holds:
            return True, "No active ATM withdrawal holds on account", None

        # Check for any active hold
        for hold in self._holds[account_id]:
            if hold.status == AtmHoldState.ACTIVE_HOLD:
                if now_utc < hold.hold_expiry_timestamp:
                    remaining_mins = max(1, int((hold.hold_expiry_timestamp - now_utc).total_seconds() / 60))
                    raise AtmDelayedWithdrawalError(
                        f"ATM cash withdrawal blocked: South Korea FSS Delayed Withdrawal Service (지연인출제도) active. "
                        f"Account received an electronic deposit of {hold.inbound_amount} at {hold.credit_timestamp.isoformat()}. "
                        f"Mandatory 30-minute anti-mule runner quarantine active. Please wait {remaining_mins} minutes "
                        f"until {hold.hold_expiry_timestamp.isoformat()}."
                    )
                else:
                    hold.status = AtmHoldState.EXPIRED_RELEASED

        return True, "ATM withdrawal cleared (quarantine period elapsed)", None


# ---------------------------------------------------------------------------
# 3. Overseas & VPN / Datacenter Ingress Shield (해외IP차단서비스)
# ---------------------------------------------------------------------------

class IngressShieldVerdict(StrEnum):
    ALLOW = "ALLOW"
    BLOCK_VPN_OR_TOR = "BLOCK_VPN_OR_TOR"
    BLOCK_DATACENTER_PROXY = "BLOCK_DATACENTER_PROXY"
    BLOCK_OVERSEAS_UNREGISTERED = "BLOCK_OVERSEAS_UNREGISTERED"


@dataclass(frozen=True)
class IngressShieldTelemetry:
    client_ip: str
    country_code: str
    is_vpn: bool = False
    is_tor: bool = False
    is_datacenter_proxy: bool = False
    registered_overseas_travel: bool = False
    customer_home_country: str = "KE"


class IpIngressShieldEngine:
    """South Korea FSS & Global Ingress Shield blocking foreign IP ranges & anonymizers."""

    @classmethod
    def evaluate_ingress(
        cls,
        telemetry: IngressShieldTelemetry,
    ) -> tuple[IngressShieldVerdict, str]:
        # 1. Block Tor or VPN anonymization
        if telemetry.is_tor or telemetry.is_vpn:
            return (
                IngressShieldVerdict.BLOCK_VPN_OR_TOR,
                f"Transaction blocked: Connection origin {telemetry.client_ip} flagged as commercial VPN/Tor exit node. "
                f"Financial regulations prohibit remote clearing over anonymized proxies.",
            )

        # 2. Block Datacenter/Hosting proxies
        if telemetry.is_datacenter_proxy:
            return (
                IngressShieldVerdict.BLOCK_DATACENTER_PROXY,
                f"Transaction blocked: Connection origin {telemetry.client_ip} belongs to a cloud datacenter CIDR. "
                f"Client execution requires direct consumer ISP carrier network.",
            )

        # 3. Block unregistered foreign countries (South Korea Overseas IP Block Model)
        client_country = telemetry.country_code.upper().strip()
        home_country = telemetry.customer_home_country.upper().strip()
        if client_country != home_country and not telemetry.registered_overseas_travel:
            return (
                IngressShieldVerdict.BLOCK_OVERSEAS_UNREGISTERED,
                f"Transaction blocked: Ingress country {client_country} does not match customer domicile {home_country}. "
                f"Overseas IP Blocking Service (해외IP차단서비스) active. Pre-register international travel in branch.",
            )

        return IngressShieldVerdict.ALLOW, "IP ingress reputation verified clean"


# ---------------------------------------------------------------------------
# 4. Brazil BCB Limit Increase Cooling-Off Period (24h - 48h)
# ---------------------------------------------------------------------------

@dataclass
class LimitIncreaseRequest:
    request_id: str
    account_id: str
    limit_type: str  # DAILY_P2P, NIGHTTIME, SINGLE_TX
    current_limit: Decimal
    requested_limit: Decimal
    requested_at: datetime
    effective_at: datetime
    is_cancelled: bool = False

    @property
    def is_cooling(self) -> bool:
        if self.is_cancelled:
            return False
        return datetime.now(timezone.utc) < self.effective_at


class LimitCoolingEngine:
    """Enforces Brazil BCB 24-48 hour cooling-off period on limit increases to counter extortion."""

    DEFAULT_COOLING_HOURS = 24

    def __init__(self, cooling_hours: int = 24) -> None:
        self.cooling_hours = cooling_hours
        self._requests: dict[str, list[LimitIncreaseRequest]] = {}
        # account_id -> limit_type -> Decimal
        self._established_limits: dict[str, dict[str, Decimal]] = {}

    def set_baseline_limit(self, account_id: str, limit_type: str, limit_val: Decimal | float) -> None:
        if account_id not in self._established_limits:
            self._established_limits[account_id] = {}
        self._established_limits[account_id][limit_type] = Decimal(str(limit_val))

    def request_limit_increase(
        self,
        account_id: str,
        limit_type: str,
        requested_limit: Decimal | float,
        now: datetime | None = None,
    ) -> LimitIncreaseRequest:
        now_utc = _ensure_utc(now)
        req_limit = Decimal(str(requested_limit))
        curr_limit = self._established_limits.get(account_id, {}).get(limit_type, Decimal("50000.00"))

        req_id = f"LIM-REQ-{uuid.uuid4().hex[:10].upper()}"
        effective = now_utc + timedelta(hours=self.cooling_hours)

        record = LimitIncreaseRequest(
            request_id=req_id,
            account_id=account_id,
            limit_type=limit_type,
            current_limit=curr_limit,
            requested_limit=req_limit,
            requested_at=now_utc,
            effective_at=effective,
            is_cancelled=False,
        )
        if account_id not in self._requests:
            self._requests[account_id] = []
        self._requests[account_id].append(record)
        return record

    def get_effective_limit(
        self,
        account_id: str,
        limit_type: str,
        now: datetime | None = None,
    ) -> tuple[Decimal, bool, str]:
        now_utc = _ensure_utc(now)
        curr_limit = self._established_limits.get(account_id, {}).get(limit_type, Decimal("50000.00"))

        if account_id in self._requests:
            for req in reversed(self._requests[account_id]):
                if req.limit_type == limit_type and not req.is_cancelled:
                    if now_utc >= req.effective_at:
                        # Cooling completed: update established limit
                        if account_id not in self._established_limits:
                            self._established_limits[account_id] = {}
                        self._established_limits[account_id][limit_type] = req.requested_limit
                        return req.requested_limit, False, "Approved limit fully active (cooling period concluded)"
                    else:
                        hours_left = max(1, int((req.effective_at - now_utc).total_seconds() / 3600))
                        return (
                            curr_limit,
                            True,
                            f"Mandatory {self.cooling_hours}h statutory cooling-off active. "
                            f"Requested limit of {req.requested_limit} activates in {hours_left}h at {req.effective_at.isoformat()}. "
                            f"Current limit {curr_limit} remains in effect.",
                        )

        return curr_limit, False, "Baseline limit active"


# ---------------------------------------------------------------------------
# 5. Australia NASC Scam-Safe Accord First-Time Payee Settlement Delays
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AccordFrictionResult:
    is_delayed: bool
    delay_hours: int
    contextual_warning_message: str | None = None
    statutory_framework: str = "Australia NASC Scam-Safe Accord 2024"


class PayeeFrictionEngine:
    """Applies psychological cooling-off delays to high-risk or first-time payees."""

    @classmethod
    def evaluate_settlement_delay(
        cls,
        account_id: str,
        payee_account: str,
        amount: Decimal | float,
        is_first_time_payee: bool,
        high_value_threshold: Decimal = Decimal("100000.00"),
    ) -> AccordFrictionResult:
        amt = Decimal(str(amount))
        if is_first_time_payee and amt >= high_value_threshold:
            return AccordFrictionResult(
                is_delayed=True,
                delay_hours=24,
                contextual_warning_message=(
                    f"Payment held for 24 hours under the Australian Scam-Safe Accord standard. "
                    f"This is your first transfer to recipient {payee_account} and exceeds high-value threshold ({amt}). "
                    f"Please review recipient authenticity. You can cancel this transfer within the next 24 hours without penalty."
                ),
            )
        elif is_first_time_payee:
            return AccordFrictionResult(
                is_delayed=True,
                delay_hours=2,
                contextual_warning_message=(
                    f"Payment scheduled with a 2-hour safety pause. "
                    f"Recipient {payee_account} has never received funds from your account before. "
                    f"Take a moment to verify details before funds irrevocably settle."
                ),
            )
        return AccordFrictionResult(is_delayed=False, delay_hours=0, contextual_warning_message=None)
