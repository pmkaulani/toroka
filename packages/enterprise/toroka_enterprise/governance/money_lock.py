"""Singapore MAS Money Lock Vault Partitioning Domain Module.

Implements customer-controlled non-digital vault partitions based on the Monetary
Authority of Singapore (MAS) and Association of Banks in Singapore (ABS) Money Lock
standards and the December 2024 Shared Responsibility Framework (SRF).

Core Principles:
1. Structural Invariance: Locked vault balances are completely isolated from digital
   clearing switches, mobile apps, and REST APIs. Zero digital transfer authorization.
2. In-Person Physical Barrier: Unlocking strictly requires physical in-person branch
   counter attendance (with national ID verification) or physical ATM card insertion
   with hardware chip-and-PIN authentication.
3. Digital Drainage Neutralization: Attempted digital transfers that exceed available
   liquid balances (even when the locked vault balance is sufficient) are rejected
   outright with MONEY_LOCK_EXCLUSION.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any
import uuid


class MoneyLockStatus(str, Enum):
    """Lifecycle status of a customer account's Money Lock vault."""
    UNLOCKED = "UNLOCKED"
    LOCKED = "LOCKED"
    UNLOCK_PENDING_BRANCH = "UNLOCK_PENDING_BRANCH"


class MoneyLockUnlockChannel(str, Enum):
    """Permitted channels for unlocking funds from a Money Lock vault."""
    PHYSICAL_BRANCH_COUNTER = "PHYSICAL_BRANCH_COUNTER"
    PHYSICAL_ATM_CHIP_PIN = "PHYSICAL_ATM_CHIP_PIN"
    DIGITAL_REMOTE_ATTEMPT = "DIGITAL_REMOTE_ATTEMPT"  # Strictly prohibited; recorded for forensics


class MoneyLockPolicyViolationError(Exception):
    """Raised when an operation violates Singapore MAS Money Lock non-digital policy."""
    pass


class MoneyLockExclusionError(Exception):
    """Raised when an outbound payment attempts to draw on funds protected by Money Lock."""
    pass


@dataclass
class MoneyLockAuditEvent:
    """Immutable audit record for Money Lock lifecycle transitions."""
    event_id: str
    event_type: str
    account_id: str
    installation_id: str
    amount: Decimal
    actor: str
    channel: str
    station_id: str | None
    timestamp: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class MoneyLockAccountVault:
    """Customer-controlled Money Lock vault partition."""
    account_id: str
    installation_id: str
    currency: str = "KES"
    total_balance: Decimal = field(default_factory=lambda: Decimal("0.00"))
    locked_vault_balance: Decimal = field(default_factory=lambda: Decimal("0.00"))
    status: MoneyLockStatus = MoneyLockStatus.UNLOCKED
    last_locked_at: datetime | None = None
    last_unlocked_at: datetime | None = None
    unlock_channel: MoneyLockUnlockChannel | None = None
    unlock_officer_id: str | None = None
    unlock_station_id: str | None = None
    dual_authorizer_id: str | None = None
    audit_trail: list[MoneyLockAuditEvent] = field(default_factory=list)

    @property
    def available_balance(self) -> Decimal:
        """The liquid portion of the account available for digital payment and clearing."""
        avail = self.total_balance - self.locked_vault_balance
        return max(Decimal("0.00"), avail)

    def lock_funds(self, amount: Decimal, actor: str) -> None:
        """Lock an amount into the non-digital vault partition.
        
        Customers can allocate funds into the vault digitally via mobile/web banking.
        Once locked, the funds are immediately ring-fenced from all digital payment switches.
        """
        if amount <= Decimal("0.00"):
            raise ValueError(f"Lock amount must be positive, got {amount}")
        if amount > self.available_balance:
            raise MoneyLockPolicyViolationError(
                f"Cannot lock {amount} {self.currency}: exceeds available liquid balance of {self.available_balance} {self.currency}"
            )

        now = datetime.now(timezone.utc)
        self.locked_vault_balance += amount
        self.status = MoneyLockStatus.LOCKED
        self.last_locked_at = now

        event = MoneyLockAuditEvent(
            event_id=str(uuid.uuid4()),
            event_type="MONEY_LOCK_FUNDS_LOCKED",
            account_id=self.account_id,
            installation_id=self.installation_id,
            amount=amount,
            actor=actor,
            channel="CUSTOMER_DIGITAL_LOCK",
            station_id=None,
            timestamp=now,
            metadata={
                "total_balance": float(self.total_balance),
                "locked_vault_balance": float(self.locked_vault_balance),
                "available_balance": float(self.available_balance),
            },
        )
        self.audit_trail.append(event)

    def validate_outbound_clearing(self, transfer_amount: Decimal) -> bool:
        """Enforces the MAS Money Lock boundary against an in-flight payment request.
        
        If the transfer amount exceeds the liquid available balance, the payment
        is rejected outright. The locked vault balance cannot be touched by any
        digital payment switch or API.
        """
        if transfer_amount > self.available_balance:
            raise MoneyLockExclusionError(
                f"Transfer of {transfer_amount} {self.currency} rejected: exceeds liquid available "
                f"balance ({self.available_balance} {self.currency}). Locked vault balance of "
                f"({self.locked_vault_balance} {self.currency}) is protected under Singapore MAS "
                f"Money Lock policy and cannot be accessed by digital channels."
            )
        return True

    def attempt_digital_unlock(self, actor: str) -> None:
        """Digital unlocking is strictly prohibited by Singapore MAS / ABS policy.
        
        Any call through a mobile app, public API, or web banking to unlock funds
        must be intercepted, rejected, and logged as an adversarial or unauthorized attempt.
        """
        now = datetime.now(timezone.utc)
        event = MoneyLockAuditEvent(
            event_id=str(uuid.uuid4()),
            event_type="MONEY_LOCK_DIGITAL_UNLOCK_PROHIBITED",
            account_id=self.account_id,
            installation_id=self.installation_id,
            amount=self.locked_vault_balance,
            actor=actor,
            channel=MoneyLockUnlockChannel.DIGITAL_REMOTE_ATTEMPT.value,
            station_id=None,
            timestamp=now,
            metadata={"status": "REJECTED_BY_POLICY", "framework": "MAS_ABS_MONEY_LOCK"},
        )
        self.audit_trail.append(event)
        raise MoneyLockPolicyViolationError(
            "Digital unlocking is strictly prohibited under Singapore MAS Money Lock policy. "
            "To unlock funds, the account holder must physically attend an authorized bank branch "
            "counter with government-issued national photo identification, or authenticate via a physical "
            "ATM terminal using hardware chip-and-PIN."
        )

    def unlock_funds_branch(
        self,
        amount_to_unlock: Decimal,
        officer_id: str,
        station_id: str,
        channel: MoneyLockUnlockChannel = MoneyLockUnlockChannel.PHYSICAL_BRANCH_COUNTER,
        dual_authorizer_id: str | None = None,
        large_unlock_threshold: Decimal = Decimal("100000.00"),
    ) -> None:
        """Execute an authorized physical in-person unlock at a bank branch or physical ATM.
        
        Enforces dual-officer maker-checker authorization for amounts exceeding the large
        unlock threshold (e.g., KES 100,000 / SGD 10,000).
        """
        if channel == MoneyLockUnlockChannel.DIGITAL_REMOTE_ATTEMPT:
            raise MoneyLockPolicyViolationError("Remote digital unlock is prohibited.")

        if amount_to_unlock <= Decimal("0.00"):
            raise ValueError(f"Unlock amount must be positive, got {amount_to_unlock}")

        if amount_to_unlock > self.locked_vault_balance:
            raise MoneyLockPolicyViolationError(
                f"Cannot unlock {amount_to_unlock} {self.currency}: exceeds locked balance of {self.locked_vault_balance} {self.currency}"
            )

        # Dual authorization check for large sums
        if amount_to_unlock >= large_unlock_threshold:
            if not dual_authorizer_id:
                raise MoneyLockPolicyViolationError(
                    f"Unlocking amounts >= {large_unlock_threshold} {self.currency} requires dual-officer "
                    f"authorization at the physical branch counter. Secondary authorizer missing."
                )
            if dual_authorizer_id == officer_id:
                raise MoneyLockPolicyViolationError(
                    "Maker and checker officer IDs cannot be identical for branch unlock."
                )

        now = datetime.now(timezone.utc)
        self.locked_vault_balance -= amount_to_unlock
        if self.locked_vault_balance == Decimal("0.00"):
            self.status = MoneyLockStatus.UNLOCKED
        else:
            self.status = MoneyLockStatus.LOCKED

        self.last_unlocked_at = now
        self.unlock_channel = channel
        self.unlock_officer_id = officer_id
        self.unlock_station_id = station_id
        self.dual_authorizer_id = dual_authorizer_id

        event = MoneyLockAuditEvent(
            event_id=str(uuid.uuid4()),
            event_type="MONEY_LOCK_OFFICER_UNLOCKED",
            account_id=self.account_id,
            installation_id=self.installation_id,
            amount=amount_to_unlock,
            actor=officer_id,
            channel=channel.value,
            station_id=station_id,
            timestamp=now,
            metadata={
                "dual_authorizer_id": dual_authorizer_id,
                "remaining_locked_balance": float(self.locked_vault_balance),
                "new_available_balance": float(self.available_balance),
            },
        )
        self.audit_trail.append(event)
