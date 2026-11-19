"""Unit tests for Singapore MAS Money Lock Vault Partitioning."""
from decimal import Decimal
import pytest

from toroka_enterprise.governance.money_lock import (
    MoneyLockAccountVault,
    MoneyLockExclusionError,
    MoneyLockPolicyViolationError,
    MoneyLockStatus,
    MoneyLockUnlockChannel,
)


def test_money_lock_initial_state():
    vault = MoneyLockAccountVault(
        account_id="ACC-SG-001",
        installation_id="inst-test-01",
        total_balance=Decimal("500000.00"),
    )
    assert vault.locked_vault_balance == Decimal("0.00")
    assert vault.available_balance == Decimal("500000.00")
    assert vault.status == MoneyLockStatus.UNLOCKED


def test_money_lock_funds_locking():
    vault = MoneyLockAccountVault(
        account_id="ACC-SG-001",
        installation_id="inst-test-01",
        total_balance=Decimal("500000.00"),
    )
    vault.lock_funds(Decimal("450000.00"), actor="customer-mobile-app")
    assert vault.locked_vault_balance == Decimal("450000.00")
    assert vault.available_balance == Decimal("50000.00")
    assert vault.status == MoneyLockStatus.LOCKED
    assert len(vault.audit_trail) == 1
    assert vault.audit_trail[0].event_type == "MONEY_LOCK_FUNDS_LOCKED"


def test_money_lock_outbound_clearing_validation_success():
    vault = MoneyLockAccountVault(
        account_id="ACC-SG-001",
        installation_id="inst-test-01",
        total_balance=Decimal("500000.00"),
        locked_vault_balance=Decimal("450000.00"),
        status=MoneyLockStatus.LOCKED,
    )
    # Outbound transfer of KES 30,000 <= available KES 50,000 -> OK
    assert vault.validate_outbound_clearing(Decimal("30000.00")) is True


def test_money_lock_outbound_clearing_exclusion_rejection():
    vault = MoneyLockAccountVault(
        account_id="ACC-SG-001",
        installation_id="inst-test-01",
        total_balance=Decimal("500000.00"),
        locked_vault_balance=Decimal("450000.00"),
        status=MoneyLockStatus.LOCKED,
    )
    # Outbound transfer of KES 100,000 > available KES 50,000 -> REJECTED even though total is 500k
    with pytest.raises(MoneyLockExclusionError) as exc_info:
        vault.validate_outbound_clearing(Decimal("100000.00"))
    assert "exceeds liquid available balance" in str(exc_info.value)
    assert "Money Lock policy" in str(exc_info.value)


def test_money_lock_digital_unlock_prohibited():
    vault = MoneyLockAccountVault(
        account_id="ACC-SG-001",
        installation_id="inst-test-01",
        total_balance=Decimal("500000.00"),
        locked_vault_balance=Decimal("450000.00"),
        status=MoneyLockStatus.LOCKED,
    )
    # Attempting to unlock via digital app or API must be prohibited
    with pytest.raises(MoneyLockPolicyViolationError) as exc_info:
        vault.attempt_digital_unlock(actor="mobile-attacker")
    assert "Digital unlocking is strictly prohibited" in str(exc_info.value)
    assert len(vault.audit_trail) == 1
    assert vault.audit_trail[0].event_type == "MONEY_LOCK_DIGITAL_UNLOCK_PROHIBITED"


def test_money_lock_branch_unlock_with_maker_checker():
    vault = MoneyLockAccountVault(
        account_id="ACC-SG-001",
        installation_id="inst-test-01",
        total_balance=Decimal("500000.00"),
        locked_vault_balance=Decimal("450000.00"),
        status=MoneyLockStatus.LOCKED,
    )
    # Large sum (>= 100k) requires dual authorizer
    with pytest.raises(MoneyLockPolicyViolationError) as exc_info:
        vault.unlock_funds_branch(
            amount_to_unlock=Decimal("150000.00"),
            officer_id="teller-01",
            station_id="STATION-BR-WESTLANDS-04",
            dual_authorizer_id=None,
        )
    assert "requires dual-officer authorization" in str(exc_info.value)

    # Valid branch unlock with dual authorizer
    vault.unlock_funds_branch(
        amount_to_unlock=Decimal("150000.00"),
        officer_id="teller-01",
        station_id="STATION-BR-WESTLANDS-04",
        channel=MoneyLockUnlockChannel.PHYSICAL_BRANCH_COUNTER,
        dual_authorizer_id="manager-02",
    )
    assert vault.locked_vault_balance == Decimal("300000.00")
    assert vault.available_balance == Decimal("200000.00")
    assert vault.unlock_officer_id == "teller-01"
    assert vault.dual_authorizer_id == "manager-02"
    assert len(vault.audit_trail) == 1
    assert vault.audit_trail[0].event_type == "MONEY_LOCK_OFFICER_UNLOCKED"
