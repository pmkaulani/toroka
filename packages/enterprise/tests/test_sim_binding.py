"""Unit tests for Cryptographic SIM Binding & Hardware Integrity Validator."""
from datetime import datetime, timezone
import pytest

from toroka_enterprise.governance.sim_binding import (
    HardwareBindingAssertion,
    HardwareBindingStatus,
    SimBindingEngine,
)


def test_sim_binding_enroll_and_verify_success():
    enrollment = SimBindingEngine.enroll_binding(
        account_id="ACC-IN-001",
        installation_id="inst-test-01",
        device_imei="352099001761482",
        sim_iccid="8991101200003204512",
        carrier_name="Airtel",
    )
    assert enrollment.status == HardwareBindingStatus.BOUND_TRUSTED

    # Matching assertion
    assertion = HardwareBindingAssertion(
        device_imei_hash=enrollment.bound_device_imei_hash,
        sim_iccid_hash=enrollment.bound_sim_iccid_hash,
        app_instance_id="app-inst-xyz",
        client_timestamp=datetime.now(timezone.utc),
        is_emulator=False,
        is_rooted=False,
        carrier_name="Airtel",
        sim_swap_hours_ago=120.0,  # 5 days ago
    )

    status, msg, details = SimBindingEngine.verify_assertion(enrollment, assertion)
    assert status == HardwareBindingStatus.BOUND_TRUSTED
    assert details["action"] == "PROCEED"


def test_sim_binding_emulator_rejection():
    enrollment = SimBindingEngine.enroll_binding(
        account_id="ACC-IN-002",
        installation_id="inst-test-01",
        device_imei="352099001761482",
        sim_iccid="8991101200003204512",
    )
    # Execution inside Bluestacks / Android x86 emulator
    assertion = HardwareBindingAssertion(
        device_imei_hash=enrollment.bound_device_imei_hash,
        sim_iccid_hash=enrollment.bound_sim_iccid_hash,
        app_instance_id="app-inst-xyz",
        client_timestamp=datetime.now(timezone.utc),
        is_emulator=True,
    )

    status, msg, details = SimBindingEngine.verify_assertion(enrollment, assertion)
    assert status == HardwareBindingStatus.EMULATOR_DETECTED_BLOCKED
    assert details["action"] == "HARD_BLOCK"


def test_sim_binding_recent_swap_cooldown():
    enrollment = SimBindingEngine.enroll_binding(
        account_id="ACC-IN-003",
        installation_id="inst-test-01",
        device_imei="352099001761482",
        sim_iccid="8991101200003204512",
    )
    # SIM swap happened 4.5 hours ago (< 24h)
    assertion = HardwareBindingAssertion(
        device_imei_hash=enrollment.bound_device_imei_hash,
        sim_iccid_hash=enrollment.bound_sim_iccid_hash,
        app_instance_id="app-inst-xyz",
        client_timestamp=datetime.now(timezone.utc),
        is_emulator=False,
        sim_swap_hours_ago=4.5,
    )

    status, msg, details = SimBindingEngine.verify_assertion(enrollment, assertion)
    assert status == HardwareBindingStatus.SIM_SWAP_DETECTED_COOLDOWN
    assert details["action"] == "COOLING_OFF_HOLD"
    assert details["cooldown_remaining_hours"] == 19.5


def test_sim_binding_device_mismatch():
    enrollment = SimBindingEngine.enroll_binding(
        account_id="ACC-IN-004",
        installation_id="inst-test-01",
        device_imei="352099001761482",
        sim_iccid="8991101200003204512",
    )
    # Stolen SIM placed in unknown device
    assertion = HardwareBindingAssertion(
        device_imei_hash="fake-foreign-device-imei-hash-9999",
        sim_iccid_hash=enrollment.bound_sim_iccid_hash,
        app_instance_id="app-inst-xyz",
        client_timestamp=datetime.now(timezone.utc),
        is_emulator=False,
    )

    status, msg, details = SimBindingEngine.verify_assertion(enrollment, assertion)
    assert status == HardwareBindingStatus.DEVICE_MISMATCH
    assert details["action"] == "STEP_UP_IN_PERSON_BRANCH"
