"""Cryptographic SIM Binding & Hardware Integrity Validator Module.

Implements hardware-anchored session verification and device binding based on:
1. National Payments Corporation of India (NPCI) UPI SIM Binding Directives.
2. Department of Telecommunications (DoT) Sanchar Saathi DIP (Digital Intelligence Platform).
3. Mobile Security Guidelines: Emulator prohibition, hardware root detection, and
   mandatory 24-hour transaction cooldown following SIM card replacements.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import hmac
from typing import Any


class HardwareBindingStatus(str, Enum):
    """Integrity and binding status of the client hardware and physical SIM."""
    BOUND_TRUSTED = "BOUND_TRUSTED"
    SIM_SWAP_DETECTED_COOLDOWN = "SIM_SWAP_DETECTED_COOLDOWN"
    DEVICE_MISMATCH = "DEVICE_MISMATCH"
    EMULATOR_DETECTED_BLOCKED = "EMULATOR_DETECTED_BLOCKED"
    ROOTED_COMPROMISED_DEVICE = "ROOTED_COMPROMISED_DEVICE"


@dataclass
class HardwareBindingAssertion:
    """Cryptographic hardware assertion token transmitted by the client SDK."""
    device_imei_hash: str
    sim_iccid_hash: str
    app_instance_id: str
    client_timestamp: datetime
    is_emulator: bool = False
    is_rooted: bool = False
    carrier_name: str | None = None
    sim_swap_hours_ago: float | None = None
    hardware_signature: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def generate_digest(self, secret: str = "toroka-hardware-anchor-secret") -> str:
        """Computes HMAC-SHA256 signature across the hardware binding components."""
        payload = (
            f"{self.device_imei_hash}:{self.sim_iccid_hash}:{self.app_instance_id}:"
            f"{int(self.is_emulator)}:{int(self.is_rooted)}"
        ).encode("utf-8")
        return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


@dataclass
class SimBindingEnrollment:
    """Persisted hardware and SIM anchor baseline for a customer account."""
    account_id: str
    installation_id: str
    bound_device_imei_hash: str
    bound_sim_iccid_hash: str
    enrolled_at: datetime
    last_verified_at: datetime
    status: HardwareBindingStatus = HardwareBindingStatus.BOUND_TRUSTED
    carrier_name: str = "Safaricom"
    metadata: dict[str, Any] = field(default_factory=dict)


class SimBindingEngine:
    """Engine executing NPCI-style SIM binding and device integrity checks."""

    @staticmethod
    def enroll_binding(
        account_id: str,
        installation_id: str,
        device_imei: str,
        sim_iccid: str,
        carrier_name: str = "Safaricom",
    ) -> SimBindingEnrollment:
        """Enroll a new hardware and SIM anchor for a customer account."""
        now = datetime.now(timezone.utc)
        imei_hash = hashlib.sha256(device_imei.encode("utf-8")).hexdigest()
        iccid_hash = hashlib.sha256(sim_iccid.encode("utf-8")).hexdigest()

        return SimBindingEnrollment(
            account_id=account_id,
            installation_id=installation_id,
            bound_device_imei_hash=imei_hash,
            bound_sim_iccid_hash=iccid_hash,
            enrolled_at=now,
            last_verified_at=now,
            status=HardwareBindingStatus.BOUND_TRUSTED,
            carrier_name=carrier_name,
        )

    @staticmethod
    def verify_assertion(
        enrollment: SimBindingEnrollment,
        assertion: HardwareBindingAssertion,
    ) -> tuple[HardwareBindingStatus, str, dict[str, Any]]:
        """Verify an inflight hardware binding assertion against the enrolled baseline."""
        now = datetime.now(timezone.utc)

        # 1. Check for emulator execution (Bluestacks, QEMU, Nox, Android x86)
        if assertion.is_emulator:
            return (
                HardwareBindingStatus.EMULATOR_DETECTED_BLOCKED,
                "Transaction rejected: execution within an emulator environment is strictly "
                "prohibited by NPCI SIM binding policy.",
                {"action": "HARD_BLOCK", "risk_level": "CRITICAL"},
            )

        # 2. Check for rooted or jailbroken OS
        if assertion.is_rooted:
            return (
                HardwareBindingStatus.ROOTED_COMPROMISED_DEVICE,
                "Transaction rejected: client device integrity compromised (root/jailbreak detected).",
                {"action": "HARD_BLOCK", "risk_level": "CRITICAL"},
            )

        # 3. Check for recent SIM card swap (< 24 hours cooldown)
        if assertion.sim_swap_hours_ago is not None and assertion.sim_swap_hours_ago < 24.0:
            return (
                HardwareBindingStatus.SIM_SWAP_DETECTED_COOLDOWN,
                f"Recent SIM card replacement detected ({assertion.sim_swap_hours_ago:.1f} hours ago). "
                f"Statutory 24-hour transaction cooling-off period active (DoT/NPCI Standard).",
                {"action": "COOLING_OFF_HOLD", "cooldown_remaining_hours": 24.0 - assertion.sim_swap_hours_ago},
            )

        # 4. Check device IMEI hash match
        if assertion.device_imei_hash != enrollment.bound_device_imei_hash:
            return (
                HardwareBindingStatus.DEVICE_MISMATCH,
                "Device hardware mismatch: current device does not match the enrolled hardware anchor.",
                {"action": "STEP_UP_IN_PERSON_BRANCH", "risk_level": "HIGH"},
            )

        # 5. Check SIM ICCID hash match
        if assertion.sim_iccid_hash != enrollment.bound_sim_iccid_hash:
            return (
                HardwareBindingStatus.SIM_SWAP_DETECTED_COOLDOWN,
                "SIM ICCID mismatch: unauthorized SIM card swap detected. Session invalidated.",
                {"action": "BLOCK_AND_REVOKE_TOKEN", "risk_level": "HIGH"},
            )

        # Success: update last verified timestamp
        enrollment.last_verified_at = now
        return (
            HardwareBindingStatus.BOUND_TRUSTED,
            "Hardware anchor and physical SIM binding verified successfully.",
            {"action": "PROCEED", "risk_level": "LOW"},
        )
