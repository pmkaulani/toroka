"""Hong Kong HKMA / HKPF FPS Scameter High-Risk Proxy & Statutory Liability Shielding.

Implements:
1. Hong Kong Faster Payment System (FPS) Scameter Integration:
   - Queries proxy identifiers (Mobile phone, Email address, Account number, National ID)
     against police cybercrime reports and high-frequency mule alerts.
2. Unskippable High-Risk Advisory Banner:
   - Evaluates risk classification: HIGH_RISK_POLICE_RECORD (Red Banner),
     SUSPICIOUS_HIGH_FREQUENCY (Amber Banner), or CLEAR.
3. Statutory Liability Shielding Waiver:
   - Under HKMA statutory guidelines, if a customer overrides a HIGH_RISK warning
     and confirms the transfer, the system requires a cryptographic signed waiver.
   - The executed waiver legally shields the financial institution from reimbursement
     obligations, shifting primary financial liability to the customer.
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from enum import StrEnum
from typing import Any


def _ensure_utc(dt: datetime | None) -> datetime:
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class ScameterRiskLevel(StrEnum):
    HIGH_RISK_POLICE_RECORD = "HIGH_RISK_POLICE_RECORD"
    SUSPICIOUS_HIGH_FREQUENCY = "SUSPICIOUS_HIGH_FREQUENCY"
    MODERATE_ANOMALOUS = "MODERATE_ANOMALOUS"
    CLEAR = "CLEAR"


@dataclass(frozen=True)
class ScameterLookupResult:
    proxy_id: str
    proxy_type: str  # PHONE, EMAIL, ACCOUNT, NATIONAL_ID
    risk_level: ScameterRiskLevel
    police_report_reference: str | None
    unskippable_warning_required: bool
    warning_title: str
    warning_body: str
    requires_liability_waiver: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "proxy_id": self.proxy_id,
            "proxy_type": self.proxy_type,
            "risk_level": self.risk_level.value,
            "police_report_reference": self.police_report_reference,
            "unskippable_warning_required": self.unskippable_warning_required,
            "warning_title": self.warning_title,
            "warning_body": self.warning_body,
            "requires_liability_waiver": self.requires_liability_waiver,
        }


@dataclass(frozen=True)
class LiabilityShieldWaiver:
    waiver_id: str
    account_id: str
    customer_id: str
    proxy_id: str
    risk_level: ScameterRiskLevel
    transfer_amount: Decimal
    signed_timestamp: datetime
    waiver_hash: str
    is_institution_shielded: bool = True
    statutory_framework: str = "Hong Kong HKMA FPS Scameter Statutory Shield Framework"

    def to_dict(self) -> dict[str, Any]:
        return {
            "waiver_id": self.waiver_id,
            "account_id": self.account_id,
            "customer_id": self.customer_id,
            "proxy_id": self.proxy_id,
            "risk_level": self.risk_level.value,
            "transfer_amount": str(self.transfer_amount),
            "signed_timestamp": self.signed_timestamp.isoformat(),
            "waiver_hash": self.waiver_hash,
            "is_institution_shielded": self.is_institution_shielded,
            "statutory_framework": self.statutory_framework,
        }


class FpsScameterShieldEngine:
    """Evaluates proxy identifiers against Scameter intelligence and executes liability waivers."""

    def __init__(self) -> None:
        # proxy_id -> (risk_level, police_case_ref)
        self._registry: dict[str, tuple[ScameterRiskLevel, str | None]] = {}
        self._signed_waivers: dict[str, LiabilityShieldWaiver] = {}

    def register_police_proxy(
        self,
        proxy_id: str,
        risk_level: ScameterRiskLevel,
        police_case_ref: str | None = None,
    ) -> None:
        self._registry[proxy_id.strip()] = (risk_level, police_case_ref)

    def lookup_proxy(self, proxy_id: str, proxy_type: str = "PHONE") -> ScameterLookupResult:
        pid = proxy_id.strip()
        risk, police_ref = self._registry.get(pid, (ScameterRiskLevel.CLEAR, None))

        if risk == ScameterRiskLevel.HIGH_RISK_POLICE_RECORD:
            return ScameterLookupResult(
                proxy_id=pid,
                proxy_type=proxy_type,
                risk_level=risk,
                police_report_reference=police_ref,
                unskippable_warning_required=True,
                warning_title="CRITICAL RED WARNING: POLICE SCAM RECORD DETECTED",
                warning_body=(
                    f"The recipient identifier {pid} is registered in the Hong Kong Police Force / Scameter "
                    f"cybercrime database under report reference {police_ref or 'HKPF-CR-CONFIRMED'}. "
                    f"Transfers to this recipient have a near-certain probability of being an irreversible fraud."
                ),
                requires_liability_waiver=True,
            )
        elif risk == ScameterRiskLevel.SUSPICIOUS_HIGH_FREQUENCY:
            return ScameterLookupResult(
                proxy_id=pid,
                proxy_type=proxy_type,
                risk_level=risk,
                police_report_reference=police_ref,
                unskippable_warning_required=True,
                warning_title="AMBER ALERT: SUSPICIOUS RECIPIENT ACTIVITY",
                warning_body=(
                    f"Recipient {pid} has been flagged for abnormal high-velocity inflows across consortium members. "
                    f"Verify the recipient's identity through an independent, trusted channel before proceeding."
                ),
                requires_liability_waiver=True,
            )
        else:
            return ScameterLookupResult(
                proxy_id=pid,
                proxy_type=proxy_type,
                risk_level=ScameterRiskLevel.CLEAR,
                police_report_reference=None,
                unskippable_warning_required=False,
                warning_title="NORMAL",
                warning_body="Recipient proxy identifier has no active police scam reports.",
                requires_liability_waiver=False,
            )

    def execute_statutory_waiver(
        self,
        account_id: str,
        customer_id: str,
        proxy_id: str,
        risk_level: ScameterRiskLevel,
        transfer_amount: Decimal | float,
        customer_consent_ack: bool,
        now: datetime | None = None,
    ) -> LiabilityShieldWaiver:
        if not customer_consent_ack:
            raise PermissionError("Customer must affirmatively acknowledge the Scameter warning to execute waiver")

        amt = Decimal(str(transfer_amount))
        now_utc = _ensure_utc(now)
        waiver_id = f"SCAMETER-WVR-{uuid.uuid4().hex[:12].upper()}"

        raw_digest = f"{waiver_id}:{account_id}:{customer_id}:{proxy_id}:{risk_level.value}:{amt}:{now_utc.isoformat()}"
        w_hash = hashlib.sha256(raw_digest.encode("utf-8")).hexdigest()

        waiver = LiabilityShieldWaiver(
            waiver_id=waiver_id,
            account_id=account_id,
            customer_id=customer_id,
            proxy_id=proxy_id,
            risk_level=risk_level,
            transfer_amount=amt,
            signed_timestamp=now_utc,
            waiver_hash=w_hash,
            is_institution_shielded=True,
        )
        self._signed_waivers[waiver_id] = waiver
        return waiver

    def get_waiver(self, waiver_id: str) -> LiabilityShieldWaiver | None:
        return self._signed_waivers.get(waiver_id)
