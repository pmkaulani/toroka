"""Controlled source reliability framework and independent corroboration utilities."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class SourceSystem(StrEnum):
    CORE_BANKING = "core_banking"
    PAYMENT_SWITCH = "payment_switch"
    IAM = "iam"
    HR = "hr"
    SIEM = "siem"
    CRM = "crm"
    MANUAL_INVESTIGATION = "manual_investigation"


@dataclass(frozen=True)
class SourceReliability:
    source: str
    weight: float
    description: str
    is_authoritative: bool


DEFAULT_SOURCE_RELIABILITIES: dict[str, SourceReliability] = {
    SourceSystem.CORE_BANKING.value: SourceReliability(
        source=SourceSystem.CORE_BANKING.value,
        weight=1.0,
        description="Core banking general ledger and posting journals; primary system of record.",
        is_authoritative=True,
    ),
    SourceSystem.PAYMENT_SWITCH.value: SourceReliability(
        source=SourceSystem.PAYMENT_SWITCH.value,
        weight=0.95,
        description="Interbank payment switch and settlement rails (e.g. M-PESA, SWIFT, RTGS).",
        is_authoritative=True,
    ),
    SourceSystem.IAM.value: SourceReliability(
        source=SourceSystem.IAM.value,
        weight=0.90,
        description="Identity and access management directory, SSO, and authentication logs.",
        is_authoritative=True,
    ),
    SourceSystem.HR.value: SourceReliability(
        source=SourceSystem.HR.value,
        weight=0.85,
        description="Human resources management system, payroll roster, leave and organizational hierarchy.",
        is_authoritative=True,
    ),
    SourceSystem.SIEM.value: SourceReliability(
        source=SourceSystem.SIEM.value,
        weight=0.80,
        description="Security information and event management; aggregated network/host telemetry.",
        is_authoritative=False,
    ),
    SourceSystem.CRM.value: SourceReliability(
        source=SourceSystem.CRM.value,
        weight=0.70,
        description="Customer relationship management, service tickets, and contact records.",
        is_authoritative=False,
    ),
    SourceSystem.MANUAL_INVESTIGATION.value: SourceReliability(
        source=SourceSystem.MANUAL_INVESTIGATION.value,
        weight=0.75,
        description="Investigator work notes, manual annotations, and interview records.",
        is_authoritative=False,
    ),
}


def get_source_reliability(source_name: str) -> SourceReliability:
    key = source_name.lower().strip()
    return DEFAULT_SOURCE_RELIABILITIES.get(
        key,
        SourceReliability(
            source=key,
            weight=0.5,
            description="Unregistered or external source system.",
            is_authoritative=False,
        ),
    )
