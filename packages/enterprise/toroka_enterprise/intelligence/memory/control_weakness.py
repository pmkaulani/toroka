from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from ..events import IntelligenceEvent


class ControlWeaknessType(StrEnum):
    TIMESTAMP_RECONCILIATION_WEAKNESS = "timestamp_reconciliation_weakness"
    CUSTOMER_AUTHORISATION_EVIDENCE_GAP = "customer_authorisation_evidence_gap"
    ACCESS_GOVERNANCE_WEAKNESS = "access_governance_weakness"
    DELAYED_DETECTION_OPPORTUNITY = "delayed_detection_opportunity"
    RECURRING_PROCESS_CONTROL_WEAKNESS = "recurring_process_control_weakness"


CONTROL_WEAKNESS_DESCRIPTIONS: dict[ControlWeaknessType, str] = {
    ControlWeaknessType.TIMESTAMP_RECONCILIATION_WEAKNESS: (
        "Inconsistent, inverted, or misaligned timestamps observed across different source systems for linked events."
    ),
    ControlWeaknessType.CUSTOMER_AUTHORISATION_EVIDENCE_GAP: (
        "Sensitive customer or account modifications executed without a verifiable customer service ticket or authorisation."
    ),
    ControlWeaknessType.ACCESS_GOVERNANCE_WEAKNESS: (
        "Privileged access session or credential override occurred without documented supervisor co-sign or dual control."
    ),
    ControlWeaknessType.DELAYED_DETECTION_OPPORTUNITY: (
        "Substantial detection latency; incident was identified only following an explicit customer complaint or delayed audit."
    ),
    ControlWeaknessType.RECURRING_PROCESS_CONTROL_WEAKNESS: (
        "Operational policy exception or control bypass repeated across accounts or transactions without administrative escalation."
    ),
}


@dataclass(frozen=True)
class ControlWeaknessEvidence:
    weakness_type: ControlWeaknessType
    title: str
    description: str
    event_ids: tuple[str, ...]
    source_systems: tuple[str, ...]
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "weakness_type": self.weakness_type.value,
            "title": self.title,
            "description": self.description,
            "event_ids": list(self.event_ids),
            "source_systems": list(self.source_systems),
            "details": dict(self.details),
        }


def detect_control_weaknesses(
    events: list[IntelligenceEvent],
) -> tuple[ControlWeaknessEvidence, ...]:
    """Deterministically analyze case events for institutional control and telemetry gaps."""
    if not events:
        return ()

    ev_sorted = sorted(events, key=lambda e: (e.event_time, e.event_id))
    weaknesses: list[ControlWeaknessEvidence] = []

    # 1. Customer Authorisation Evidence Gap:
    # Sensitive change (beneficiary, limit, contact) without service ticket or customer authorisation
    sensitive_types = {
        "beneficiary_change",
        "contact_details_changed",
        "limit_change",
        "account_unrestricted",
    }
    authorisation_types = {
        "service_ticket_created",
        "customer_authorisation",
        "customer_consent",
        "mandate_verified",
    }

    sensitive_events = [e for e in ev_sorted if e.event_type in sensitive_types]
    auth_events = [e for e in ev_sorted if e.event_type in authorisation_types]

    if sensitive_events and not auth_events:
        weaknesses.append(
            ControlWeaknessEvidence(
                weakness_type=ControlWeaknessType.CUSTOMER_AUTHORISATION_EVIDENCE_GAP,
                title="Customer Authorisation Evidence Gap",
                description=(
                    f"Identified {len(sensitive_events)} sensitive modification(s) "
                    "without corresponding customer service ticket or documented customer consent in case evidence."
                ),
                event_ids=tuple(e.event_id for e in sensitive_events),
                source_systems=tuple(
                    sorted(set(e.source_system for e in sensitive_events if e.source_system))
                ),
                details={"sensitive_event_types": list(set(e.event_type for e in sensitive_events))},
            )
        )

    # 2. Access Governance Weakness:
    # Privileged login or role change without supervisor co-sign or dual approval
    privileged_types = {"privileged_login", "role_change", "mfa_disabled"}
    approval_types = {"supervisor_approval", "dual_control_approved", "change_request_approved"}

    priv_events = [e for e in ev_sorted if e.event_type in privileged_types]
    appr_events = [e for e in ev_sorted if e.event_type in approval_types]

    if priv_events and not appr_events:
        weaknesses.append(
            ControlWeaknessEvidence(
                weakness_type=ControlWeaknessType.ACCESS_GOVERNANCE_WEAKNESS,
                title="Access Governance Weakness",
                description=(
                    f"Observed {len(priv_events)} privileged or credential change event(s) "
                    "without supervisor co-sign or dual-control authorization in the audit record."
                ),
                event_ids=tuple(e.event_id for e in priv_events),
                source_systems=tuple(
                    sorted(set(e.source_system for e in priv_events if e.source_system))
                ),
                details={"privileged_event_types": list(set(e.event_type for e in priv_events))},
            )
        )

    # 3. Delayed Detection Opportunity:
    # Incident surfaced primarily via customer complaint after funds transfers
    complaint_events = [e for e in ev_sorted if e.event_type == "customer_complaint"]
    transfer_events = [
        e for e in ev_sorted if e.event_type in ("transfer_initiated", "high_value_transfer")
    ]

    if complaint_events:
        # Check if complaint occurred after sensitive changes or transfers
        earliest_complaint = min(e.event_time for e in complaint_events)
        preceding_transfers = [e for e in transfer_events if e.event_time <= earliest_complaint]
        if preceding_transfers or sensitive_events:
            lead_time_seconds = (
                earliest_complaint - min(e.event_time for e in (preceding_transfers or sensitive_events))
            ).total_seconds()
            weaknesses.append(
                ControlWeaknessEvidence(
                    weakness_type=ControlWeaknessType.DELAYED_DETECTION_OPPORTUNITY,
                    title="Delayed Detection Opportunity",
                    description=(
                        "Incident was triggered only after explicit customer complaint "
                        f"({lead_time_seconds:.0f}s after sensitive activity), indicating reactive detection."
                    ),
                    event_ids=tuple(e.event_id for e in complaint_events + preceding_transfers),
                    source_systems=tuple(
                        sorted(
                            set(
                                e.source_system
                                for e in (complaint_events + preceding_transfers)
                                if e.source_system
                            )
                        )
                    ),
                    details={"detection_latency_seconds": lead_time_seconds},
                )
            )

    # 4. Timestamp Reconciliation Weakness:
    # Cross-system clock skew or out-of-order logs for linked entities
    # For example: event B logically caused by A has an earlier timestamp from another source system
    for i in range(len(ev_sorted) - 1):
        e1 = ev_sorted[i]
        e2 = ev_sorted[i + 1]
        if (
            e1.source_system
            and e2.source_system
            and e1.source_system != e2.source_system
        ):
            # Check for negative delta in sequence if attributes indicate sequence dependency
            if e2.attributes.get("preceding_event_id") == e1.event_id and e2.event_time < e1.event_time:
                weaknesses.append(
                    ControlWeaknessEvidence(
                        weakness_type=ControlWeaknessType.TIMESTAMP_RECONCILIATION_WEAKNESS,
                        title="Timestamp Reconciliation Weakness",
                        description=(
                            f"Cross-system timestamp inversion observed between {e1.source_system} "
                            f"and {e2.source_system} for correlated events."
                        ),
                        event_ids=(e1.event_id, e2.event_id),
                        source_systems=(e1.source_system, e2.source_system),
                        details={
                            "skew_seconds": (e1.event_time - e2.event_time).total_seconds(),
                        },
                    )
                )

    # 5. Recurring Process Control Weakness:
    # Repeated limit modifications or account unrestrictions without administrative escalation
    unrestriction_events = [e for e in ev_sorted if e.event_type == "account_unrestricted"]
    limit_events = [e for e in ev_sorted if e.event_type == "limit_change"]
    if len(unrestriction_events) >= 2 or len(limit_events) >= 3:
        events_involved = unrestriction_events + limit_events
        weaknesses.append(
            ControlWeaknessEvidence(
                weakness_type=ControlWeaknessType.RECURRING_PROCESS_CONTROL_WEAKNESS,
                title="Recurring Process Control Weakness",
                description=(
                    "Multiple un-escalated policy threshold exceptions (repeated limit adjustments "
                    "or restrictions lifted) observed within the same case scope."
                ),
                event_ids=tuple(e.event_id for e in events_involved),
                source_systems=tuple(
                    sorted(set(e.source_system for e in events_involved if e.source_system))
                ),
                details={
                    "unrestriction_count": len(unrestriction_events),
                    "limit_change_count": len(limit_events),
                },
            )
        )

    return tuple(weaknesses)
