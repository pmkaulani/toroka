"""Evidence contradictions detection and auditable conflict tracking."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .events import IntelligenceEvent


class ContradictionSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True)
class EvidenceContradiction:
    contradiction_id: str
    event_a: str
    event_b: str
    field: str
    value_a: str
    value_b: str
    severity: ContradictionSeverity
    explanation: str
    resolution_required: bool = True


def detect_evidence_contradictions(
    events: list[IntelligenceEvent],
) -> list[EvidenceContradiction]:
    """Scans independently sourced events for factual contradictions without silently resolving them."""
    contradictions: list[EvidenceContradiction] = []
    
    # Sort chronologically
    sorted_events = sorted(events, key=lambda e: e.event_time)

    for i in range(len(sorted_events)):
        for j in range(i + 1, len(sorted_events)):
            ea = sorted_events[i]
            eb = sorted_events[j]

            # 1. Temporal contradiction: overlapping active sessions vs terminated sessions
            time_diff = abs((eb.event_time - ea.event_time).total_seconds())
            if ea.actor and eb.actor and ea.actor == eb.actor:
                # Same actor, within 60 seconds, but conflicting branch locations or IP addresses
                ip_a = ea.attributes.get("ip_address")
                ip_b = eb.attributes.get("ip_address")
                if ip_a and ip_b and ip_a != ip_b and time_diff < 120:
                    cid = f"contra_{uuid.uuid4().hex[:10]}"
                    contradictions.append(
                        EvidenceContradiction(
                            contradiction_id=cid,
                            event_a=ea.event_id,
                            event_b=eb.event_id,
                            field="ip_address",
                            value_a=str(ip_a),
                            value_b=str(ip_b),
                            severity=ContradictionSeverity.HIGH,
                            explanation=(
                                f"Actor {ea.actor} associated with simultaneous IP addresses {ip_a} ({ea.source_system}) "
                                f"and {ip_b} ({eb.source_system}) within {int(time_diff)} seconds."
                            ),
                            resolution_required=True,
                        )
                    )

                branch_a = ea.attributes.get("branch_code") or ea.attributes.get("branch_id")
                branch_b = eb.attributes.get("branch_code") or eb.attributes.get("branch_id")
                if branch_a and branch_b and branch_a != branch_b and time_diff < 300:
                    cid = f"contra_{uuid.uuid4().hex[:10]}"
                    contradictions.append(
                        EvidenceContradiction(
                            contradiction_id=cid,
                            event_a=ea.event_id,
                            event_b=eb.event_id,
                            field="branch_location",
                            value_a=str(branch_a),
                            value_b=str(branch_b),
                            severity=ContradictionSeverity.HIGH,
                            explanation=(
                                f"Physical branch conflict: actor {ea.actor} recorded at branch {branch_a} "
                                f"and branch {branch_b} within {int(time_diff)} seconds."
                            ),
                            resolution_required=True,
                        )
                    )

            # 2. System status contradiction: Core Banking vs Switch state
            if ea.subject and eb.subject and ea.subject == eb.subject:
                status_a = ea.attributes.get("account_status")
                status_b = eb.attributes.get("account_status")
                if status_a and status_b and status_a.lower() != status_b.lower() and time_diff < 3600:
                    cid = f"contra_{uuid.uuid4().hex[:10]}"
                    contradictions.append(
                        EvidenceContradiction(
                            contradiction_id=cid,
                            event_a=ea.event_id,
                            event_b=eb.event_id,
                            field="account_status",
                            value_a=str(status_a),
                            value_b=str(status_b),
                            severity=ContradictionSeverity.MEDIUM,
                            explanation=(
                                f"Subject {ea.subject} account status reported as '{status_a}' by {ea.source_system} "
                                f"and '{status_b}' by {eb.source_system} within 1 hour."
                            ),
                            resolution_required=True,
                        )
                    )

            # 3. Session status contradiction: active vs terminated
            if ea.actor and eb.actor and ea.actor == eb.actor:
                if ea.event_type == "session_start" and eb.event_type == "workstation_terminated" and ea.event_time > eb.event_time:
                    # Ingested order or log discrepancy
                    if (ea.event_time - eb.event_time).total_seconds() < 60:
                        cid = f"contra_{uuid.uuid4().hex[:10]}"
                        contradictions.append(
                            EvidenceContradiction(
                                contradiction_id=cid,
                                event_a=ea.event_id,
                                event_b=eb.event_id,
                                field="session_lifecycle",
                                value_a=ea.event_type,
                                value_b=eb.event_type,
                                severity=ContradictionSeverity.MEDIUM,
                                explanation=(
                                    f"Session start on {ea.source_system} recorded after workstation termination on {eb.source_system} "
                                    f"with {int(time_diff)}s difference. Potential timestamp drift or session hijacking."
                                ),
                                resolution_required=True,
                            )
                        )

    return contradictions
