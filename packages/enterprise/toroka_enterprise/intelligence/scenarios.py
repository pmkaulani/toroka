"""Structured competing investigation scenarios and counterfactual hypothesis models."""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .events import IntelligenceEvent
    from .change_vector import ChangeVector
    from .contradictions import EvidenceContradiction


@dataclass(frozen=True)
class InvestigationScenario:
    scenario_id: str
    title: str
    description: str
    required_evidence: tuple[str, ...]
    supporting_evidence: tuple[str, ...]
    contradicting_evidence: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    relative_support: float


def generate_competing_scenarios(
    events: list[IntelligenceEvent],
    *,
    change_vector: ChangeVector | None = None,
    contradictions: list[EvidenceContradiction] | None = None,
) -> list[InvestigationScenario]:
    """Generates standard institutional competing scenarios evaluated deterministically against available evidence."""
    available_sources = {e.source_system.lower().strip() for e in events if e.source_system}
    event_types = {e.event_type.lower().strip() for e in events if e.event_type}

    has_ticket = "crm" in available_sources or any("ticket" in et or "complaint" in et for et in event_types)
    has_beneficiary_change = any("beneficiary" in et for et in event_types)
    has_transfer = any("transfer" in et or "payment" in et or "payout" in et for et in event_types)
    has_unusual_network = bool(change_vector and ("device" in change_vector.changed_dimensions or "ip_address" in change_vector.changed_dimensions))
    has_conflicts = bool(contradictions and len(contradictions) > 0)

    # 1. SCENARIO A: Legitimate Customer Service Activity
    supp_a: list[str] = []
    contra_a: list[str] = []
    miss_a: list[str] = []

    if has_ticket:
        supp_a.append("Customer ticket or inquiry on record (CRM/Support)")
    else:
        miss_a.append("Customer service ticket authorization record")

    if not has_unusual_network:
        supp_a.append("Conducted from standard branch workstation/IP")
    else:
        contra_a.append("Unusual terminal or external IP address detected")

    if has_conflicts:
        contra_a.append("Unresolved telemetry timestamps or session conflicts")

    score_a = max(0.1, round((len(supp_a) + 0.5) / (len(supp_a) + len(contra_a) + len(miss_a) + 1.0), 2))

    scenario_a = InvestigationScenario(
        scenario_id="scenario_legitimate_service",
        title="Legitimate Customer Service Activity",
        description="Employee acted under an authorized customer request or standard customer care operational workflow.",
        required_evidence=("crm_ticket", "workstation_telemetry", "standard_working_hours"),
        supporting_evidence=tuple(supp_a),
        contradicting_evidence=tuple(contra_a),
        missing_evidence=tuple(miss_a),
        relative_support=score_a,
    )

    # 2. SCENARIO B: Unauthorized Insider Misuse
    supp_b: list[str] = []
    contra_b: list[str] = []
    miss_b: list[str] = []

    if has_beneficiary_change and has_transfer:
        supp_b.append("Beneficiary modification immediately followed by transfer execution")
    if not has_ticket:
        supp_b.append("Absence of prior customer service ticket or inquiry")
    else:
        contra_b.append("Valid customer inquiry logged prior to action")

    if has_unusual_network:
        supp_b.append("Action executed across unexpected device or IP")

    score_b = max(0.1, round((len(supp_b) + 0.5) / (len(supp_b) + len(contra_b) + len(miss_b) + 1.0), 2))

    scenario_b = InvestigationScenario(
        scenario_id="scenario_insider_misuse",
        title="Unauthorized Employee Intervention",
        description="Employee accessed customer accounts and initiated changes outside formal customer service authority.",
        required_evidence=("core_banking_audit", "iam_session_log", "beneficiary_change_record"),
        supporting_evidence=tuple(supp_b),
        contradicting_evidence=tuple(contra_b),
        missing_evidence=tuple(miss_b),
        relative_support=score_b,
    )

    # 3. SCENARIO C: Compromised Employee Credentials
    supp_c: list[str] = []
    contra_c: list[str] = []
    miss_c: list[str] = []

    if has_unusual_network:
        supp_c.append("Session initiated from anomalous device or external IP")
    else:
        contra_c.append("Activity performed from verified physical branch hardware")

    if has_conflicts:
        supp_c.append("Simultaneous or conflicting active sessions recorded in logs")
    else:
        miss_c.append("Corroborating SIEM brute-force or impossible-travel telemetry")

    score_c = max(0.1, round((len(supp_c) + 0.5) / (len(supp_c) + len(contra_c) + len(miss_c) + 1.0), 2))

    scenario_c = InvestigationScenario(
        scenario_id="scenario_compromised_credentials",
        title="Compromised Employee Credentials",
        description="External third-party obtained valid employee credentials and performed actions without employee awareness.",
        required_evidence=("siem_endpoint_telemetry", "external_ip_log", "mfa_challenge_record"),
        supporting_evidence=tuple(supp_c),
        contradicting_evidence=tuple(contra_c),
        missing_evidence=tuple(miss_c),
        relative_support=score_c,
    )

    # 4. SCENARIO D: System / Integration Process Error
    supp_d: list[str] = []
    contra_d: list[str] = []
    miss_d: list[str] = []

    if has_conflicts:
        supp_d.append("Timestamp drift or conflicting status across Core Banking and Switch")
    else:
        contra_d.append("Timestamps and payload digests align cleanly across systems")

    score_d = max(0.1, round((len(supp_d) + 0.5) / (len(supp_d) + len(contra_d) + len(miss_d) + 1.0), 2))

    scenario_d = InvestigationScenario(
        scenario_id="scenario_system_error",
        title="System Integration or Ingestion Error",
        description="Apparent discrepancy caused by asynchronous event replay, network retry, or delayed batch synchronization.",
        required_evidence=("switch_reconciliation_log", "message_queue_ack", "retry_header"),
        supporting_evidence=tuple(supp_d),
        contradicting_evidence=tuple(contra_d),
        missing_evidence=tuple(miss_d),
        relative_support=score_d,
    )

    # Normalize relative support so they sum to 1.0
    total = score_a + score_b + score_c + score_d
    return [
        InvestigationScenario(
            scenario_id=s.scenario_id,
            title=s.title,
            description=s.description,
            required_evidence=s.required_evidence,
            supporting_evidence=s.supporting_evidence,
            contradicting_evidence=s.contradicting_evidence,
            missing_evidence=s.missing_evidence,
            relative_support=round(s.relative_support / total, 2),
        )
        for s in (scenario_a, scenario_b, scenario_c, scenario_d)
    ]
