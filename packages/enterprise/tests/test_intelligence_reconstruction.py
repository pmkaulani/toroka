"""Tests for Attack Reconstruction Engine, state transitions, change vectors, and competing scenarios."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import pytest

from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise.intelligence.entities import EntityRef, EntityType, Relationship
from toroka_enterprise.intelligence.reconstruction import (
    AttackReconstruction,
    ReconstructionStep,
)
from toroka_enterprise.intelligence.transitions import (
    StateTransition,
    identify_transition,
    extract_transitions_from_events,
)
from toroka_enterprise.intelligence.change_vector import (
    ChangeVector,
    build_change_vector,
)
from toroka_enterprise.intelligence.attack_path import (
    AttackPath,
    AttackPathNode,
    AttackPathEdge,
    build_attack_path_from_relationships,
)
from toroka_enterprise.intelligence.contradictions import (
    EvidenceContradiction,
    ContradictionSeverity,
    detect_evidence_contradictions,
)
from toroka_enterprise.intelligence.evidence_completeness import (
    EvidenceRequirement,
    EvidenceCompleteness,
    calculate_evidence_completeness,
)
from toroka_enterprise.intelligence.reconstruction_engine import reconstruct
from toroka_enterprise.intelligence.scenarios import (
    InvestigationScenario,
    generate_competing_scenarios,
)


def test_reconstruction_step_and_bundle_validation():
    now = datetime.now(timezone.utc)
    step = ReconstructionStep(
        sequence=0,
        event_id="evt_1",
        event_type="session_start",
        event_time=now,
        actor_id="emp_01",
        subject_id="cif_100",
        source_system="iam",
        explanation="Staff login",
        evidence_strength=0.95,
        provenance_ids=("rec_101",),
    )
    assert step.sequence == 0
    assert step.evidence_strength == 0.95

    # Negative sequence raises ValueError
    with pytest.raises(ValueError, match="sequence cannot be negative"):
        ReconstructionStep(
            sequence=-1,
            event_id="evt_err",
            event_type="session_start",
            event_time=now,
            actor_id=None,
            subject_id=None,
            source_system=None,
            explanation="err",
            evidence_strength=1.0,
        )

    # Invalid evidence strength
    with pytest.raises(ValueError, match="evidence_strength must be between 0 and 1"):
        ReconstructionStep(
            sequence=1,
            event_id="evt_err",
            event_type="session_start",
            event_time=now,
            actor_id=None,
            subject_id=None,
            source_system=None,
            explanation="err",
            evidence_strength=1.5,
        )


def test_state_transitions_detection():
    now = datetime.now(timezone.utc)
    # 1. Direct identify_transition
    t_mat = identify_transition("normal", "beneficiary_changed", "evt_b1")
    assert t_mat.material_change is True
    assert "beneficiary_changed" in t_mat.explanation

    t_routine = identify_transition("active", "active", "evt_r1")
    assert t_routine.material_change is False

    # 2. Sequential extraction from events
    evts = [
        IntelligenceEvent(
            installation_id="inst_1",
            event_id="e1",
            event_type="customer_record_access",
            event_time=now,
            actor="emp_1",
            subject="acc_100",
            source_system="core_banking",
        ),
        IntelligenceEvent(
            installation_id="inst_1",
            event_id="e2",
            event_type="beneficiary_change",
            event_time=now + timedelta(minutes=2),
            actor="emp_1",
            subject="acc_100",
            source_system="core_banking",
        ),
        IntelligenceEvent(
            installation_id="inst_1",
            event_id="e3",
            event_type="high_value_transfer",
            event_time=now + timedelta(minutes=5),
            actor="emp_1",
            subject="acc_100",
            source_system="payment_switch",
            attributes={"amount": 1200000.0},
        ),
    ]

    transitions = extract_transitions_from_events(evts)
    assert len(transitions) >= 2
    assert any(t.new_state == "beneficiary_changed" for t in transitions)
    assert any(t.new_state == "high_value_transfer" for t in transitions)


def test_change_vector_computation():
    cv = build_change_vector(
        subject_id="emp_42",
        observed_attributes={
            "device": {"changed": True, "unusual": True},
            "ip_address": "new_external_ip",
            "working_hours": "unusual_hours",
            "transaction_value": "normal",
        },
    )
    assert "device" in cv.changed_dimensions
    assert "ip_address" in cv.changed_dimensions
    assert "working_hours" in cv.unusual_dimensions
    assert 0.0 <= cv.completeness <= 1.0
    assert "operational change" in cv.explanation.lower()


def test_attack_path_graph_construction():
    inst = "inst_1"
    rels = [
        Relationship(
            installation_id=inst,
            source=EntityRef(installation_id=inst, entity_type=EntityType.EMPLOYEE, entity_id="emp_01"),
            target=EntityRef(installation_id=inst, entity_type=EntityType.SESSION, entity_id="sess_01"),
            relationship_type="authenticated",
            confidence=1.0,
            source_system="iam",
        ),
        Relationship(
            installation_id=inst,
            source=EntityRef(installation_id=inst, entity_type=EntityType.SESSION, entity_id="sess_01"),
            target=EntityRef(installation_id=inst, entity_type=EntityType.CUSTOMER, entity_id="cif_99"),
            relationship_type="accessed",
            confidence=0.9,
            source_system="core_banking",
        ),
    ]

    path = build_attack_path_from_relationships("path_01", rels)
    assert len(path.nodes) == 3
    assert len(path.edges) == 2
    assert path.edges[0].relationship == "authenticated"
    assert path.edges[1].relationship == "accessed"
    assert path.confidence == 0.95


def test_evidence_contradictions_detection():
    now = datetime.now(timezone.utc)
    evts = [
        IntelligenceEvent(
            installation_id="inst_1",
            event_id="e_iam",
            event_type="session_start",
            event_time=now,
            actor="emp_concurrent",
            source_system="iam",
            attributes={"ip_address": "192.168.1.50", "branch_code": "BR-NAIROBI-01"},
        ),
        IntelligenceEvent(
            installation_id="inst_1",
            event_id="e_siem",
            event_type="terminal_login",
            event_time=now + timedelta(seconds=15),
            actor="emp_concurrent",
            source_system="siem",
            attributes={"ip_address": "10.45.2.100", "branch_code": "BR-MOMBASA-02"},
        ),
    ]

    contradictions = detect_evidence_contradictions(evts)
    assert len(contradictions) >= 1
    # IP conflict or branch conflict surfaced
    fields = [c.field for c in contradictions]
    assert "ip_address" in fields or "branch_location" in fields
    assert any(c.severity == ContradictionSeverity.HIGH for c in contradictions)
    assert all(c.resolution_required for c in contradictions)


def test_evidence_completeness_and_debt():
    # Only Core Banking and IAM present; CRM, SIEM, and Switch missing
    available = {"core_banking", "iam"}
    comp = calculate_evidence_completeness(available)
    assert comp.total_requirements == 5  # default required: iam, core_banking, payment_switch, crm, siem
    assert comp.satisfied_requirements == 2
    assert comp.percentage == 40.0
    assert "crm" in comp.evidence_debt
    assert "siem" in comp.evidence_debt
    assert "payment_switch" in comp.evidence_debt


def test_deterministic_reconstruction_reproducibility():
    """Deterministic Replay: Reconstructing the exact same events twice

    must yield identical sequences, steps, and hashes.
    """
    now = datetime.now(timezone.utc)
    evts = [
        IntelligenceEvent(
            installation_id="inst_det",
            event_id="evt_02",
            event_type="beneficiary_change",
            event_time=now + timedelta(minutes=5),
            actor="emp_det",
            source_system="core_banking",
        ),
        IntelligenceEvent(
            installation_id="inst_det",
            event_id="evt_01",
            event_type="session_start",
            event_time=now,
            actor="emp_det",
            source_system="iam",
        ),
    ]

    recon1 = reconstruct(
        reconstruction_id="rec_1",
        installation_id="inst_det",
        title="Test Incident",
        events=evts,
    )
    recon2 = reconstruct(
        reconstruction_id="rec_1",
        installation_id="inst_det",
        title="Test Incident",
        events=evts,
    )

    # Sequence 0 must be evt_01 (earlier timestamp) despite passed order
    assert recon1.steps[0].event_id == "evt_01"
    assert recon1.steps[1].event_id == "evt_02"
    assert [s.event_id for s in recon1.steps] == [s.event_id for s in recon2.steps]
    assert recon1.start_time == recon2.start_time
    assert recon1.end_time == recon2.end_time


def test_competing_scenarios_generation():
    now = datetime.now(timezone.utc)
    evts = [
        IntelligenceEvent(
            installation_id="inst_1",
            event_id="e1",
            event_type="beneficiary_change",
            event_time=now,
            actor="emp_target",
            source_system="core_banking",
        ),
        IntelligenceEvent(
            installation_id="inst_1",
            event_id="e2",
            event_type="transfer_initiated",
            event_time=now + timedelta(minutes=2),
            actor="emp_target",
            source_system="payment_switch",
        ),
    ]

    scenarios = generate_competing_scenarios(evts)
    assert len(scenarios) == 4
    # Check all standard institutional scenarios exist
    ids = [s.scenario_id for s in scenarios]
    assert "scenario_legitimate_service" in ids
    assert "scenario_insider_misuse" in ids
    assert "scenario_compromised_credentials" in ids
    assert "scenario_system_error" in ids

    # Sum of relative support is normalized to ~1.0
    total_support = sum(s.relative_support for s in scenarios)
    assert 0.95 <= total_support <= 1.05
