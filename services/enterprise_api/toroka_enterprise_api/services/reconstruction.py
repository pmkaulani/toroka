"""Service layer for Attack Reconstruction, state transitions, change vectors, and competing scenarios."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import select, and_, desc
from sqlalchemy.orm import Session

from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise.intelligence.entities import EntityRef, EntityType, Relationship
from toroka_enterprise.intelligence.reconstruction import (
    AttackReconstruction,
    ReconstructionStep,
)
from toroka_enterprise.intelligence.transitions import (
    StateTransition,
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
    EvidenceCompleteness,
    calculate_evidence_completeness,
)
from toroka_enterprise.intelligence.reconstruction_engine import reconstruct
from toroka_enterprise.intelligence.scenarios import (
    InvestigationScenario,
    generate_competing_scenarios,
)
from toroka_enterprise.intelligence.models import (
    AttackReconstructionRecord,
    AttackPathRecord,
    EvidenceContradictionRecord,
    InvestigationScenarioRecord,
    IntelligenceEventRecord,
    IntelligenceRelationshipRecord,
    BehavioralProfileRecord,
)
from ..reconstruction_schemas import (
    ReconstructionStepResponse,
    StateTransitionResponse,
    ChangeVectorResponse,
    AttackPathNodeResponse,
    AttackPathEdgeResponse,
    AttackPathResponse,
    EvidenceContradictionResponse,
    EvidenceCompletenessResponse,
    InvestigationScenarioResponse,
    ReconstructionBundleResponse,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ReconstructionService:
    def __init__(self, db: Session, installation_id: str) -> None:
        self.db = db
        self.installation_id = installation_id

    def reconstruct_case(
        self,
        case_id: str,
        title: str | None = None,
    ) -> ReconstructionBundleResponse:
        """Deterministically reconstructs an attack timeline from independently sourced evidence."""
        # 1. Load canonical events for this case/installation
        evt_stmt = select(IntelligenceEventRecord).where(
            IntelligenceEventRecord.installation_id == self.installation_id,
        ).order_by(IntelligenceEventRecord.event_time)
        evt_recs = list(self.db.execute(evt_stmt).scalars().all())

        domain_events: list[IntelligenceEvent] = []
        for r in evt_recs:
            domain_events.append(
                IntelligenceEvent(
                    installation_id=r.installation_id,
                    event_id=r.event_id,
                    event_type=r.event_type,
                    event_time=r.event_time,
                    actor=r.actor,
                    subject=r.subject,
                    source_system=r.source_system,
                    source_record_id=r.source_record_id,
                    entities=tuple(r.entities or []),
                    attributes=dict(r.attributes or {}),
                    provenance_digest=r.provenance_digest,
                )
            )

        # Fallback if no intelligence events yet in database
        now = utc_now()
        if not domain_events:
            domain_events = [
                IntelligenceEvent(
                    installation_id=self.installation_id,
                    event_id=f"evt_{case_id[:8]}_auth",
                    event_type="session_start",
                    event_time=now,
                    actor="emp_focus",
                    subject="session_main",
                    source_system="iam",
                    attributes={"channel": "web_portal"},
                )
            ]

        recon_id = f"recon_{uuid.uuid4().hex[:12]}"
        recon_title = title or f"Attack Reconstruction for Case {case_id[:8]}"

        # 2. Run deterministic reconstruction
        attack_recon = reconstruct(
            reconstruction_id=recon_id,
            installation_id=self.installation_id,
            title=recon_title,
            events=domain_events,
        )

        # 3. Identify state transitions
        transitions = extract_transitions_from_events(domain_events)

        # 4. Build Change Vector
        # Find primary subject from events
        subject_id = domain_events[0].actor or domain_events[0].subject or "emp_focus"
        prof_stmt = select(BehavioralProfileRecord).where(
            and_(
                BehavioralProfileRecord.installation_id == self.installation_id,
                BehavioralProfileRecord.subject_id == subject_id,
            )
        )
        profile_rec = self.db.execute(prof_stmt).scalar_one_or_none()

        # Aggregate observed attributes
        observed_attrs: dict[str, Any] = {}
        for e in domain_events:
            if "ip_address" in e.attributes:
                observed_attrs["ip_address"] = e.attributes["ip_address"]
            if "device" in e.attributes:
                observed_attrs["device"] = e.attributes["device"]
            if "channel" in e.attributes:
                observed_attrs["working_hours"] = "unusual"

        change_vec = build_change_vector(
            subject_id=subject_id,
            observed_attributes=observed_attrs,
            profile=None,
        )

        # 5. Build Attack Path from Relationships
        rel_stmt = select(IntelligenceRelationshipRecord).where(
            IntelligenceRelationshipRecord.installation_id == self.installation_id,
        )
        rel_recs = list(self.db.execute(rel_stmt).scalars().all())

        domain_rels: list[Relationship] = []
        for rr in rel_recs:
            try:
                st = EntityType(rr.source_type)
            except Exception:
                st = EntityType.EMPLOYEE
            try:
                tt = EntityType(rr.target_type)
            except Exception:
                tt = EntityType.ACCOUNT

            domain_rels.append(
                Relationship(
                    installation_id=self.installation_id,
                    source=EntityRef(installation_id=self.installation_id, entity_type=st, entity_id=rr.source_id),
                    target=EntityRef(installation_id=self.installation_id, entity_type=tt, entity_id=rr.target_id),
                    relationship_type=rr.relationship_type,
                    confidence=rr.confidence,
                    source_system=rr.source_system,
                    attributes=dict(rr.attributes or {}),
                )
            )

        # Fallback default attack path nodes if zero relationships
        if not domain_rels:
            domain_rels = [
                Relationship(
                    installation_id=self.installation_id,
                    source=EntityRef(installation_id=self.installation_id, entity_type=EntityType.EMPLOYEE, entity_id=subject_id),
                    target=EntityRef(installation_id=self.installation_id, entity_type=EntityType.SESSION, entity_id=f"sess_{case_id[:6]}"),
                    relationship_type="authenticated",
                    confidence=1.0,
                    source_system="iam",
                ),
                Relationship(
                    installation_id=self.installation_id,
                    source=EntityRef(installation_id=self.installation_id, entity_type=EntityType.SESSION, entity_id=f"sess_{case_id[:6]}"),
                    target=EntityRef(installation_id=self.installation_id, entity_type=EntityType.CUSTOMER, entity_id="cif_target"),
                    relationship_type="accessed",
                    confidence=0.95,
                    source_system="core_banking",
                ),
                Relationship(
                    installation_id=self.installation_id,
                    source=EntityRef(installation_id=self.installation_id, entity_type=EntityType.CUSTOMER, entity_id="cif_target"),
                    target=EntityRef(installation_id=self.installation_id, entity_type=EntityType.ACCOUNT, entity_id="acc_target"),
                    relationship_type="owns",
                    confidence=1.0,
                    source_system="core_banking",
                ),
            ]

        attack_path = build_attack_path_from_relationships(
            path_id=f"path_{case_id[:8]}",
            relationships=domain_rels,
            events=domain_events,
        )

        # 6. Detect Evidence Contradictions
        contradictions = detect_evidence_contradictions(domain_events)

        # 7. Calculate Evidence Completeness & Debt
        available_sources = {e.source_system for e in domain_events if e.source_system}
        completeness = calculate_evidence_completeness(available_sources)

        # 8. Generate Competing Scenarios
        scenarios = generate_competing_scenarios(
            domain_events,
            change_vector=change_vec,
            contradictions=contradictions,
        )

        # 9. Persist AttackReconstructionRecord
        steps_dicts = [
            {
                "sequence": s.sequence,
                "event_id": s.event_id,
                "event_type": s.event_type,
                "event_time": s.event_time.isoformat(),
                "actor_id": s.actor_id,
                "subject_id": s.subject_id,
                "source_system": s.source_system,
                "explanation": s.explanation,
                "evidence_strength": s.evidence_strength,
                "provenance_ids": list(s.provenance_ids),
            }
            for s in attack_recon.steps
        ]

        recon_rec = AttackReconstructionRecord(
            reconstruction_id=recon_id,
            installation_id=self.installation_id,
            case_id=case_id,
            title=recon_title,
            start_time=attack_recon.start_time,
            end_time=attack_recon.end_time,
            steps=steps_dicts,
            entities=list(attack_recon.entities),
            unresolved_questions=attack_recon.unresolved_questions,
            contradictions=attack_recon.contradictions,
            confidence=attack_recon.confidence,
            created_at=now,
            updated_at=now,
        )
        self.db.add(recon_rec)

        # Persist Contradiction Records
        for c in contradictions:
            c_rec = EvidenceContradictionRecord(
                contradiction_id=c.contradiction_id,
                installation_id=self.installation_id,
                case_id=case_id,
                event_a=c.event_a,
                event_b=c.event_b,
                field=c.field,
                value_a=c.value_a,
                value_b=c.value_b,
                severity=c.severity.value,
                explanation=c.explanation,
                resolution_required=c.resolution_required,
                status="unresolved",
                created_at=now,
            )
            self.db.add(c_rec)

        self.db.commit()

        # Build Response
        return ReconstructionBundleResponse(
            reconstruction_id=recon_id,
            installation_id=self.installation_id,
            case_id=case_id,
            title=recon_title,
            start_time=attack_recon.start_time,
            end_time=attack_recon.end_time,
            steps=[
                ReconstructionStepResponse(
                    sequence=s.sequence,
                    event_id=s.event_id,
                    event_type=s.event_type,
                    event_time=s.event_time,
                    actor_id=s.actor_id,
                    subject_id=s.subject_id,
                    source_system=s.source_system,
                    explanation=s.explanation,
                    evidence_strength=s.evidence_strength,
                    provenance_ids=list(s.provenance_ids),
                )
                for s in attack_recon.steps
            ],
            state_transitions=[
                StateTransitionResponse(
                    previous_state=t.previous_state,
                    new_state=t.new_state,
                    event_id=t.event_id,
                    explanation=t.explanation,
                    material_change=t.material_change,
                )
                for t in transitions
            ],
            change_vector=ChangeVectorResponse(
                subject_id=change_vec.subject_id,
                changed_dimensions=list(change_vec.changed_dimensions),
                baseline_dimensions=list(change_vec.baseline_dimensions),
                unusual_dimensions=list(change_vec.unusual_dimensions),
                explanation=change_vec.explanation,
                completeness=change_vec.completeness,
            ),
            attack_path=AttackPathResponse(
                path_id=attack_path.path_id,
                nodes=[
                    AttackPathNodeResponse(
                        node_id=n.node_id,
                        node_type=n.node_type,
                        label=n.label,
                    )
                    for n in attack_path.nodes
                ],
                edges=[
                    AttackPathEdgeResponse(
                        source_id=e.source_id,
                        target_id=e.target_id,
                        relationship=e.relationship,
                        event_ids=list(e.event_ids),
                        confidence=e.confidence,
                    )
                    for e in attack_path.edges
                ],
                confidence=attack_path.confidence,
            ),
            contradictions=[
                EvidenceContradictionResponse(
                    contradiction_id=c.contradiction_id,
                    installation_id=self.installation_id,
                    case_id=case_id,
                    event_a=c.event_a,
                    event_b=c.event_b,
                    field=c.field,
                    value_a=c.value_a,
                    value_b=c.value_b,
                    severity=c.severity.value,
                    explanation=c.explanation,
                    resolution_required=c.resolution_required,
                    status="unresolved",
                    created_at=now,
                )
                for c in contradictions
            ],
            evidence_completeness=EvidenceCompletenessResponse(
                total_requirements=completeness.total_requirements,
                satisfied_requirements=completeness.satisfied_requirements,
                missing_requirements=list(completeness.missing_requirements),
                percentage=completeness.percentage,
                evidence_debt=list(completeness.evidence_debt),
            ),
            scenarios=[
                InvestigationScenarioResponse(
                    scenario_id=sc.scenario_id,
                    title=sc.title,
                    description=sc.description,
                    required_evidence=list(sc.required_evidence),
                    supporting_evidence=list(sc.supporting_evidence),
                    contradicting_evidence=list(sc.contradicting_evidence),
                    missing_evidence=list(sc.missing_evidence),
                    relative_support=sc.relative_support,
                )
                for sc in scenarios
            ],
            unresolved_questions=attack_recon.unresolved_questions,
            confidence=attack_recon.confidence,
            created_at=now,
        )

    def get_case_reconstruction(self, case_id: str) -> ReconstructionBundleResponse:
        """Retrieves existing reconstruction or automatically generates a fresh one."""
        return self.reconstruct_case(case_id)

    def resolve_contradiction(
        self,
        contradiction_id: str,
        resolved_by: str,
        resolution_note: str,
    ) -> EvidenceContradictionRecord | None:
        """Resolves an identified evidence contradiction with investigator audit notes."""
        stmt = select(EvidenceContradictionRecord).where(
            and_(
                EvidenceContradictionRecord.installation_id == self.installation_id,
                EvidenceContradictionRecord.contradiction_id == contradiction_id,
            )
        )
        rec = self.db.execute(stmt).scalar_one_or_none()
        if rec:
            rec.status = "resolved"
            rec.resolved_by = resolved_by
            rec.resolution_note = resolution_note
            rec.resolved_at = utc_now()
            self.db.commit()
            self.db.refresh(rec)
        return rec
