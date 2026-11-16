"""Service layer for Attack Reconstruction, state transitions, change vectors, and competing scenarios."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from fastapi import HTTPException
from sqlalchemy import select, and_, desc, or_
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
from toroka_enterprise.intelligence.baselines import BaselineDimension
from toroka_enterprise.intelligence.statistics import BaselineStatistics
from toroka_enterprise.intelligence.profiles import BehavioralProfile
from toroka_enterprise.intelligence.models import (
    AttackReconstructionRecord,
    AttackPathRecord,
    EvidenceContradictionRecord,
    InvestigationScenarioRecord,
    IntelligenceEventRecord,
    IntelligenceRelationshipRecord,
    BehavioralProfileRecord,
)
from ..persistence.models import EnterpriseCase
from ..persistence.audit import append_audit
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

    def _get_case_or_404(self, case_id: str) -> EnterpriseCase:
        stmt = select(EnterpriseCase).where(
            and_(
                EnterpriseCase.id == case_id,
                EnterpriseCase.installation_id == self.installation_id,
            )
        )
        case = self.db.execute(stmt).scalar_one_or_none()
        if not case:
            raise HTTPException(
                status_code=404,
                detail=f"Case '{case_id}' not found in installation '{self.installation_id}'",
            )
        return case

    def _extract_case_entities(self, case: EnterpriseCase) -> set[str]:
        entities: set[str] = set()
        if case.focus and case.focus.strip():
            entities.add(case.focus.strip())

        snapshot = case.snapshot or {}
        for key in ("staff_ref", "customer_ref", "account_ref", "focus", "subject_id", "actor_id"):
            val = snapshot.get(key)
            if val and isinstance(val, str) and val.strip():
                entities.add(val.strip())

        raw_entities = snapshot.get("entities")
        if isinstance(raw_entities, (list, tuple, set)):
            for ent in raw_entities:
                if ent and isinstance(ent, str) and ent.strip():
                    entities.add(ent.strip())

        return entities

    def reconstruct_case(
        self,
        case_id: str,
        title: str | None = None,
        actor: str | None = None,
    ) -> ReconstructionBundleResponse:
        """Deterministically reconstructs an attack timeline from independently sourced evidence scoped strictly to the case."""
        # 1. Validate case and derive target entities
        case = self._get_case_or_404(case_id)
        case_entities = self._extract_case_entities(case)

        now = utc_now()
        recon_id = f"recon_{uuid.uuid4().hex[:12]}"
        recon_title = title or f"Attack Reconstruction for Case {case_id[:8]}"

        # 2. Load and filter canonical events strictly belonging to this case's entities
        evt_stmt = select(IntelligenceEventRecord).where(
            IntelligenceEventRecord.installation_id == self.installation_id,
        ).order_by(IntelligenceEventRecord.event_time, IntelligenceEventRecord.event_id)
        all_recs = list(self.db.execute(evt_stmt).scalars().all())

        domain_events: list[IntelligenceEvent] = []
        for r in all_recs:
            matches_case = False
            if r.actor and r.actor in case_entities:
                matches_case = True
            elif r.subject and r.subject in case_entities:
                matches_case = True
            elif any(e in case_entities for e in (r.entities or [])):
                matches_case = True
            elif r.attributes and r.attributes.get("case_id") == case_id:
                matches_case = True

            if matches_case:
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

        # 3. Handle zero-evidence without fabricating fictitious records
        if not domain_events:
            completeness = calculate_evidence_completeness(set())
            change_vec = build_change_vector(
                subject_id=case.focus,
                observed_attributes={},
                profile=None,
            )
            empty_path = AttackPath(path_id=f"path_{case_id[:8]}", nodes=[], edges=[], confidence=0.0)

            # Persist zero-evidence reconstruction record
            recon_rec = AttackReconstructionRecord(
                reconstruction_id=recon_id,
                installation_id=self.installation_id,
                case_id=case_id,
                title=recon_title,
                start_time=now,
                end_time=now,
                steps=[],
                entities=list(case_entities),
                unresolved_questions=[f"No verified telemetry found for case focus '{case.focus}'."],
                contradictions=[],
                confidence=0.0,
                created_at=now,
                updated_at=now,
            )
            self.db.add(recon_rec)

            path_rec = AttackPathRecord(
                path_id=empty_path.path_id,
                installation_id=self.installation_id,
                reconstruction_id=recon_id,
                case_id=case_id,
                nodes=[],
                edges=[],
                confidence=0.0,
                created_at=now,
            )
            self.db.add(path_rec)

            self.db.commit()

            append_audit(
                self.db,
                installation_id=self.installation_id,
                actor_subject=actor or "system",
                actor_role="investigator",
                action="RECONSTRUCTION_GENERATED",
                target_type="case",
                target_id=case_id,
                safe_metadata={
                    "case_id": case_id,
                    "reconstruction_id": recon_id,
                    "installation_id": self.installation_id,
                },
            )

            return ReconstructionBundleResponse(
                reconstruction_id=recon_id,
                installation_id=self.installation_id,
                case_id=case_id,
                title=recon_title,
                start_time=now,
                end_time=now,
                steps=[],
                state_transitions=[],
                change_vector=ChangeVectorResponse(
                    subject_id=case.focus,
                    changed_dimensions=[],
                    baseline_dimensions=[],
                    unusual_dimensions=[],
                    explanation=change_vec.explanation,
                    completeness=change_vec.completeness,
                ),
                attack_path=AttackPathResponse(
                    path_id=empty_path.path_id,
                    nodes=[],
                    edges=[],
                    confidence=0.0,
                ),
                contradictions=[],
                evidence_completeness=EvidenceCompletenessResponse(
                    total_requirements=completeness.total_requirements,
                    satisfied_requirements=0,
                    missing_requirements=list(completeness.missing_requirements),
                    percentage=0.0,
                    evidence_debt=list(completeness.evidence_debt),
                ),
                scenarios=[],
                unresolved_questions=list(recon_rec.unresolved_questions),
                confidence=0.0,
                created_at=now,
            )

        # 4. Deterministic chronological reconstruction from real evidence
        attack_recon = reconstruct(
            reconstruction_id=recon_id,
            installation_id=self.installation_id,
            title=recon_title,
            events=domain_events,
        )

        # 5. Extract state transitions
        transitions = extract_transitions_from_events(domain_events)

        # 6. Build Change Vector with actual stored baseline profile
        primary_subject = domain_events[0].actor or domain_events[0].subject or case.focus
        prof_stmt = select(BehavioralProfileRecord).where(
            and_(
                BehavioralProfileRecord.installation_id == self.installation_id,
                BehavioralProfileRecord.subject_id == primary_subject,
            )
        )
        profile_rec = self.db.execute(prof_stmt).scalar_one_or_none()

        domain_profile: BehavioralProfile | None = None
        if profile_rec:
            domain_profile = BehavioralProfile(
                installation_id=profile_rec.installation_id,
                subject_id=profile_rec.subject_id,
                subject_type=profile_rec.subject_type,
                observation_start=profile_rec.observation_start,
                observation_end=profile_rec.observation_end,
                sample_count=profile_rec.sample_count,
                minimum_required_samples=20,
            )
            for d_name, d_stats in (profile_rec.dimensions or {}).items():
                try:
                    dim_enum = BaselineDimension(d_name)
                except Exception:
                    continue
                stats_obj = BaselineStatistics(
                    count=d_stats.get("count", 0),
                    mean=d_stats.get("mean", 0.0),
                    standard_deviation=d_stats.get("standard_deviation", 0.0),
                    minimum=d_stats.get("minimum", 0.0),
                    maximum=d_stats.get("maximum", 0.0),
                    median=d_stats.get("median"),
                )
                domain_profile.add_dimension(dim_enum, stats_obj)

        observed_attrs: dict[str, Any] = {}
        for e in domain_events:
            if "ip_address" in e.attributes:
                observed_attrs["ip_address"] = e.attributes["ip_address"]
            if "device" in e.attributes:
                observed_attrs["device"] = e.attributes["device"]
            if "working_hours" in e.attributes:
                observed_attrs["working_hours"] = e.attributes["working_hours"]
            elif e.event_time:
                hr = e.event_time.hour
                if hr < 6 or hr >= 19:
                    observed_attrs["working_hours"] = "unusual_hours"
            if "amount" in e.attributes or "transaction_value" in e.attributes:
                observed_attrs["transaction_value"] = e.attributes.get("amount") or e.attributes.get("transaction_value")
            if "branch_code" in e.attributes:
                observed_attrs["branch_location"] = e.attributes["branch_code"]

        change_vec = build_change_vector(
            subject_id=primary_subject,
            observed_attributes=observed_attrs,
            profile=domain_profile,
        )

        # 7. Build Attack Path from case-scoped entity relationships
        rel_stmt = select(IntelligenceRelationshipRecord).where(
            IntelligenceRelationshipRecord.installation_id == self.installation_id,
        )
        all_rels = list(self.db.execute(rel_stmt).scalars().all())

        domain_rels: list[Relationship] = []
        for rr in all_rels:
            if rr.source_id in case_entities or rr.target_id in case_entities:
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

        attack_path = build_attack_path_from_relationships(
            path_id=f"path_{case_id[:8]}",
            relationships=domain_rels,
            events=domain_events,
        )

        # 8. Detect Contradictions with stable fingerprints and deduplicate
        contradictions = detect_evidence_contradictions(domain_events)

        existing_c_stmt = select(EvidenceContradictionRecord).where(
            and_(
                EvidenceContradictionRecord.installation_id == self.installation_id,
                EvidenceContradictionRecord.case_id == case_id,
            )
        )
        existing_c_records = {c.contradiction_id: c for c in self.db.execute(existing_c_stmt).scalars().all()}

        active_contradictions: list[EvidenceContradictionRecord] = []
        for c in contradictions:
            if c.contradiction_id in existing_c_records:
                active_contradictions.append(existing_c_records[c.contradiction_id])
            else:
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
                active_contradictions.append(c_rec)

        # 9. Calculate Evidence Completeness & Debt
        available_sources = {e.source_system for e in domain_events if e.source_system}
        completeness = calculate_evidence_completeness(available_sources)

        # 10. Generate Competing Scenarios (ACH)
        scenarios = generate_competing_scenarios(
            domain_events,
            change_vector=change_vec,
            contradictions=contradictions,
        )

        # 11. Persist AttackReconstructionRecord
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

        # Persist versioned AttackPathRecord
        nodes_dicts = [{"node_id": n.node_id, "node_type": n.node_type, "label": n.label} for n in attack_path.nodes]
        edges_dicts = [
            {
                "source_id": e.source_id,
                "target_id": e.target_id,
                "relationship": e.relationship,
                "event_ids": list(e.event_ids),
                "confidence": e.confidence,
            }
            for e in attack_path.edges
        ]
        path_rec = AttackPathRecord(
            path_id=attack_path.path_id,
            installation_id=self.installation_id,
            reconstruction_id=recon_id,
            case_id=case_id,
            nodes=nodes_dicts,
            edges=edges_dicts,
            confidence=attack_path.confidence,
            created_at=now,
        )
        self.db.add(path_rec)

        # Persist versioned InvestigationScenarioRecords (replacing or inserting for this case)
        for sc in scenarios:
            sc_rec = InvestigationScenarioRecord(
                scenario_id=sc.scenario_id,
                installation_id=self.installation_id,
                case_id=case_id,
                title=sc.title,
                description=sc.description,
                required_evidence=list(sc.required_evidence),
                supporting_evidence=list(sc.supporting_evidence),
                contradicting_evidence=list(sc.contradicting_evidence),
                missing_evidence=list(sc.missing_evidence),
                relative_support=sc.relative_support,
                created_at=now,
            )
            self.db.merge(sc_rec)

        self.db.commit()

        # Audit append
        append_audit(
            self.db,
            installation_id=self.installation_id,
            actor_subject=actor or "system",
            actor_role="investigator",
            action="RECONSTRUCTION_GENERATED",
            target_type="case",
            target_id=case_id,
            safe_metadata={
                "case_id": case_id,
                "reconstruction_id": recon_id,
                "installation_id": self.installation_id,
            },
        )

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
                    contradiction_id=cr.contradiction_id,
                    installation_id=self.installation_id,
                    case_id=case_id,
                    event_a=cr.event_a,
                    event_b=cr.event_b,
                    field=cr.field,
                    value_a=cr.value_a,
                    value_b=cr.value_b,
                    severity=cr.severity,
                    explanation=cr.explanation,
                    resolution_required=cr.resolution_required,
                    status=cr.status,
                    resolved_by=cr.resolved_by,
                    resolution_note=cr.resolution_note,
                    created_at=cr.created_at,
                    resolved_at=cr.resolved_at,
                )
                for cr in active_contradictions
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
        """Retrieves existing stored reconstruction bundle without performing mutating writes."""
        # 1. Validate case
        self._get_case_or_404(case_id)

        # 2. Query latest stored reconstruction record
        stmt = (
            select(AttackReconstructionRecord)
            .where(
                and_(
                    AttackReconstructionRecord.installation_id == self.installation_id,
                    AttackReconstructionRecord.case_id == case_id,
                )
            )
            .order_by(desc(AttackReconstructionRecord.created_at))
        )
        recon_rec = self.db.execute(stmt).scalars().first()

        if not recon_rec:
            raise HTTPException(
                status_code=404,
                detail=f"No attack reconstruction has been generated for case '{case_id}'. Call POST /cases/{case_id}/reconstruct first.",
            )

        # 3. Load associated attack path
        path_stmt = (
            select(AttackPathRecord)
            .where(
                and_(
                    AttackPathRecord.installation_id == self.installation_id,
                    AttackPathRecord.reconstruction_id == recon_rec.reconstruction_id,
                )
            )
            .order_by(desc(AttackPathRecord.created_at))
        )
        path_rec = self.db.execute(path_stmt).scalars().first()
        attack_path_resp = AttackPathResponse(
            path_id=path_rec.path_id if path_rec else f"path_{case_id[:8]}",
            nodes=[
                AttackPathNodeResponse(
                    node_id=n["node_id"],
                    node_type=n.get("node_type", "entity"),
                    label=n.get("label", n["node_id"]),
                )
                for n in (path_rec.nodes if path_rec else [])
            ],
            edges=[
                AttackPathEdgeResponse(
                    source_id=e["source_id"],
                    target_id=e["target_id"],
                    relationship=e.get("relationship", "associated"),
                    event_ids=list(e.get("event_ids", [])),
                    confidence=e.get("confidence", 1.0),
                )
                for e in (path_rec.edges if path_rec else [])
            ],
            confidence=path_rec.confidence if path_rec else 0.0,
        )

        # 4. Load contradictions for this case
        c_stmt = (
            select(EvidenceContradictionRecord)
            .where(
                and_(
                    EvidenceContradictionRecord.installation_id == self.installation_id,
                    EvidenceContradictionRecord.case_id == case_id,
                )
            )
            .order_by(EvidenceContradictionRecord.created_at)
        )
        c_recs = list(self.db.execute(c_stmt).scalars().all())

        # 5. Load stored scenarios for this case
        sc_stmt = (
            select(InvestigationScenarioRecord)
            .where(
                and_(
                    InvestigationScenarioRecord.installation_id == self.installation_id,
                    InvestigationScenarioRecord.case_id == case_id,
                )
            )
            .order_by(desc(InvestigationScenarioRecord.relative_support))
        )
        sc_recs = list(self.db.execute(sc_stmt).scalars().all())

        steps = [
            ReconstructionStepResponse(
                sequence=s.get("sequence", idx),
                event_id=s.get("event_id", f"evt_{idx}"),
                event_type=s.get("event_type", "unknown"),
                event_time=datetime.fromisoformat(s["event_time"]) if isinstance(s.get("event_time"), str) else (s.get("event_time") or recon_rec.start_time),
                actor_id=s.get("actor_id"),
                subject_id=s.get("subject_id"),
                source_system=s.get("source_system"),
                explanation=s.get("explanation", ""),
                evidence_strength=s.get("evidence_strength", 0.70),
                provenance_ids=list(s.get("provenance_ids", [])),
            )
            for idx, s in enumerate(recon_rec.steps or [])
        ]

        # Calculate completeness from steps sources
        sources = {s.source_system for s in steps if s.source_system}
        completeness = calculate_evidence_completeness(sources)

        return ReconstructionBundleResponse(
            reconstruction_id=recon_rec.reconstruction_id,
            installation_id=recon_rec.installation_id,
            case_id=recon_rec.case_id or case_id,
            title=recon_rec.title,
            start_time=recon_rec.start_time,
            end_time=recon_rec.end_time,
            steps=steps,
            state_transitions=[],
            change_vector=ChangeVectorResponse(
                subject_id=case_id,
                changed_dimensions=[],
                baseline_dimensions=[],
                unusual_dimensions=[],
                explanation="Historical change vector loaded from persisted investigation state.",
                completeness=completeness.percentage / 100.0,
            ),
            attack_path=attack_path_resp,
            contradictions=[
                EvidenceContradictionResponse(
                    contradiction_id=cr.contradiction_id,
                    installation_id=self.installation_id,
                    case_id=case_id,
                    event_a=cr.event_a,
                    event_b=cr.event_b,
                    field=cr.field,
                    value_a=cr.value_a,
                    value_b=cr.value_b,
                    severity=cr.severity,
                    explanation=cr.explanation,
                    resolution_required=cr.resolution_required,
                    status=cr.status,
                    resolved_by=cr.resolved_by,
                    resolution_note=cr.resolution_note,
                    created_at=cr.created_at,
                    resolved_at=cr.resolved_at,
                )
                for cr in c_recs
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
                    scenario_id=sr.scenario_id,
                    title=sr.title,
                    description=sr.description,
                    required_evidence=list(sr.required_evidence or []),
                    supporting_evidence=list(sr.supporting_evidence or []),
                    contradicting_evidence=list(sr.contradicting_evidence or []),
                    missing_evidence=list(sr.missing_evidence or []),
                    relative_support=sr.relative_support,
                )
                for sr in sc_recs
            ],
            unresolved_questions=list(recon_rec.unresolved_questions or []),
            confidence=recon_rec.confidence,
            created_at=recon_rec.created_at,
        )

    def resolve_contradiction(
        self,
        case_id: str,
        contradiction_id: str,
        resolved_by: str,
        resolution_note: str,
    ) -> EvidenceContradictionRecord | None:
        """Resolves an identified evidence contradiction strictly bound to the specific case and installation."""
        stmt = select(EvidenceContradictionRecord).where(
            and_(
                EvidenceContradictionRecord.installation_id == self.installation_id,
                EvidenceContradictionRecord.case_id == case_id,
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

            append_audit(
                self.db,
                installation_id=self.installation_id,
                actor_subject=resolved_by,
                actor_role="investigator",
                action="CONTRADICTION_RESOLVED",
                target_type="contradiction",
                target_id=contradiction_id,
                safe_metadata={
                    "case_id": case_id,
                    "contradiction_id": contradiction_id,
                    "reason": resolution_note[:100],
                    "installation_id": self.installation_id,
                },
            )

        return rec
