"""Operational service for Phase 10: Network Intelligence & Collaborative Fraud Graphs."""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from toroka_enterprise.intelligence.models import (
    EntityLinkCandidateRecord,
    EntityLinkReviewRecord,
    IntelligenceEventRecord,
    IntelligenceRelationshipRecord,
    NetworkAnalysisRunRecord,
    NetworkEdgeRecord,
    NetworkFindingEvidenceRecord,
    NetworkFindingRecord,
    NetworkNodeRecord,
    NetworkSnapshotRecord,
)
from toroka_enterprise.intelligence.network import (
    EntityLinkCandidate,
    EntityLinkStatus,
    EntityResolutionEngine,
    EvidenceBasis,
    EvidenceNetwork,
    EvidenceSubgraph,
    FindingEvidenceSubgraph,
    NetworkAnalysisResult,
    NetworkAnalysisService,
    NetworkEdge,
    NetworkNode,
    NetworkPatternFinding,
    TemporalNetworkManager,
    TransferObservation,
    expand_neighborhood,
    extract_finding_subgraph,
    find_shortest_path,
)
from ..network_schemas import (
    EntityLinkCandidateResponse,
    EntityLinkReviewResponse,
    EvidenceSubgraphResponse,
    FindingEvidenceSubgraphResponse,
    NeighborhoodExpandRequest,
    NetworkAnalysisRequest,
    NetworkAnalysisResponse,
    NetworkAnalysisRunResponse,
    NetworkEdgeResponse,
    NetworkNodeResponse,
    NetworkPatternFindingResponse,
    NetworkSnapshotResponse,
    ShortestPathRequest,
    ShortestPathResponse,
)
from ..persistence.audit import append_audit
from ..persistence.models import EnterpriseCase

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class NetworkService:
    """Manages graph construction, neighborhood expansion, motif mining, and entity link governance."""

    def __init__(self, session: Session, installation_id: str) -> None:
        self.session = session
        self.installation_id = installation_id

    # -------------------------------------------------------------------------
    # Graph Building & Synchronization
    # -------------------------------------------------------------------------

    def load_active_network(self, as_of: datetime | None = None) -> EvidenceNetwork:
        """Assemble current network graph from persisted nodes, edges, relationships, and events."""
        graph = EvidenceNetwork(self.installation_id)

        # 1. Load persisted nodes
        node_stmt = select(NetworkNodeRecord).where(
            NetworkNodeRecord.installation_id == self.installation_id
        )
        for nrec in self.session.execute(node_stmt).scalars():
            if as_of and nrec.first_seen and _ensure_utc(nrec.first_seen) > _ensure_utc(as_of):
                continue
            graph.add_node(
                NetworkNode(
                    installation_id=nrec.installation_id,
                    node_key=nrec.node_key,
                    entity_type=nrec.entity_type,
                    pseudonymous_label=nrec.pseudonymous_label,
                    attributes=dict(nrec.attributes or {}),
                    first_seen=nrec.first_seen,
                    last_seen=nrec.last_seen,
                )
            )

        # 2. Load persisted edges
        edge_stmt = select(NetworkEdgeRecord).where(
            NetworkEdgeRecord.installation_id == self.installation_id
        )
        for erec in self.session.execute(edge_stmt).scalars():
            if as_of and erec.first_seen and _ensure_utc(erec.first_seen) > _ensure_utc(as_of):
                continue
            if erec.source_key in graph.nodes and erec.target_key in graph.nodes:
                basis = EvidenceBasis(erec.evidence_basis) if erec.evidence_basis in EvidenceBasis._value2member_map_ else EvidenceBasis.DIRECT_OBSERVATION
                graph.add_edge(
                    NetworkEdge(
                        installation_id=erec.installation_id,
                        source_key=erec.source_key,
                        target_key=erec.target_key,
                        relationship_type=erec.relationship_type,
                        evidence_basis=basis,
                        event_ids=tuple(erec.event_ids or []),
                        source_record_ids=tuple(erec.source_record_ids or []),
                        source_systems=tuple(erec.source_systems or []),
                        first_seen=erec.first_seen,
                        last_seen=erec.last_seen,
                        confidence=erec.confidence,
                        directed=erec.directed,
                        attributes=dict(erec.attributes or {}),
                    )
                )

        # 3. If graph is sparse, materialize from intelligence events & relationships
        if len(graph.nodes) == 0:
            events_stmt = (
                select(IntelligenceEventRecord)
                .where(IntelligenceEventRecord.installation_id == self.installation_id)
                .order_by(IntelligenceEventRecord.event_time.asc())
            )
            raw_events = [
                {
                    "installation_id": ev.installation_id,
                    "event_id": ev.event_id,
                    "event_type": ev.event_type,
                    "event_time": ev.event_time,
                    "actor": ev.actor,
                    "subject": ev.subject,
                    "source_system": ev.source_system,
                    "source_record_id": ev.source_record_id,
                    "attributes": ev.attributes or {},
                }
                for ev in self.session.execute(events_stmt).scalars()
            ]

            rel_stmt = select(IntelligenceRelationshipRecord).where(
                IntelligenceRelationshipRecord.installation_id == self.installation_id
            )
            raw_rels = [
                {
                    "installation_id": r.installation_id,
                    "source": {"entity_type": r.source_type, "entity_id": r.source_id},
                    "target": {"entity_type": r.target_type, "entity_id": r.target_id},
                    "relationship_type": r.relationship_type,
                    "first_seen": r.first_seen,
                    "confidence": r.confidence,
                    "source_system": r.source_system,
                    "source_record_id": r.source_record_id,
                }
                for r in self.session.execute(rel_stmt).scalars()
            ]

            service = NetworkAnalysisService(self.installation_id)
            dyn_graph, _, candidates = service.build_network_from_events(raw_events, raw_rels, as_of=as_of)
            graph = dyn_graph

            # Persist newly extracted nodes & edges to avoid repeating
            for n in graph.nodes.values():
                n_rec = NetworkNodeRecord(
                    node_key=n.node_key,
                    installation_id=n.installation_id,
                    entity_type=n.entity_type,
                    pseudonymous_label=n.pseudonymous_label,
                    attributes=n.attributes,
                    first_seen=n.first_seen,
                    last_seen=n.last_seen,
                    created_at=_utc_now(),
                )
                self.session.merge(n_rec)

            for e in graph.edges:
                e_rec = NetworkEdgeRecord(
                    id=uuid.uuid4().hex,
                    installation_id=e.installation_id,
                    source_key=e.source_key,
                    target_key=e.target_key,
                    relationship_type=e.relationship_type,
                    evidence_basis=e.evidence_basis.value,
                    event_ids=list(e.event_ids),
                    source_record_ids=list(e.source_record_ids),
                    source_systems=list(e.source_systems),
                    confidence=e.confidence,
                    directed=e.directed,
                    first_seen=e.first_seen,
                    last_seen=e.last_seen,
                    attributes=e.attributes,
                    created_at=_utc_now(),
                )
                self.session.add(e_rec)

            for c in candidates:
                c_rec = EntityLinkCandidateRecord(
                    candidate_id=c.candidate_id,
                    installation_id=c.installation_id,
                    source_entity_key=c.source_entity_key,
                    target_entity_key=c.target_entity_key,
                    attribute_type=c.attribute_type,
                    attribute_value=c.attribute_value,
                    match_type=c.match_type.value,
                    status=c.status.value,
                    confidence=c.confidence,
                    supporting_evidence=list(c.supporting_evidence),
                    contradicting_evidence=list(c.contradicting_evidence),
                    source_systems=list(c.source_systems),
                    first_observed=c.first_observed,
                    last_observed=c.last_observed,
                    created_at=_utc_now(),
                )
                self.session.merge(c_rec)

            self.session.commit()

        return graph

    # -------------------------------------------------------------------------
    # Neighborhood Expansion & Traversal
    # -------------------------------------------------------------------------

    def expand(
        self,
        request: NeighborhoodExpandRequest,
        actor_subject: str,
        actor_role: str,
    ) -> EvidenceSubgraphResponse:
        as_of_dt = datetime.fromisoformat(request.as_of) if request.as_of else None
        graph = self.load_active_network(as_of=as_of_dt)

        # Check that seed nodes exist in the graph
        missing = [s for s in request.seed_nodes if s not in graph.nodes]
        if missing:
            # Create placeholder nodes for seeds if not found
            for s in missing:
                etype = s.split(":")[0] if ":" in s else "entity"
                p_node = NetworkNode(
                    installation_id=self.installation_id,
                    node_key=s,
                    entity_type=etype,
                    pseudonymous_label=s,
                    first_seen=_utc_now(),
                    last_seen=_utc_now(),
                )
                graph.add_node(p_node)

        subgraph = expand_neighborhood(
            graph,
            set(request.seed_nodes),
            max_depth=request.max_depth,
            max_nodes=request.max_nodes,
            max_edges=request.max_edges,
            minimum_confidence=request.minimum_confidence,
            include_shared_attributes=request.include_shared_attributes,
            direction=request.direction,
            as_of=as_of_dt,
        )

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="expand_network_neighborhood",
            target_type="network_subgraph",
            target_id=request.seed_nodes[0] if request.seed_nodes else None,
            safe_metadata={
                "count": len(subgraph.nodes),
                "max_depth": request.max_depth,
                "include_shared_attributes": request.include_shared_attributes,
            },
        )

        return self._to_subgraph_response(subgraph)

    def shortest_path(
        self,
        request: ShortestPathRequest,
        actor_subject: str,
        actor_role: str,
    ) -> ShortestPathResponse:
        graph = self.load_active_network()
        result = find_shortest_path(
            graph,
            request.source_key,
            request.target_key,
            max_depth=request.max_depth,
            minimum_confidence=request.minimum_confidence,
            include_shared_attributes=request.include_shared_attributes,
        )

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="find_shortest_path",
            target_type="network_path",
            target_id=f"{request.source_key}->{request.target_key}",
            safe_metadata={"node_key": request.source_key},
        )

        if not result:
            return ShortestPathResponse(
                source_key=request.source_key,
                target_key=request.target_key,
                found=False,
                path_length=0,
                nodes=[],
                edges=[],
            )

        nodes, edges = result
        return ShortestPathResponse(
            source_key=request.source_key,
            target_key=request.target_key,
            found=True,
            path_length=len(edges),
            nodes=[self._to_node_response(n) for n in nodes],
            edges=[self._to_edge_response(e) for e in edges],
        )

    # -------------------------------------------------------------------------
    # Network Analysis Orchestration
    # -------------------------------------------------------------------------

    def analyze(
        self,
        request: NetworkAnalysisRequest,
        actor_subject: str,
        actor_role: str,
    ) -> NetworkAnalysisResponse:
        as_of_dt = datetime.fromisoformat(request.as_of) if request.as_of else None

        # Fetch relevant raw events for this case / seeds
        ev_stmt = (
            select(IntelligenceEventRecord)
            .where(IntelligenceEventRecord.installation_id == self.installation_id)
            .order_by(IntelligenceEventRecord.event_time.asc())
        )
        raw_events = [
            {
                "installation_id": ev.installation_id,
                "event_id": ev.event_id,
                "event_type": ev.event_type,
                "event_time": ev.event_time,
                "actor": ev.actor,
                "subject": ev.subject,
                "source_system": ev.source_system,
                "source_record_id": ev.source_record_id,
                "attributes": ev.attributes or {},
            }
            for ev in self.session.execute(ev_stmt).scalars()
        ]

        analysis_svc = NetworkAnalysisService(self.installation_id)
        result = analysis_svc.analyze(
            seed_entities=request.seed_entities,
            events=raw_events,
            case_id=request.case_id,
            max_depth=request.max_depth,
            max_nodes=request.max_nodes,
            max_edges=request.max_edges,
            include_shared_attributes=request.include_shared_attributes,
            as_of=as_of_dt,
        )

        # Persist findings
        for f in result.findings:
            f_rec = NetworkFindingRecord(
                finding_id=f.pattern_id,
                installation_id=f.installation_id,
                case_id=request.case_id,
                pattern_type=f.pattern_type,
                anchor_entity=f.anchor_entity,
                related_entities=list(f.related_entities),
                event_ids=list(f.event_ids),
                start_time=f.start_time,
                end_time=f.end_time,
                detection_time=f.detection_time,
                explanation=f.explanation,
                evidence_limitations=list(f.evidence_limitations),
                alternative_legitimate_explanations=list(f.alternative_legitimate_explanations),
                supporting_source_systems=list(f.supporting_source_systems),
                transaction_ids=list(f.transaction_ids),
                monetary_total=str(f.monetary_total) if f.monetary_total is not None else None,
                currency=f.currency,
                confidence=f.confidence,
                pattern_version=f.pattern_version,
                created_at=_utc_now(),
            )
            self.session.merge(f_rec)

            # Persist minimal evidence subgraph
            subgraph_ext = extract_finding_subgraph(f, self.load_active_network())
            sub_rec = NetworkFindingEvidenceRecord(
                id=uuid.uuid4().hex,
                installation_id=self.installation_id,
                finding_id=f.pattern_id,
                subgraph_json=subgraph_ext.to_dict(),
                created_at=_utc_now(),
            )
            self.session.add(sub_rec)

        # Persist analysis run
        res_json = result.to_dict()
        res_digest = hashlib.sha256(json.dumps(res_json, sort_keys=True, default=str).encode()).hexdigest()
        run_rec = NetworkAnalysisRunRecord(
            run_id=result.analysis_id,
            installation_id=self.installation_id,
            case_id=request.case_id,
            executed_by=actor_subject,
            seed_entities=list(result.anchor_entities),
            findings_count=len(result.findings),
            nodes_count=result.subgraph.node_count,
            edges_count=result.subgraph.edge_count,
            truncated=result.subgraph.truncated,
            result_digest=res_digest,
            result_json=res_json,
            executed_at=_utc_now(),
        )
        self.session.add(run_rec)
        self.session.commit()

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="run_network_analysis",
            target_type="network_analysis_run",
            target_id=result.analysis_id,
            safe_metadata={
                "run_id": result.analysis_id,
                "case_id": request.case_id,
                "count": len(result.findings),
            },
        )

        return NetworkAnalysisResponse(
            analysis_id=result.analysis_id,
            installation_id=result.installation_id,
            case_id=result.case_id,
            anchor_entities=list(result.anchor_entities),
            subgraph=self._to_subgraph_response(result.subgraph),
            findings=[self._to_finding_response(f) for f in result.findings],
            entity_link_candidates=[self._to_candidate_response(c) for c in result.entity_link_candidates],
            source_coverage=result.source_coverage,
            source_systems=list(result.source_systems),
            alternative_explanations=list(result.alternative_explanations),
            missing_evidence=list(result.missing_evidence),
            institutional_pattern_matches=list(result.institutional_pattern_matches),
            executed_at=result.executed_at.isoformat(),
        )

    # -------------------------------------------------------------------------
    # Findings & Subgraphs
    # -------------------------------------------------------------------------

    def list_findings(self, case_id: str | None = None) -> list[NetworkPatternFindingResponse]:
        stmt = select(NetworkFindingRecord).where(
            NetworkFindingRecord.installation_id == self.installation_id
        )
        if case_id:
            stmt = stmt.where(NetworkFindingRecord.case_id == case_id)
        stmt = stmt.order_by(NetworkFindingRecord.detection_time.desc())

        records = self.session.execute(stmt).scalars().all()
        return [
            NetworkPatternFindingResponse(
                pattern_id=r.finding_id,
                installation_id=r.installation_id,
                pattern_type=r.pattern_type,
                anchor_entity=r.anchor_entity,
                related_entities=r.related_entities or [],
                event_ids=r.event_ids or [],
                start_time=r.start_time.isoformat(),
                end_time=r.end_time.isoformat(),
                detection_time=r.detection_time.isoformat(),
                explanation=r.explanation,
                evidence_limitations=r.evidence_limitations or [],
                alternative_legitimate_explanations=r.alternative_legitimate_explanations or [],
                supporting_source_systems=r.supporting_source_systems or [],
                transaction_ids=r.transaction_ids or [],
                monetary_total=r.monetary_total,
                currency=r.currency,
                confidence=r.confidence,
                pattern_version=r.pattern_version,
            )
            for r in records
        ]

    def get_finding_evidence(self, finding_id: str) -> FindingEvidenceSubgraphResponse:
        f_rec = self.session.execute(
            select(NetworkFindingRecord).where(
                NetworkFindingRecord.installation_id == self.installation_id,
                NetworkFindingRecord.finding_id == finding_id,
            )
        ).scalar_one_or_none()
        if not f_rec:
            raise HTTPException(status_code=404, detail="Finding not found")

        ev_rec = self.session.execute(
            select(NetworkFindingEvidenceRecord).where(
                NetworkFindingEvidenceRecord.installation_id == self.installation_id,
                NetworkFindingEvidenceRecord.finding_id == finding_id,
            )
        ).scalar_one_or_none()

        if ev_rec and ev_rec.subgraph_json:
            data = ev_rec.subgraph_json
            return FindingEvidenceSubgraphResponse(**data)

        # Fallback to computing on the fly
        graph = self.load_active_network()
        finding = NetworkPatternFinding(
            pattern_id=f_rec.finding_id,
            installation_id=f_rec.installation_id,
            pattern_type=f_rec.pattern_type,
            anchor_entity=f_rec.anchor_entity,
            related_entities=tuple(f_rec.related_entities or []),
            event_ids=tuple(f_rec.event_ids or []),
            start_time=f_rec.start_time,
            end_time=f_rec.end_time,
            detection_time=f_rec.detection_time,
            explanation=f_rec.explanation,
            evidence_limitations=tuple(f_rec.evidence_limitations or []),
            alternative_legitimate_explanations=tuple(f_rec.alternative_legitimate_explanations or []),
            supporting_source_systems=tuple(f_rec.supporting_source_systems or []),
            transaction_ids=tuple(f_rec.transaction_ids or []),
            monetary_total=Decimal(f_rec.monetary_total) if f_rec.monetary_total else None,
            currency=f_rec.currency,
            confidence=f_rec.confidence,
            pattern_version=f_rec.pattern_version,
        )
        subgraph = extract_finding_subgraph(finding, graph)
        return FindingEvidenceSubgraphResponse(**subgraph.to_dict())

    # -------------------------------------------------------------------------
    # Entity Resolution & Link Reviews
    # -------------------------------------------------------------------------

    def list_entity_link_candidates(self) -> list[EntityLinkCandidateResponse]:
        stmt = (
            select(EntityLinkCandidateRecord)
            .where(EntityLinkCandidateRecord.installation_id == self.installation_id)
            .order_by(EntityLinkCandidateRecord.confidence.desc())
        )
        return [
            EntityLinkCandidateResponse(
                candidate_id=r.candidate_id,
                installation_id=r.installation_id,
                source_entity_key=r.source_entity_key,
                target_entity_key=r.target_entity_key,
                attribute_type=r.attribute_type,
                attribute_value=r.attribute_value,
                match_type=r.match_type,
                status=r.status,
                confidence=r.confidence,
                supporting_evidence=r.supporting_evidence or [],
                contradicting_evidence=r.contradicting_evidence or [],
                source_systems=r.source_systems or [],
                first_observed=r.first_observed.isoformat(),
                last_observed=r.last_observed.isoformat(),
                reviewed_by=r.reviewed_by,
                reviewed_at=r.reviewed_at.isoformat() if r.reviewed_at else None,
                review_rationale=r.review_rationale,
            )
            for r in self.session.execute(stmt).scalars()
        ]

    def review_entity_link(
        self,
        candidate_id: str,
        decision_str: str,
        rationale: str,
        actor_subject: str,
        actor_role: str,
    ) -> EntityLinkReviewResponse:
        cand_rec = self.session.execute(
            select(EntityLinkCandidateRecord).where(
                EntityLinkCandidateRecord.installation_id == self.installation_id,
                EntityLinkCandidateRecord.candidate_id == candidate_id,
            )
        ).scalar_one_or_none()
        if not cand_rec:
            raise HTTPException(status_code=404, detail="Entity link candidate not found")

        try:
            decision = EntityLinkStatus(decision_str)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid decision '{decision_str}'. Must be one of {[s.value for s in EntityLinkStatus]}",
            )

        prev_status = cand_rec.status
        cand_rec.status = decision.value
        cand_rec.reviewed_by = actor_subject
        cand_rec.reviewed_at = _utc_now()
        cand_rec.review_rationale = rationale

        if decision == EntityLinkStatus.SAME_ENTITY_CONFIRMED:
            cand_rec.confidence = 1.0
        elif decision == EntityLinkStatus.RELATIONSHIP_DISPROVEN:
            cand_rec.confidence = 0.0

        rev_id = uuid.uuid4().hex
        rev_rec = EntityLinkReviewRecord(
            review_id=rev_id,
            installation_id=self.installation_id,
            candidate_id=candidate_id,
            reviewer_subject=actor_subject,
            decision=decision.value,
            rationale=rationale,
            previous_status=prev_status,
            new_status=decision.value,
            reviewed_at=_utc_now(),
        )
        self.session.add(rev_rec)
        self.session.commit()

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="review_entity_link",
            target_type="entity_link_candidate",
            target_id=candidate_id,
            safe_metadata={
                "candidate_id": candidate_id,
                "decision": decision.value,
                "previous_status": prev_status,
                "new_status": decision.value,
            },
        )
        self.session.commit()

        return EntityLinkReviewResponse(
            review_id=rev_id,
            candidate_id=candidate_id,
            installation_id=self.installation_id,
            reviewer_subject=actor_subject,
            decision=decision.value,
            rationale=rationale,
            previous_status=prev_status,
            new_status=decision.value,
            reviewed_at=rev_rec.reviewed_at.isoformat(),
        )

    # -------------------------------------------------------------------------
    # Snapshots & Runs
    # -------------------------------------------------------------------------

    def create_snapshot(
        self,
        as_of: datetime | None,
        actor_subject: str,
        actor_role: str,
    ) -> NetworkSnapshotResponse:
        as_of_dt = as_of or _utc_now()
        graph = self.load_active_network(as_of=as_of_dt)

        n_keys = sorted(graph.nodes.keys())
        e_keys = sorted(e.edge_id for e in graph.edges)
        nodes_digest = hashlib.sha256(",".join(n_keys).encode()).hexdigest()
        edges_digest = hashlib.sha256(",".join(e_keys).encode()).hexdigest()

        snap_id = f"snap_{hashlib.sha256(f'{self.installation_id}:{as_of_dt.isoformat()}'.encode()).hexdigest()[:16]}"
        snap_rec = NetworkSnapshotRecord(
            snapshot_id=snap_id,
            installation_id=self.installation_id,
            as_of=as_of_dt,
            node_count=len(n_keys),
            edge_count=len(e_keys),
            nodes_digest=nodes_digest,
            edges_digest=edges_digest,
            metadata_={"created_by": actor_subject},
            created_at=_utc_now(),
        )
        self.session.merge(snap_rec)
        self.session.commit()

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="create_network_snapshot",
            target_type="network_snapshot",
            target_id=snap_id,
            safe_metadata={"snapshot_id": snap_id, "count": len(n_keys)},
        )
        self.session.commit()

        return NetworkSnapshotResponse(
            snapshot_id=snap_id,
            installation_id=self.installation_id,
            as_of=as_of_dt.isoformat(),
            node_count=len(n_keys),
            edge_count=len(e_keys),
            nodes_digest=nodes_digest,
            edges_digest=edges_digest,
            metadata=snap_rec.metadata_,
            created_at=snap_rec.created_at.isoformat(),
        )

    def list_snapshots(self) -> list[NetworkSnapshotResponse]:
        stmt = (
            select(NetworkSnapshotRecord)
            .where(NetworkSnapshotRecord.installation_id == self.installation_id)
            .order_by(NetworkSnapshotRecord.created_at.desc())
        )
        return [
            NetworkSnapshotResponse(
                snapshot_id=r.snapshot_id,
                installation_id=r.installation_id,
                as_of=r.as_of.isoformat(),
                node_count=r.node_count,
                edge_count=r.edge_count,
                nodes_digest=r.nodes_digest,
                edges_digest=r.edges_digest,
                metadata=r.metadata_ or {},
                created_at=r.created_at.isoformat(),
            )
            for r in self.session.execute(stmt).scalars()
        ]

    def list_analysis_runs(self, case_id: str | None = None) -> list[NetworkAnalysisRunResponse]:
        stmt = select(NetworkAnalysisRunRecord).where(
            NetworkAnalysisRunRecord.installation_id == self.installation_id
        )
        if case_id:
            stmt = stmt.where(NetworkAnalysisRunRecord.case_id == case_id)
        stmt = stmt.order_by(NetworkAnalysisRunRecord.executed_at.desc())

        return [
            NetworkAnalysisRunResponse(
                run_id=r.run_id,
                installation_id=r.installation_id,
                case_id=r.case_id,
                executed_by=r.executed_by,
                seed_entities=r.seed_entities or [],
                findings_count=r.findings_count,
                nodes_count=r.nodes_count,
                edges_count=r.edges_count,
                truncated=r.truncated,
                result_digest=r.result_digest,
                executed_at=r.executed_at.isoformat(),
            )
            for r in self.session.execute(stmt).scalars()
        ]

    # -------------------------------------------------------------------------
    # Response formatting helpers
    # -------------------------------------------------------------------------

    def _to_node_response(self, n: NetworkNode) -> NetworkNodeResponse:
        return NetworkNodeResponse(
            installation_id=n.installation_id,
            node_key=n.node_key,
            entity_type=n.entity_type,
            pseudonymous_label=n.pseudonymous_label,
            attributes=n.attributes,
            first_seen=n.first_seen.isoformat() if n.first_seen else None,
            last_seen=n.last_seen.isoformat() if n.last_seen else None,
        )

    def _to_edge_response(self, e: NetworkEdge) -> NetworkEdgeResponse:
        return NetworkEdgeResponse(
            installation_id=e.installation_id,
            edge_id=e.edge_id,
            source_key=e.source_key,
            target_key=e.target_key,
            relationship_type=e.relationship_type,
            evidence_basis=e.evidence_basis.value,
            event_ids=list(e.event_ids),
            source_record_ids=list(e.source_record_ids),
            source_systems=list(e.source_systems),
            first_seen=e.first_seen.isoformat() if e.first_seen else None,
            last_seen=e.last_seen.isoformat() if e.last_seen else None,
            confidence=e.confidence,
            directed=e.directed,
            attributes=e.attributes,
        )

    def _to_subgraph_response(self, s: EvidenceSubgraph) -> EvidenceSubgraphResponse:
        return EvidenceSubgraphResponse(
            installation_id=s.installation_id,
            seed_nodes=list(s.seed_nodes),
            nodes=[self._to_node_response(n) for n in s.nodes],
            edges=[self._to_edge_response(e) for e in s.edges],
            truncated=s.truncated,
            truncation_reason=s.truncation_reason,
            max_depth_reached=s.max_depth_reached,
            limitations=list(s.limitations),
            node_count=s.node_count,
            edge_count=s.edge_count,
        )

    def _to_finding_response(self, f: NetworkPatternFinding) -> NetworkPatternFindingResponse:
        return NetworkPatternFindingResponse(
            pattern_id=f.pattern_id,
            installation_id=f.installation_id,
            pattern_type=f.pattern_type,
            anchor_entity=f.anchor_entity,
            related_entities=list(f.related_entities),
            event_ids=list(f.event_ids),
            start_time=f.start_time.isoformat(),
            end_time=f.end_time.isoformat(),
            detection_time=f.detection_time.isoformat(),
            explanation=f.explanation,
            evidence_limitations=list(f.evidence_limitations),
            alternative_legitimate_explanations=list(f.alternative_legitimate_explanations),
            supporting_source_systems=list(f.supporting_source_systems),
            transaction_ids=list(f.transaction_ids),
            monetary_total=str(f.monetary_total) if f.monetary_total is not None else None,
            currency=f.currency,
            confidence=f.confidence,
            pattern_version=f.pattern_version,
        )

    def _to_candidate_response(self, c: EntityLinkCandidate) -> EntityLinkCandidateResponse:
        return EntityLinkCandidateResponse(
            candidate_id=c.candidate_id,
            installation_id=c.installation_id,
            source_entity_key=c.source_entity_key,
            target_entity_key=c.target_entity_key,
            attribute_type=c.attribute_type,
            attribute_value=c.attribute_value,
            match_type=c.match_type.value,
            status=c.status.value,
            confidence=c.confidence,
            supporting_evidence=list(c.supporting_evidence),
            contradicting_evidence=list(c.contradicting_evidence),
            source_systems=list(c.source_systems),
            first_observed=c.first_observed.isoformat(),
            last_observed=c.last_observed.isoformat(),
            reviewed_by=c.reviewed_by,
            reviewed_at=c.reviewed_at.isoformat() if c.reviewed_at else None,
            review_rationale=c.review_rationale,
        )
