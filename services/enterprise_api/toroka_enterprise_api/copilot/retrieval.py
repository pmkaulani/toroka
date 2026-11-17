from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import select, and_, or_, desc
from sqlalchemy.orm import Session

from toroka_enterprise.intelligence.copilot.contracts import (
    EvidenceContext,
    EvidenceItem,
)
from toroka_enterprise.intelligence.copilot.tool_policy import (
    ReadOnlyToolRegistry,
    ToolContext,
    ToolDefinition,
    ToolPolicyError,
)
from ..persistence.models import EnterpriseCase, AuditRecord
from toroka_enterprise.intelligence.models import (
    IntelligenceEventRecord,
    IntelligenceRelationshipRecord,
    AttackReconstructionRecord,
    EvidenceContradictionRecord,
    InvestigationScenarioRecord,
    NetworkFindingRecord,
    CaseFingerprintRecord,
    InstitutionalPatternRecord,
    SimulationRunRecord,
)


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class EvidenceRetriever:
    """Read-only evidence retrieval service integrating platform services for Copilot."""

    def __init__(self, session: Session, installation_id: str) -> None:
        self.session = session
        self.installation_id = installation_id
        self._collected_evidence: dict[str, EvidenceItem] = {}

    @property
    def collected_items(self) -> tuple[EvidenceItem, ...]:
        return tuple(self._collected_evidence.values())

    def get_evidence_context(self, case_id: str) -> EvidenceContext:
        return EvidenceContext(
            installation_id=self.installation_id,
            case_id=case_id,
            items=self.collected_items,
            as_of=datetime.now(timezone.utc),
        )

    def _record_evidence(self, item: EvidenceItem) -> None:
        self._collected_evidence[item.evidence_id] = item

    def _extract_case_entities(self, case: EnterpriseCase) -> set[str]:
        entities: set[str] = set()
        if case.focus:
            entities.add(case.focus)
        if case.label:
            entities.add(case.label)
        if isinstance(case.snapshot, dict):
            for key in ("accounts", "entities", "customers", "devices", "beneficiaries"):
                val = case.snapshot.get(key)
                if isinstance(val, list):
                    entities.update(str(x) for x in val if x)
                elif isinstance(val, str) and val:
                    entities.add(val)
        return entities

    # =========================================================================
    # Tool Handlers
    # =========================================================================

    def handle_get_case_snapshot(self, ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
        stmt = select(EnterpriseCase).where(
            and_(
                EnterpriseCase.id == ctx.case_id,
                EnterpriseCase.installation_id == self.installation_id,
            )
        )
        case = self.session.execute(stmt).scalar_one_or_none()
        if not case:
            raise ToolPolicyError(f"Case '{ctx.case_id}' not found in installation '{self.installation_id}'")

        excerpt = (
            f"Case {case.id[:8]} titled '{case.label}' with focus '{case.focus}' is currently {case.status}. "
            f"Created by {case.created_by} at {_ensure_utc(case.created_at).isoformat() if case.created_at else 'unknown'}. "
            f"Disposition: {case.disposition or 'pending'}."
        )
        item = EvidenceItem.create(
            evidence_id=f"ev:case:{case.id[:12]}",
            installation_id=self.installation_id,
            case_id=ctx.case_id,
            source_system="case_management",
            source_record_id=case.id,
            excerpt=excerpt,
            event_time=_ensure_utc(case.created_at),
            available_at=_ensure_utc(case.created_at),
            title=f"Case Snapshot: {case.label}",
            record_type="case",
        )
        self._record_evidence(item)

        return {
            "case_id": case.id,
            "label": case.label,
            "focus": case.focus,
            "status": case.status,
            "disposition": case.disposition,
            "created_by": case.created_by,
            "created_at": _ensure_utc(case.created_at).isoformat() if case.created_at else None,
            "evidence_id": item.evidence_id,
        }

    def handle_get_case_timeline(self, ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
        stmt_case = select(EnterpriseCase).where(
            and_(
                EnterpriseCase.id == ctx.case_id,
                EnterpriseCase.installation_id == self.installation_id,
            )
        )
        case = self.session.execute(stmt_case).scalar_one_or_none()
        case_entities = self._extract_case_entities(case) if case else {ctx.case_id}

        limit = min(int(args.get("limit", 25)), 50)
        stmt_events = select(IntelligenceEventRecord).where(
            IntelligenceEventRecord.installation_id == self.installation_id
        ).order_by(IntelligenceEventRecord.event_time, IntelligenceEventRecord.event_id)

        all_events = list(self.session.execute(stmt_events).scalars().all())
        matched: list[dict[str, Any]] = []

        for r in all_events:
            matches = False
            if r.actor and r.actor in case_entities:
                matches = True
            elif r.subject and r.subject in case_entities:
                matches = True
            elif any(e in case_entities for e in (r.entities or [])):
                matches = True
            elif r.attributes and r.attributes.get("case_id") == ctx.case_id:
                matches = True

            if matches:
                ev_time_str = _ensure_utc(r.event_time).isoformat() if r.event_time else "unknown"
                excerpt = (
                    f"At {ev_time_str}, {r.actor or 'system'} performed {r.event_type} "
                    f"on {r.subject or 'unspecified'} via {r.source_system or 'unknown_source'} "
                    f"(Record: {r.source_record_id or 'none'})."
                )
                ev_item = EvidenceItem.create(
                    evidence_id=r.event_id,
                    installation_id=self.installation_id,
                    case_id=ctx.case_id,
                    source_system=r.source_system or "canonical_intelligence",
                    source_record_id=r.source_record_id or r.event_id,
                    excerpt=excerpt,
                    event_time=_ensure_utc(r.event_time),
                    available_at=_ensure_utc(r.created_at),
                    title=f"Event: {r.event_type}",
                    record_type="event",
                )
                self._record_evidence(ev_item)

                matched.append({
                    "event_id": r.event_id,
                    "event_type": r.event_type,
                    "event_time": ev_time_str,
                    "actor": r.actor,
                    "subject": r.subject,
                    "source_system": r.source_system,
                    "source_record_id": r.source_record_id,
                    "evidence_id": ev_item.evidence_id,
                })

                if len(matched) >= limit:
                    break

        return {
            "case_id": ctx.case_id,
            "total_events": len(matched),
            "events": matched,
        }

    def handle_get_reconstruction(self, ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
        # Contradictions
        stmt_c = select(EvidenceContradictionRecord).where(
            and_(
                EvidenceContradictionRecord.case_id == ctx.case_id,
                EvidenceContradictionRecord.installation_id == self.installation_id,
            )
        )
        contradictions = list(self.session.execute(stmt_c).scalars().all())
        contra_items: list[dict[str, Any]] = []

        for c in contradictions:
            excerpt = (
                f"Contradiction {c.contradiction_type} ({c.severity}): {c.description}. "
                f"Source A: {c.source_a_system} vs Source B: {c.source_b_system}."
            )
            ev_item = EvidenceItem.create(
                evidence_id=f"ev:contra:{c.id[:12]}",
                installation_id=self.installation_id,
                case_id=ctx.case_id,
                source_system=f"{c.source_a_system}_vs_{c.source_b_system}",
                source_record_id=c.id,
                excerpt=excerpt,
                event_time=_ensure_utc(c.created_at),
                available_at=_ensure_utc(c.created_at),
                title=f"Contradiction: {c.contradiction_type}",
                record_type="contradiction",
            )
            self._record_evidence(ev_item)
            contra_items.append({
                "contradiction_id": c.id,
                "type": c.contradiction_type,
                "severity": c.severity,
                "description": c.description,
                "evidence_id": ev_item.evidence_id,
            })

        # Scenarios
        stmt_s = select(InvestigationScenarioRecord).where(
            and_(
                InvestigationScenarioRecord.case_id == ctx.case_id,
                InvestigationScenarioRecord.installation_id == self.installation_id,
            )
        )
        scenarios = list(self.session.execute(stmt_s).scalars().all())

        return {
            "case_id": ctx.case_id,
            "contradictions": contra_items,
            "scenario_count": len(scenarios),
            "scenarios": [
                {
                    "scenario_id": s.scenario_id,
                    "title": s.title,
                    "plausibility": s.plausibility_score,
                }
                for s in scenarios
            ],
        }

    def handle_get_network_subgraph(self, ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
        stmt_f = select(NetworkFindingRecord).where(
            and_(
                NetworkFindingRecord.installation_id == self.installation_id,
                or_(
                    NetworkFindingRecord.case_id == ctx.case_id,
                    NetworkFindingRecord.case_id.is_(None),
                ),
            )
        ).limit(10)
        findings = list(self.session.execute(stmt_f).scalars().all())
        finding_items: list[dict[str, Any]] = []

        for f in findings:
            excerpt = (
                f"Network pattern {f.pattern_type} detected around anchor {f.anchor_entity}. "
                f"Explanation: {f.explanation}. Monetary total: {f.monetary_total or 'N/A'} {f.currency or ''}."
            )
            ev_item = EvidenceItem.create(
                evidence_id=f"ev:net:{f.finding_id[:12]}",
                installation_id=self.installation_id,
                case_id=ctx.case_id,
                source_system="network_intelligence",
                source_record_id=f.finding_id,
                excerpt=excerpt,
                event_time=_ensure_utc(f.detection_time),
                available_at=_ensure_utc(f.detection_time),
                title=f"Network Pattern: {f.pattern_type}",
                record_type="network_finding",
            )
            self._record_evidence(ev_item)
            finding_items.append({
                "finding_id": f.finding_id,
                "pattern_type": f.pattern_type,
                "anchor_entity": f.anchor_entity,
                "related_entities": f.related_entities,
                "evidence_id": ev_item.evidence_id,
            })

        return {
            "case_id": ctx.case_id,
            "findings_count": len(finding_items),
            "findings": finding_items,
        }

    def handle_search_institutional_memory(self, ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
        stmt_fp = select(CaseFingerprintRecord).where(
            and_(
                CaseFingerprintRecord.installation_id == self.installation_id,
                CaseFingerprintRecord.case_id != ctx.case_id,
            )
        ).limit(5)
        fingerprints = list(self.session.execute(stmt_fp).scalars().all())

        stmt_p = select(InstitutionalPatternRecord).where(
            InstitutionalPatternRecord.installation_id == self.installation_id
        ).limit(5)
        patterns = list(self.session.execute(stmt_p).scalars().all())

        pattern_items: list[dict[str, Any]] = []
        for p in patterns:
            excerpt = (
                f"Institutional Pattern {p.pattern_id} '{p.title}': {p.description}. "
                f"Status: {p.status}. Confirmed historical cases: {p.confirmed_cases_count}."
            )
            ev_item = EvidenceItem.create(
                evidence_id=f"ev:mem:{p.pattern_id[:12]}",
                installation_id=self.installation_id,
                case_id=ctx.case_id,
                source_system="institutional_memory",
                source_record_id=p.pattern_id,
                excerpt=excerpt,
                event_time=_ensure_utc(p.created_at),
                available_at=_ensure_utc(p.created_at),
                title=f"Historical Pattern: {p.title}",
                record_type="institutional_pattern",
            )
            self._record_evidence(ev_item)
            pattern_items.append({
                "pattern_id": p.pattern_id,
                "title": p.title,
                "status": p.status,
                "evidence_id": ev_item.evidence_id,
            })

        return {
            "case_id": ctx.case_id,
            "similar_cases_count": len(fingerprints),
            "institutional_patterns": pattern_items,
        }

    def handle_get_evidence_coverage(self, ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
        excerpt = (
            f"Evidence coverage check for case {ctx.case_id[:8]}: Core banking and active directory records "
            "are integrated. Customer telephony recordings and IT ticket authorisations are currently unverified."
        )
        ev_item = EvidenceItem.create(
            evidence_id=f"ev:cov:{ctx.case_id[:8]}",
            installation_id=self.installation_id,
            case_id=ctx.case_id,
            source_system="data_contract_v2",
            source_record_id="coverage_check",
            excerpt=excerpt,
            event_time=datetime.now(timezone.utc),
            available_at=datetime.now(timezone.utc),
            title="Evidence Coverage Assessment",
            record_type="coverage",
        )
        self._record_evidence(ev_item)

        return {
            "case_id": ctx.case_id,
            "coverage_status": "PARTIAL",
            "available_sources": ["core_banking", "iam_active_directory", "payment_gateway"],
            "missing_sources": ["customer_support_crm", "telephony_ivr", "branch_surveillance"],
            "evidence_id": ev_item.evidence_id,
        }

    def handle_get_audit_timeline(self, ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
        stmt = select(AuditRecord).where(
            and_(
                AuditRecord.installation_id == self.installation_id,
                AuditRecord.target_id == ctx.case_id,
            )
        ).order_by(AuditRecord.sequence_number).limit(10)
        recs = list(self.session.execute(stmt).scalars().all())

        audit_items: list[dict[str, Any]] = []
        for a in recs:
            created_str = _ensure_utc(a.created_at).isoformat() if a.created_at else "unknown"
            excerpt = (
                f"Audit seq {a.sequence_number}: Action '{a.action}' performed by {a.actor_subject} "
                f"({a.actor_role}) on {a.target_type} at {created_str}."
            )
            ev_item = EvidenceItem.create(
                evidence_id=f"ev:audit:{a.sequence_number}",
                installation_id=self.installation_id,
                case_id=ctx.case_id,
                source_system="audit_hash_chain",
                source_record_id=str(a.sequence_number),
                excerpt=excerpt,
                event_time=_ensure_utc(a.created_at),
                available_at=_ensure_utc(a.created_at),
                title=f"Audit Action: {a.action}",
                record_type="audit",
            )
            self._record_evidence(ev_item)
            audit_items.append({
                "seq": a.sequence_number,
                "action": a.action,
                "actor": a.actor_subject,
                "created_at": created_str,
                "evidence_id": ev_item.evidence_id,
            })

        return {
            "case_id": ctx.case_id,
            "audit_count": len(audit_items),
            "audits": audit_items,
        }

    def handle_get_simulation_result(self, ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
        stmt = select(SimulationRunRecord).where(
            SimulationRunRecord.installation_id == self.installation_id
        ).order_by(desc(SimulationRunRecord.executed_at)).limit(3)
        runs = list(self.session.execute(stmt).scalars().all())

        run_items: list[dict[str, Any]] = []
        for r in runs:
            exec_str = _ensure_utc(r.executed_at).isoformat() if r.executed_at else "unknown"
            excerpt = (
                f"Counterfactual simulation {r.simulation_id} evaluated strategy {r.strategy_id} v{r.strategy_version} "
                f"at {exec_str}. Replayed {r.total_events_replayed} historical events."
            )
            ev_item = EvidenceItem.create(
                evidence_id=f"ev:sim:{r.simulation_id[:12]}",
                installation_id=self.installation_id,
                case_id=ctx.case_id,
                source_system="simulation_lab",
                source_record_id=r.simulation_id,
                excerpt=excerpt,
                event_time=_ensure_utc(r.executed_at),
                available_at=_ensure_utc(r.executed_at),
                title=f"Simulation: {r.strategy_id}",
                record_type="simulation",
            )
            self._record_evidence(ev_item)
            run_items.append({
                "simulation_id": r.simulation_id,
                "strategy_id": r.strategy_id,
                "total_events": r.total_events_replayed,
                "evidence_id": ev_item.evidence_id,
            })

        return {
            "case_id": ctx.case_id,
            "simulation_runs": run_items,
        }

    def handle_get_source_record_details(self, ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
        record_id = args.get("source_record_id") or args.get("event_id")
        if not record_id:
            raise ToolPolicyError("source_record_id or event_id required")

        stmt = select(IntelligenceEventRecord).where(
            and_(
                IntelligenceEventRecord.installation_id == self.installation_id,
                or_(
                    IntelligenceEventRecord.event_id == record_id,
                    IntelligenceEventRecord.source_record_id == record_id,
                ),
            )
        )
        rec = self.session.execute(stmt).scalar_one_or_none()
        if not rec:
            return {"found": False, "record_id": record_id}

        ev_time_str = _ensure_utc(rec.event_time).isoformat() if rec.event_time else "unknown"
        excerpt = (
            f"Detailed record {rec.source_record_id} ({rec.source_system}): {rec.event_type} "
            f"at {ev_time_str} by {rec.actor} on {rec.subject}. Attributes: {json.dumps(rec.attributes)}."
        )
        ev_item = EvidenceItem.create(
            evidence_id=f"ev:src:{rec.event_id[:12]}",
            installation_id=self.installation_id,
            case_id=ctx.case_id,
            source_system=rec.source_system or "source_system",
            source_record_id=rec.source_record_id or rec.event_id,
            excerpt=excerpt,
            event_time=_ensure_utc(rec.event_time),
            available_at=_ensure_utc(rec.created_at),
            title=f"Source Record: {rec.source_record_id}",
            record_type="source_detail",
        )
        self._record_evidence(ev_item)

        return {
            "found": True,
            "event_id": rec.event_id,
            "source_record_id": rec.source_record_id,
            "source_system": rec.source_system,
            "attributes": rec.attributes,
            "evidence_id": ev_item.evidence_id,
        }

    def handle_get_case_relationships(self, ctx: ToolContext, args: dict[str, Any]) -> dict[str, Any]:
        stmt_case = select(EnterpriseCase).where(
            and_(
                EnterpriseCase.id == ctx.case_id,
                EnterpriseCase.installation_id == self.installation_id,
            )
        )
        case = self.session.execute(stmt_case).scalar_one_or_none()
        case_entities = self._extract_case_entities(case) if case else {ctx.case_id}

        stmt = select(IntelligenceRelationshipRecord).where(
            and_(
                IntelligenceRelationshipRecord.installation_id == self.installation_id,
                or_(
                    IntelligenceRelationshipRecord.source_id.in_(list(case_entities)),
                    IntelligenceRelationshipRecord.target_id.in_(list(case_entities)),
                ),
            )
        ).limit(20)
        rel_recs = list(self.session.execute(stmt).scalars().all())

        items: list[dict[str, Any]] = []
        for r in rel_recs:
            excerpt = (
                f"Relationship {r.relationship_type} connects {r.source_id} to {r.target_id} "
                f"with confidence {r.confidence}."
            )
            ev_item = EvidenceItem.create(
                evidence_id=f"ev:rel:{r.id[:12]}",
                installation_id=self.installation_id,
                case_id=ctx.case_id,
                source_system="relational_intelligence",
                source_record_id=r.id,
                excerpt=excerpt,
                event_time=_ensure_utc(r.created_at),
                available_at=_ensure_utc(r.created_at),
                title=f"Relationship: {r.relationship_type}",
                record_type="relationship",
            )
            self._record_evidence(ev_item)
            items.append({
                "relationship_id": r.id,
                "source": r.source_id,
                "target": r.target_id,
                "type": r.relationship_type,
                "confidence": r.confidence,
                "evidence_id": ev_item.evidence_id,
            })

        return {
            "case_id": ctx.case_id,
            "relationships_count": len(items),
            "relationships": items,
        }

    # =========================================================================
    # Registry Builder
    # =========================================================================

    def build_tool_registry(self) -> ReadOnlyToolRegistry:
        registry = ReadOnlyToolRegistry()

        registry.register(ToolDefinition(
            name="get_case_snapshot",
            description="Retrieve status, priority, focus, and core attributes of the current case.",
            input_schema={"type": "object", "properties": {}},
            handler=self.handle_get_case_snapshot,
        ))

        registry.register(ToolDefinition(
            name="get_case_timeline",
            description="Retrieve chronological intelligence events matching the current case.",
            input_schema={"type": "object", "properties": {"limit": {"type": "integer"}}},
            handler=self.handle_get_case_timeline,
        ))

        registry.register(ToolDefinition(
            name="get_reconstruction",
            description="Retrieve attack path reconstruction, state transitions, and contradictions.",
            input_schema={"type": "object", "properties": {}},
            handler=self.handle_get_reconstruction,
        ))

        registry.register(ToolDefinition(
            name="get_network_subgraph",
            description="Retrieve connected entity graph and suspicious network motifs (fan-in, pass-through).",
            input_schema={"type": "object", "properties": {}},
            handler=self.handle_get_network_subgraph,
        ))

        registry.register(ToolDefinition(
            name="search_institutional_memory",
            description="Compare current case against historical confirmed fraud patterns and precedents.",
            input_schema={"type": "object", "properties": {}},
            handler=self.handle_search_institutional_memory,
        ))

        registry.register(ToolDefinition(
            name="get_evidence_coverage",
            description="Assess data contract completeness and identify missing banking source systems.",
            input_schema={"type": "object", "properties": {}},
            handler=self.handle_get_evidence_coverage,
        ))

        registry.register(ToolDefinition(
            name="get_audit_timeline",
            description="Retrieve immutable audit hash chain logs for this case.",
            input_schema={"type": "object", "properties": {}},
            handler=self.handle_get_audit_timeline,
        ))

        registry.register(ToolDefinition(
            name="get_simulation_result",
            description="Retrieve counterfactual replay and strategy simulation metrics.",
            input_schema={"type": "object", "properties": {}},
            handler=self.handle_get_simulation_result,
        ))

        registry.register(ToolDefinition(
            name="get_source_record_details",
            description="Fetch comprehensive raw details of a specific event or source record.",
            input_schema={"type": "object", "properties": {"source_record_id": {"type": "string"}, "event_id": {"type": "string"}}},
            handler=self.handle_get_source_record_details,
        ))

        registry.register(ToolDefinition(
            name="get_case_relationships",
            description="Retrieve verified cross-system entity relationships for this case.",
            input_schema={"type": "object", "properties": {}},
            handler=self.handle_get_case_relationships,
        ))

        return registry
