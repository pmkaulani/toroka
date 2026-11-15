"""Application service managing cross-system correlation, entity relationships, and investigation bundling."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from toroka_enterprise.intelligence.entities import EntityRef, EntityType, Relationship
from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise.intelligence.hypotheses import HypothesisStatus, InvestigationHypothesis
from toroka_enterprise.intelligence.investigation import InvestigationBundle
from toroka_enterprise.intelligence.models import (
    IntelligenceEventRecord,
    IntelligenceRelationshipRecord,
    IntelligenceSignalRecord,
    InvestigationBundleRecord,
    InvestigationHypothesisRecord,
    new_id,
    utc_now,
)
from toroka_enterprise.intelligence.rules import run_all_correlation_rules
from toroka_enterprise.intelligence.signals import CorrelationSignal, SignalSeverity
from toroka_enterprise.intelligence.summary import summarize

from ..persistence.models import EnterpriseCase

logger = logging.getLogger(__name__)


class IntelligenceService:
    """Manages cross-system fraud intelligence, temporal correlation, and investigation bundling."""

    def __init__(self, db: Session, installation_id: str):
        self.db = db
        self.installation_id = installation_id

    def record_event(self, event: IntelligenceEvent) -> IntelligenceEventRecord:
        """Persist an intelligence event with installation scoping."""
        if event.installation_id != self.installation_id:
            raise ValueError(
                f"Installation mismatch: cannot record event for '{event.installation_id}' in '{self.installation_id}'"
            )

        existing = self.db.get(
            IntelligenceEventRecord,
            (event.event_id, self.installation_id),
        )
        if existing:
            return existing

        rec = IntelligenceEventRecord(
            event_id=event.event_id,
            installation_id=self.installation_id,
            event_type=event.event_type,
            event_time=event.event_time,
            actor=event.actor,
            subject=event.subject,
            source_system=event.source_system,
            source_record_id=event.source_record_id,
            entities=list(event.entities),
            attributes=dict(event.attributes),
            provenance_digest=event.provenance_digest,
            created_at=utc_now(),
        )
        self.db.add(rec)
        self.db.flush()
        return rec

    def record_relationship(self, rel: Relationship) -> IntelligenceRelationshipRecord:
        """Persist an entity relationship edge."""
        if rel.installation_id != self.installation_id:
            raise ValueError(
                f"Installation mismatch: cannot record relationship for '{rel.installation_id}' in '{self.installation_id}'"
            )

        stmt = select(IntelligenceRelationshipRecord).where(
            IntelligenceRelationshipRecord.installation_id == self.installation_id,
            IntelligenceRelationshipRecord.source_type == rel.source.entity_type.value,
            IntelligenceRelationshipRecord.source_id == rel.source.entity_id,
            IntelligenceRelationshipRecord.target_type == rel.target.entity_type.value,
            IntelligenceRelationshipRecord.target_id == rel.target.entity_id,
            IntelligenceRelationshipRecord.relationship_type == rel.relationship_type,
        )
        existing = self.db.execute(stmt).scalar_one_or_none()
        if existing:
            if rel.last_seen:
                existing.last_seen = rel.last_seen
            existing.confidence = rel.confidence
            existing.attributes = dict(rel.attributes)
            self.db.flush()
            return existing

        rec = IntelligenceRelationshipRecord(
            id=new_id(),
            installation_id=self.installation_id,
            source_type=rel.source.entity_type.value,
            source_id=rel.source.entity_id,
            target_type=rel.target.entity_type.value,
            target_id=rel.target.entity_id,
            relationship_type=rel.relationship_type,
            first_seen=rel.first_seen,
            last_seen=rel.last_seen,
            confidence=rel.confidence,
            source_system=rel.source_system,
            source_record_id=rel.source_record_id,
            attributes=dict(rel.attributes),
            created_at=utc_now(),
        )
        self.db.add(rec)
        self.db.flush()
        return rec

    def record_signal(
        self,
        signal: CorrelationSignal,
        case_id: str | None = None,
    ) -> IntelligenceSignalRecord:
        """Persist a correlation signal."""
        existing = self.db.get(
            IntelligenceSignalRecord,
            (signal.signal_id, self.installation_id),
        )
        if existing:
            if case_id and not existing.case_id:
                existing.case_id = case_id
                self.db.flush()
            return existing

        rec = IntelligenceSignalRecord(
            signal_id=signal.signal_id,
            installation_id=self.installation_id,
            case_id=case_id,
            signal_type=signal.signal_type,
            severity=signal.severity.value,
            title=signal.title,
            explanation=signal.explanation,
            event_ids=list(signal.event_ids),
            confidence=signal.confidence,
            evidence=[dict(e) for e in signal.evidence],
            alternative_explanations=list(signal.alternative_explanations),
            missing_evidence=list(signal.missing_evidence),
            created_at=utc_now(),
        )
        self.db.add(rec)
        self.db.flush()
        return rec

    def save_hypothesis(
        self,
        case_id: str,
        hypothesis: InvestigationHypothesis,
    ) -> InvestigationHypothesisRecord:
        """Create or update an investigation hypothesis for a case."""
        existing = self.db.get(
            InvestigationHypothesisRecord,
            (hypothesis.hypothesis_id, self.installation_id),
        )
        if existing:
            if existing.case_id != case_id:
                raise ValueError("Hypothesis belongs to a different case")
            existing.title = hypothesis.title
            existing.description = hypothesis.description
            existing.status = hypothesis.status.value
            existing.supporting_signal_ids = list(hypothesis.supporting_signal_ids)
            existing.contradicting_signal_ids = list(hypothesis.contradicting_signal_ids)
            existing.confidence = hypothesis.confidence
            existing.investigator_note = hypothesis.investigator_note
            existing.updated_at = utc_now()
            self.db.flush()
            return existing

        rec = InvestigationHypothesisRecord(
            hypothesis_id=hypothesis.hypothesis_id,
            installation_id=self.installation_id,
            case_id=case_id,
            title=hypothesis.title,
            description=hypothesis.description,
            status=hypothesis.status.value,
            supporting_signal_ids=list(hypothesis.supporting_signal_ids),
            contradicting_signal_ids=list(hypothesis.contradicting_signal_ids),
            confidence=hypothesis.confidence,
            investigator_note=hypothesis.investigator_note,
            created_at=utc_now(),
        )
        self.db.add(rec)
        self.db.flush()
        return rec

    def list_hypotheses(self, case_id: str) -> list[InvestigationHypothesisRecord]:
        """List all hypotheses attached to a case."""
        stmt = (
            select(InvestigationHypothesisRecord)
            .where(
                InvestigationHypothesisRecord.installation_id == self.installation_id,
                InvestigationHypothesisRecord.case_id == case_id,
            )
            .order_by(InvestigationHypothesisRecord.created_at)
        )
        return list(self.db.execute(stmt).scalars().all())

    def get_case_relationships(self, case_id: str) -> list[IntelligenceRelationshipRecord]:
        """Retrieve relationship edges relevant to entities in the case."""
        case = self.db.get(EnterpriseCase, case_id)
        if not case or case.installation_id != self.installation_id:
            return []

        # Collect entities from snapshot
        entities: set[str] = set()
        snapshot = case.snapshot or {}
        for key in ("staff_ref", "customer_ref", "account_ref", "focus"):
            val = snapshot.get(key)
            if val and isinstance(val, str):
                entities.add(val)

        if not entities:
            # Fallback to case label/focus
            entities.add(case.focus)

        stmt = select(IntelligenceRelationshipRecord).where(
            IntelligenceRelationshipRecord.installation_id == self.installation_id,
            (
                IntelligenceRelationshipRecord.source_id.in_(entities)
                | IntelligenceRelationshipRecord.target_id.in_(entities)
            ),
        )
        return list(self.db.execute(stmt).scalars().all())

    def get_case_timeline(self, case_id: str) -> list[IntelligenceEventRecord]:
        """Chronologically order events linked to entities in the case."""
        case = self.db.get(EnterpriseCase, case_id)
        if not case or case.installation_id != self.installation_id:
            return []

        entities: set[str] = set()
        snapshot = case.snapshot or {}
        for key in ("staff_ref", "customer_ref", "account_ref", "focus"):
            val = snapshot.get(key)
            if val and isinstance(val, str):
                entities.add(val)
        entities.add(case.focus)

        stmt = (
            select(IntelligenceEventRecord)
            .where(
                IntelligenceEventRecord.installation_id == self.installation_id,
                (
                    IntelligenceEventRecord.actor.in_(entities)
                    | IntelligenceEventRecord.subject.in_(entities)
                ),
            )
            .order_by(IntelligenceEventRecord.event_time.asc())
        )
        return list(self.db.execute(stmt).scalars().all())

    def correlate_case(
        self,
        case_id: str,
        before_minutes: int = 60,
        after_minutes: int = 60,
    ) -> tuple[InvestigationBundle, InvestigationBundleRecord]:
        """Correlate events for a case across systems within a temporal window and generate an investigation bundle."""
        case = self.db.get(EnterpriseCase, case_id)
        if not case or case.installation_id != self.installation_id:
            raise ValueError(f"Case '{case_id}' not found in installation '{self.installation_id}'")

        # Determine anchor time (from case updated_at or created_at)
        anchor_time = case.created_at
        start_win = anchor_time - timedelta(minutes=before_minutes)
        end_win = anchor_time + timedelta(minutes=after_minutes)

        # Query events in window for this installation
        stmt = (
            select(IntelligenceEventRecord)
            .where(
                IntelligenceEventRecord.installation_id == self.installation_id,
                IntelligenceEventRecord.event_time >= start_win,
                IntelligenceEventRecord.event_time <= end_win,
            )
            .order_by(IntelligenceEventRecord.event_time.asc())
        )
        db_events = list(self.db.execute(stmt).scalars().all())

        # Convert to domain IntelligenceEvents
        domain_events: list[IntelligenceEvent] = []
        for dbe in db_events:
            domain_events.append(
                IntelligenceEvent(
                    installation_id=self.installation_id,
                    event_id=dbe.event_id,
                    event_type=dbe.event_type,
                    event_time=dbe.event_time,
                    actor=dbe.actor,
                    subject=dbe.subject,
                    source_system=dbe.source_system,
                    source_record_id=dbe.source_record_id,
                    entities=tuple(dbe.entities or []),
                    attributes=dict(dbe.attributes or {}),
                    provenance_digest=dbe.provenance_digest,
                )
            )

        # Run correlation rules
        detected_signals = run_all_correlation_rules(domain_events)

        # Build investigation bundle
        inv_id = f"inv-{case_id}-{int(utc_now().timestamp())}"
        bundle = InvestigationBundle(
            investigation_id=inv_id,
            installation_id=self.installation_id,
            anchor_event_ids=[dbe.event_id for dbe in db_events[:5]],
        )

        for e in domain_events:
            bundle.add_event(e)

        for sig in detected_signals:
            bundle.add_signal(sig)
            self.record_signal(sig, case_id=case_id)

        # Attach existing hypotheses from database or generate standard competing hypotheses if none exist
        existing_hypo_recs = self.list_hypotheses(case_id)
        if existing_hypo_recs:
            for hr in existing_hypo_recs:
                bundle.add_hypothesis(
                    InvestigationHypothesis(
                        hypothesis_id=hr.hypothesis_id,
                        title=hr.title,
                        description=hr.description,
                        status=HypothesisStatus(hr.status),
                        supporting_signal_ids=tuple(hr.supporting_signal_ids or []),
                        contradicting_signal_ids=tuple(hr.contradicting_signal_ids or []),
                        confidence=hr.confidence,
                        investigator_note=hr.investigator_note,
                    )
                )
        elif detected_signals:
            # Generate starting competing hypotheses
            sig_ids = tuple(s.signal_id for s in detected_signals)
            h1 = InvestigationHypothesis(
                hypothesis_id=f"H1-unauthorized-{case_id[:8]}",
                title="Unauthorized Procedural Intervention",
                description="Staff member conducted unauthorized actions outside approved workflow guidelines.",
                status=HypothesisStatus.OPEN,
                supporting_signal_ids=sig_ids,
                confidence=0.5,
            )
            h2 = InvestigationHypothesis(
                hypothesis_id=f"H2-legitimate-service-{case_id[:8]}",
                title="Legitimate Customer Service Activity",
                description="Staff member was executing authorized customer requests with documentation pending.",
                status=HypothesisStatus.OPEN,
                supporting_signal_ids=(),
                contradicting_signal_ids=sig_ids,
                confidence=0.5,
                investigator_note="Awaiting ticket confirmation from branch/CRM.",
            )
            self.save_hypothesis(case_id, h1)
            self.save_hypothesis(case_id, h2)
            bundle.add_hypothesis(h1)
            bundle.add_hypothesis(h2)

        # Attach relationships
        rel_recs = self.get_case_relationships(case_id)
        for rr in rel_recs:
            bundle.add_relationship(
                Relationship(
                    installation_id=self.installation_id,
                    source=EntityRef(self.installation_id, EntityType(rr.source_type), rr.source_id),
                    target=EntityRef(self.installation_id, EntityType(rr.target_type), rr.target_id),
                    relationship_type=rr.relationship_type,
                    first_seen=rr.first_seen,
                    last_seen=rr.last_seen,
                    confidence=rr.confidence,
                    source_system=rr.source_system,
                    source_record_id=rr.source_record_id,
                    attributes=dict(rr.attributes or {}),
                )
            )

        summary = summarize(bundle)

        bundle_record = InvestigationBundleRecord(
            investigation_id=inv_id,
            installation_id=self.installation_id,
            case_id=case_id,
            anchor_event_ids=bundle.anchor_event_ids,
            finding=summary.finding,
            confidence=summary.confidence,
            requires_human_review=summary.requires_human_review,
            bundle_json=bundle.to_dict(),
            created_at=utc_now(),
        )
        self.db.add(bundle_record)
        self.db.commit()

        return bundle, bundle_record

    def get_investigation_bundle(self, case_id: str) -> InvestigationBundleRecord | None:
        """Retrieve the latest investigation bundle for a case."""
        stmt = (
            select(InvestigationBundleRecord)
            .where(
                InvestigationBundleRecord.installation_id == self.installation_id,
                InvestigationBundleRecord.case_id == case_id,
            )
            .order_by(desc(InvestigationBundleRecord.created_at))
        )
        return self.db.execute(stmt).scalars().first()

    def list_signals(self, limit: int = 50) -> list[IntelligenceSignalRecord]:
        """List detected correlation signals across the installation."""
        stmt = (
            select(IntelligenceSignalRecord)
            .where(IntelligenceSignalRecord.installation_id == self.installation_id)
            .order_by(desc(IntelligenceSignalRecord.created_at))
            .limit(limit)
        )
        return list(self.db.execute(stmt).scalars().all())
