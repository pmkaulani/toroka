"""Operational service for Phase 9: Fraud DNA & Institutional Memory Engine."""
from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any
import uuid

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise.intelligence.memory import (
    CaseFingerprint,
    CaseSimilarity,
    FingerprintEvidence,
    InstitutionalPattern,
    PatternMatch,
    PatternStatus,
    PatternValidationPolicy,
    PatternValidationResult,
    approve_pattern,
    build_case_fingerprint,
    discover_candidate_patterns,
    evaluate_pattern,
    match_case_against_patterns,
    reinstate_pattern,
    reject_pattern,
    retire_pattern,
    retrieve_similar_historical_cases,
    suspend_pattern,
)
from toroka_enterprise.intelligence.models import (
    CaseFingerprintRecord,
    CaseMemoryFeatureRecord,
    InstitutionalPatternRecord,
    IntelligenceEventRecord,
    MemoryAuditEventRecord,
    MemoryMatchResultRecord,
    PatternCaseLinkRecord,
    PatternReviewRecord,
    PatternVersionRecord,
    SimulationCaseOutcomeRecord,
)
from ..memory_schemas import InstitutionalPatternCreate
from ..persistence.audit import append_audit
from ..persistence.models import EnterpriseCase

logger = logging.getLogger(__name__)


class MemoryService:
    """Manages case fingerprinting, fraud DNA typologies, pattern validation, and historical matching."""

    def __init__(self, session: Session, installation_id: str) -> None:
        self.session = session
        self.installation_id = installation_id

    # -------------------------------------------------------------------------
    # 1. Case Fingerprinting
    # -------------------------------------------------------------------------

    def get_or_build_fingerprint(
        self,
        case_id: str,
        force_refresh: bool = False,
    ) -> CaseFingerprint:
        """Retrieve existing fingerprint or deterministically extract and persist one."""
        if not force_refresh:
            stmt = select(CaseFingerprintRecord).where(
                CaseFingerprintRecord.case_id == case_id,
                CaseFingerprintRecord.installation_id == self.installation_id,
            )
            rec = self.session.execute(stmt).scalars().first()
            if rec:
                return self._record_to_domain_fingerprint(rec)

        # 1. Verify case exists
        case_stmt = select(EnterpriseCase).where(
            EnterpriseCase.id == case_id,
            EnterpriseCase.installation_id == self.installation_id,
        )
        case_rec = self.session.execute(case_stmt).scalars().first()
        if not case_rec:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case '{case_id}' not found in installation",
            )

        # 2. Check for ground truth outcome label
        outcome_stmt = select(SimulationCaseOutcomeRecord).where(
            SimulationCaseOutcomeRecord.case_id == case_id,
            SimulationCaseOutcomeRecord.installation_id == self.installation_id,
        )
        outcome_rec = self.session.execute(outcome_stmt).scalars().first()
        adjudicated_label = outcome_rec.label if outcome_rec else None

        # 3. Collect case events
        events: list[IntelligenceEvent] = []
        ev_stmt = (
            select(IntelligenceEventRecord)
            .where(IntelligenceEventRecord.installation_id == self.installation_id)
            .order_by(IntelligenceEventRecord.event_time.asc())
        )
        all_evs = self.session.execute(ev_stmt).scalars().all()

        focus_entities = {case_rec.focus} if case_rec.focus else set()
        if case_rec.snapshot and isinstance(case_rec.snapshot, dict):
            for k in ("staff_ref", "customer_ref", "account_ref", "entity_id"):
                val = case_rec.snapshot.get(k)
                if val:
                    focus_entities.add(str(val))

        for e in all_evs:
            ev_case_id = e.attributes.get("case_id") if e.attributes else None
            is_case_event = False
            if ev_case_id and ev_case_id == case_id:
                is_case_event = True
            elif e.subject and e.subject in focus_entities:
                is_case_event = True
            elif e.actor and e.actor in focus_entities:
                is_case_event = True
            elif any(ent in focus_entities for ent in e.entities):
                is_case_event = True

            if is_case_event:
                events.append(
                    IntelligenceEvent(
                        installation_id=e.installation_id,
                        event_id=e.event_id,
                        event_type=e.event_type,
                        event_time=e.event_time,
                        actor=e.actor,
                        subject=e.subject,
                        source_system=e.source_system,
                        source_record_id=e.source_record_id,
                        entities=tuple(e.entities or ()),
                        attributes=dict(e.attributes or {}),
                        provenance_digest=e.provenance_digest,
                    )
                )

        # If no normalized intelligence events found, check case snapshot for raw events
        if not events and case_rec.snapshot and isinstance(case_rec.snapshot, dict):
            snap_events = case_rec.snapshot.get("events") or case_rec.snapshot.get("telemetry") or []
            if isinstance(snap_events, list):
                for idx, se in enumerate(snap_events):
                    if isinstance(se, dict):
                        ev_time_raw = se.get("timestamp") or se.get("event_time")
                        try:
                            ev_time = (
                                datetime.fromisoformat(ev_time_raw)
                                if ev_time_raw
                                else case_rec.created_at
                            )
                        except Exception:
                            ev_time = case_rec.created_at
                        events.append(
                            IntelligenceEvent(
                                installation_id=self.installation_id,
                                event_id=str(se.get("event_id") or f"{case_id}-ev-{idx}"),
                                event_type=str(se.get("event_type") or "generic_event"),
                                event_time=ev_time,
                                actor=str(se.get("actor") or "") or None,
                                subject=str(se.get("subject") or "") or None,
                                source_system=str(se.get("source_system") or "core_banking"),
                                attributes=se,
                            )
                        )

        # 4. Build domain CaseFingerprint
        fp = build_case_fingerprint(
            case_id=case_id,
            installation_id=self.installation_id,
            events=events,
            adjudicated_label=adjudicated_label,
        )

        # 5. Persist CaseFingerprintRecord
        evidence_dicts = [e.to_dict() for e in fp.evidence]
        fp_rec = CaseFingerprintRecord(
            case_id=fp.case_id,
            installation_id=fp.installation_id,
            extractor_version=fp.extractor_version,
            features=dict(fp.features),
            evidence=evidence_dicts,
            source_systems=list(fp.source_systems),
            source_coverage=fp.source_coverage,
            total_events=fp.total_events,
            first_event_time=fp.first_event_time,
            last_event_time=fp.last_event_time,
            control_weaknesses=list(fp.control_weaknesses),
            adjudicated_label=fp.adjudicated_label,
            created_at=datetime.now(timezone.utc),
        )
        self.session.merge(fp_rec)

        # Index memory features for fast dimension searching
        for dim, val in fp.features.items():
            ev_ids = []
            src_systems = []
            matching_ev = next((e for e in fp.evidence if e.dimension == dim), None)
            if matching_ev:
                ev_ids = list(matching_ev.event_ids)
                src_systems = list(matching_ev.source_systems)
            feat_rec = CaseMemoryFeatureRecord(
                id=str(uuid.uuid4()),
                installation_id=self.installation_id,
                case_id=case_id,
                dimension=dim,
                feature_value=val,
                event_ids=ev_ids,
                source_systems=src_systems,
                created_at=datetime.now(timezone.utc),
            )
            self.session.add(feat_rec)

        self.session.commit()
        return fp

    def list_fingerprints(self) -> list[CaseFingerprint]:
        """List all case fingerprints within this installation."""
        stmt = (
            select(CaseFingerprintRecord)
            .where(CaseFingerprintRecord.installation_id == self.installation_id)
            .order_by(CaseFingerprintRecord.created_at.desc())
        )
        records = self.session.execute(stmt).scalars().all()
        return [self._record_to_domain_fingerprint(r) for r in records]

    def _record_to_domain_fingerprint(self, rec: CaseFingerprintRecord) -> CaseFingerprint:
        evidence_tuples = []
        if rec.evidence and isinstance(rec.evidence, list):
            for e in rec.evidence:
                if isinstance(e, dict):
                    evidence_tuples.append(
                        FingerprintEvidence(
                            dimension=e.get("dimension", ""),
                            event_ids=tuple(e.get("event_ids", ())),
                            source_systems=tuple(e.get("source_systems", ())),
                        )
                    )

        return CaseFingerprint(
            case_id=rec.case_id,
            installation_id=rec.installation_id,
            extractor_version=rec.extractor_version,
            features=dict(rec.features or {}),
            evidence=tuple(evidence_tuples),
            source_systems=tuple(rec.source_systems or ()),
            source_coverage=rec.source_coverage,
            total_events=rec.total_events,
            first_event_time=rec.first_event_time,
            last_event_time=rec.last_event_time,
            control_weaknesses=tuple(rec.control_weaknesses or ()),
            adjudicated_label=rec.adjudicated_label,
            created_at=rec.created_at,
        )

    # -------------------------------------------------------------------------
    # 2. Pattern Discovery & Curation
    # -------------------------------------------------------------------------

    def discover_candidates(
        self,
        curator_subject: str,
        curator_role: str,
        min_support: int = 2,
    ) -> list[InstitutionalPatternRecord]:
        """Discover candidate fraud patterns from adjudicated cases in this installation."""
        # Ensure all adjudicated cases have fingerprints
        outcomes_stmt = select(SimulationCaseOutcomeRecord).where(
            SimulationCaseOutcomeRecord.installation_id == self.installation_id
        )
        outcomes = self.session.execute(outcomes_stmt).scalars().all()
        for oc in outcomes:
            self.get_or_build_fingerprint(oc.case_id)

        all_fps = self.list_fingerprints()
        candidates = discover_candidate_patterns(
            all_fps,
            installation_id=self.installation_id,
            curator_subject=curator_subject,
            min_cases_support=min_support,
        )

        persisted: list[InstitutionalPatternRecord] = []
        for cand in candidates:
            # Check if pattern already exists
            existing_stmt = select(InstitutionalPatternRecord).where(
                InstitutionalPatternRecord.pattern_id == cand.pattern_id,
                InstitutionalPatternRecord.installation_id == self.installation_id,
            )
            existing = self.session.execute(existing_stmt).scalars().first()
            if not existing:
                rec = InstitutionalPatternRecord(
                    pattern_id=cand.pattern_id,
                    installation_id=cand.installation_id,
                    version=cand.version,
                    title=cand.title,
                    description=cand.description,
                    feature_signature=dict(cand.feature_signature),
                    extractor_version=cand.extractor_version,
                    status=cand.status.value,
                    curator_subject=cand.curator,
                    limitations=list(cand.limitations),
                    control_weaknesses=list(cand.control_weaknesses),
                    independent_source_systems=list(cand.independent_source_systems),
                    supporting_event_ids=list(cand.supporting_event_ids),
                    created_at=cand.created_at,
                )
                self.session.add(rec)

                # Add case links
                for fc_id in cand.confirmed_fraud_case_ids:
                    self.session.add(
                        PatternCaseLinkRecord(
                            id=str(uuid.uuid4()),
                            installation_id=self.installation_id,
                            pattern_id=cand.pattern_id,
                            case_id=fc_id,
                            case_role="confirmed_fraud",
                            created_at=datetime.now(timezone.utc),
                        )
                    )
                for lc_id in cand.confirmed_legitimate_case_ids:
                    self.session.add(
                        PatternCaseLinkRecord(
                            id=str(uuid.uuid4()),
                            installation_id=self.installation_id,
                            pattern_id=cand.pattern_id,
                            case_id=lc_id,
                            case_role="confirmed_legitimate",
                            created_at=datetime.now(timezone.utc),
                        )
                    )

                append_audit(
                    self.session,
                    installation_id=self.installation_id,
                    actor_subject=curator_subject,
                    actor_role=curator_role,
                    action="candidate_pattern_discovered",
                    target_type="institutional_pattern",
                    target_id=cand.pattern_id,
                    safe_metadata={
                        "pattern_id": cand.pattern_id,
                        "pattern_version": cand.version,
                        "lifecycle_status": cand.status.value,
                        "installation_id": self.installation_id,
                    },
                )
                persisted.append(rec)

        self.session.commit()
        return self.list_patterns(status_filter="candidate")

    def create_custom_pattern(
        self,
        payload: InstitutionalPatternCreate,
        curator_subject: str,
        curator_role: str,
    ) -> InstitutionalPatternRecord:
        """Curate an institutional pattern candidate manually."""
        existing_stmt = select(InstitutionalPatternRecord).where(
            InstitutionalPatternRecord.pattern_id == payload.pattern_id,
            InstitutionalPatternRecord.installation_id == self.installation_id,
        )
        if self.session.execute(existing_stmt).scalars().first():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Pattern '{payload.pattern_id}' already exists in installation",
            )

        now = datetime.now(timezone.utc)
        rec = InstitutionalPatternRecord(
            pattern_id=payload.pattern_id,
            installation_id=self.installation_id,
            version=1,
            title=payload.title,
            description=payload.description,
            feature_signature=dict(payload.feature_signature),
            extractor_version="v1",
            status="candidate",
            curator_subject=curator_subject,
            limitations=list(payload.limitations),
            control_weaknesses=list(payload.control_weaknesses),
            independent_source_systems=list(payload.independent_source_systems),
            supporting_event_ids=[],
            created_at=now,
        )
        self.session.add(rec)

        for fc_id in payload.confirmed_fraud_case_ids:
            self.session.add(
                PatternCaseLinkRecord(
                    id=str(uuid.uuid4()),
                    installation_id=self.installation_id,
                    pattern_id=payload.pattern_id,
                    case_id=fc_id,
                    case_role="confirmed_fraud",
                    created_at=now,
                )
            )
        for lc_id in payload.confirmed_legitimate_case_ids:
            self.session.add(
                PatternCaseLinkRecord(
                    id=str(uuid.uuid4()),
                    installation_id=self.installation_id,
                    pattern_id=payload.pattern_id,
                    case_id=lc_id,
                    case_role="confirmed_legitimate",
                    created_at=now,
                )
            )

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=curator_subject,
            actor_role=curator_role,
            action="custom_pattern_created",
            target_type="institutional_pattern",
            target_id=payload.pattern_id,
            safe_metadata={
                "pattern_id": payload.pattern_id,
                "pattern_version": 1,
                "lifecycle_status": "candidate",
                "installation_id": self.installation_id,
            },
        )
        self.session.commit()
        return rec

    def list_patterns(self, status_filter: str | None = None) -> list[InstitutionalPatternRecord]:
        """List institutional patterns in this installation."""
        stmt = select(InstitutionalPatternRecord).where(
            InstitutionalPatternRecord.installation_id == self.installation_id
        )
        if status_filter:
            stmt = stmt.where(InstitutionalPatternRecord.status == status_filter)
        stmt = stmt.order_by(InstitutionalPatternRecord.created_at.desc())
        return list(self.session.execute(stmt).scalars().all())

    def get_pattern(self, pattern_id: str) -> InstitutionalPatternRecord:
        """Get specific pattern by ID."""
        stmt = select(InstitutionalPatternRecord).where(
            InstitutionalPatternRecord.pattern_id == pattern_id,
            InstitutionalPatternRecord.installation_id == self.installation_id,
        )
        rec = self.session.execute(stmt).scalars().first()
        if not rec:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Pattern '{pattern_id}' not found in installation",
            )
        return rec

    def _record_to_domain_pattern(self, rec: InstitutionalPatternRecord) -> InstitutionalPattern:
        # Load linked cases
        links_stmt = select(PatternCaseLinkRecord).where(
            PatternCaseLinkRecord.pattern_id == rec.pattern_id,
            PatternCaseLinkRecord.installation_id == self.installation_id,
        )
        links = self.session.execute(links_stmt).scalars().all()
        fraud_cases = [l.case_id for l in links if l.case_role == "confirmed_fraud"]
        legit_cases = [l.case_id for l in links if l.case_role == "confirmed_legitimate"]

        return InstitutionalPattern(
            pattern_id=rec.pattern_id,
            installation_id=rec.installation_id,
            version=rec.version,
            title=rec.title,
            description=rec.description,
            feature_signature=dict(rec.feature_signature or {}),
            confirmed_fraud_case_ids=tuple(fraud_cases),
            confirmed_legitimate_case_ids=tuple(legit_cases),
            independent_source_systems=tuple(rec.independent_source_systems or ()),
            status=PatternStatus(rec.status),
            created_by=rec.curator_subject,
            created_at=rec.created_at,
            extractor_version=rec.extractor_version,
            supporting_event_ids=tuple(rec.supporting_event_ids or ()),
            control_weaknesses=tuple(rec.control_weaknesses or ()),
            curator=rec.curator_subject,
            reviewer=rec.reviewer_subject,
            reviewed_at=rec.reviewed_at,
            validation_rationale=rec.validation_rationale,
            limitations=tuple(rec.limitations or ()),
            updated_at=rec.updated_at,
        )

    # -------------------------------------------------------------------------
    # 3. Pattern Governance & Dual Control
    # -------------------------------------------------------------------------

    def evaluate_pattern_for_validation(self, pattern_id: str) -> PatternValidationResult:
        """Evaluate candidate pattern against institutional validation policy."""
        rec = self.get_pattern(pattern_id)
        domain_pattern = self._record_to_domain_pattern(rec)
        return evaluate_pattern(domain_pattern, PatternValidationPolicy())

    def review_pattern_lifecycle(
        self,
        pattern_id: str,
        action: str,
        rationale: str,
        actor_subject: str,
        actor_role: str,
    ) -> InstitutionalPatternRecord:
        """Perform a dual-control review action on an institutional pattern."""
        rec = self.get_pattern(pattern_id)
        domain_pattern = self._record_to_domain_pattern(rec)
        now = datetime.now(timezone.utc)

        if action == "submit_for_review":
            if rec.status != "candidate":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Pattern in status '{rec.status}' cannot be submitted for review",
                )
            rec.status = "under_review"
            rec.updated_at = now

        elif action == "validate":
            try:
                approved = approve_pattern(
                    domain_pattern,
                    reviewer_subject=actor_subject,
                    rationale=rationale,
                    policy=PatternValidationPolicy(),
                )
            except ValueError as ex:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ex))

            rec.status = approved.status.value
            rec.reviewer_subject = approved.reviewer
            rec.reviewed_at = approved.reviewed_at
            rec.validation_rationale = approved.validation_rationale
            rec.updated_at = now

            # Save immutable version record
            ver_rec = PatternVersionRecord(
                id=str(uuid.uuid4()),
                installation_id=self.installation_id,
                pattern_id=rec.pattern_id,
                version=rec.version,
                title=rec.title,
                description=rec.description,
                feature_signature=dict(rec.feature_signature or {}),
                status=rec.status,
                changed_by=actor_subject,
                change_summary=f"Pattern validated: {rationale}",
                created_at=now,
            )
            self.session.add(ver_rec)

        elif action == "reject":
            rejected = reject_pattern(domain_pattern, reviewer_subject=actor_subject, rationale=rationale)
            rec.status = rejected.status.value
            rec.reviewer_subject = rejected.reviewer
            rec.reviewed_at = rejected.reviewed_at
            rec.validation_rationale = rejected.validation_rationale
            rec.updated_at = now

        elif action == "suspend":
            suspended = suspend_pattern(domain_pattern, actor_subject=actor_subject, rationale=rationale)
            rec.status = suspended.status.value
            rec.updated_at = now

        elif action == "reinstate":
            reinstated = reinstate_pattern(domain_pattern, actor_subject=actor_subject, rationale=rationale)
            rec.status = reinstated.status.value
            rec.updated_at = now

        elif action == "retire":
            retired = retire_pattern(domain_pattern, actor_subject=actor_subject, rationale=rationale)
            rec.status = retired.status.value
            rec.updated_at = now
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported review action '{action}'",
            )

        # Record review audit
        eval_res = evaluate_pattern(domain_pattern)
        review_rec = PatternReviewRecord(
            review_id=str(uuid.uuid4()),
            installation_id=self.installation_id,
            pattern_id=rec.pattern_id,
            pattern_version=rec.version,
            reviewer_subject=actor_subject,
            action=action,
            rationale=rationale,
            evaluation_metrics=eval_res.to_dict(),
            created_at=now,
        )
        self.session.add(review_rec)

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action=f"pattern_{action}",
            target_type="institutional_pattern",
            target_id=rec.pattern_id,
            safe_metadata={
                "pattern_id": rec.pattern_id,
                "pattern_version": rec.version,
                "review_id": review_rec.review_id,
                "decision": action,
                "lifecycle_status": rec.status,
                "installation_id": self.installation_id,
            },
        )
        self.session.commit()
        return rec

    def list_pattern_versions(self, pattern_id: str) -> list[PatternVersionRecord]:
        """List historical immutable versions of a pattern."""
        stmt = (
            select(PatternVersionRecord)
            .where(
                PatternVersionRecord.pattern_id == pattern_id,
                PatternVersionRecord.installation_id == self.installation_id,
            )
            .order_by(PatternVersionRecord.version.desc())
        )
        return list(self.session.execute(stmt).scalars().all())

    # -------------------------------------------------------------------------
    # 4. Historical Case & Pattern Matching
    # -------------------------------------------------------------------------

    def search_similar_historical_cases(
        self,
        case_id: str,
        limit: int = 10,
        min_coverage: float = 0.1,
    ) -> list[CaseSimilarity]:
        """Search historical cases within this installation for explainable feature similarity."""
        curr_fp = self.get_or_build_fingerprint(case_id)

        # Ensure historical cases in installation have fingerprints built
        cases_stmt = select(EnterpriseCase.id).where(
            EnterpriseCase.installation_id == self.installation_id,
            EnterpriseCase.id != case_id,
        )
        for other_id in self.session.execute(cases_stmt).scalars():
            self.get_or_build_fingerprint(other_id)

        all_fps = self.list_fingerprints()

        matches = retrieve_similar_historical_cases(
            current=curr_fp,
            historical_fingerprints=all_fps,
            min_coverage=min_coverage,
            limit=limit,
        )

        # Persist match evaluation audit
        for m in matches:
            mr_rec = MemoryMatchResultRecord(
                match_id=str(uuid.uuid4()),
                installation_id=self.installation_id,
                query_case_id=case_id,
                matched_type="case",
                target_id=m.historical_case_id,
                similarity_index=m.similarity_index,
                comparison_coverage=m.comparison_coverage,
                matched_features=list(m.matched_features),
                different_features=list(m.different_features),
                target_outcome=m.historical_outcome,
                created_at=datetime.now(timezone.utc),
            )
            self.session.add(mr_rec)
        self.session.commit()

        return matches

    def match_case_against_patterns(
        self,
        case_id: str,
        min_coverage: float = 0.1,
    ) -> list[PatternMatch]:
        """Match an investigation against institutional patterns in this installation."""
        curr_fp = self.get_or_build_fingerprint(case_id)
        patterns_recs = self.list_patterns()
        domain_patterns = [self._record_to_domain_pattern(r) for r in patterns_recs]

        return match_case_against_patterns(
            current=curr_fp,
            patterns=domain_patterns,
            min_coverage=min_coverage,
        )

    # -------------------------------------------------------------------------
    # 5. Memory Overview & Health
    # -------------------------------------------------------------------------

    def get_overview(self) -> dict[str, Any]:
        """Retrieve aggregated institutional memory health metrics."""
        # 1. Adjudicated case count
        adjudicated_count = (
            self.session.query(func.count(SimulationCaseOutcomeRecord.case_id))
            .filter(
                SimulationCaseOutcomeRecord.installation_id == self.installation_id,
                SimulationCaseOutcomeRecord.label.in_(("confirmed_fraud", "confirmed_legitimate")),
            )
            .scalar()
            or 0
        )

        # 2. Pattern counts by status
        pat_status_counts = dict(
            self.session.query(
                InstitutionalPatternRecord.status,
                func.count(InstitutionalPatternRecord.pattern_id),
            )
            .filter(InstitutionalPatternRecord.installation_id == self.installation_id)
            .group_by(InstitutionalPatternRecord.status)
            .all()
        )

        # 3. Fingerprints count and average coverage
        fps = self.list_fingerprints()
        avg_coverage = (
            round(sum(fp.source_coverage for fp in fps) / len(fps), 4) if fps else 0.0
        )

        # 4. Recent reviews
        rev_stmt = (
            select(PatternReviewRecord)
            .where(PatternReviewRecord.installation_id == self.installation_id)
            .order_by(PatternReviewRecord.created_at.desc())
            .limit(5)
        )
        recent_revs = list(self.session.execute(rev_stmt).scalars().all())

        return {
            "adjudicated_case_count": adjudicated_count,
            "validated_pattern_count": pat_status_counts.get("validated", 0),
            "candidate_pattern_count": pat_status_counts.get("candidate", 0),
            "under_review_pattern_count": pat_status_counts.get("under_review", 0),
            "suspended_pattern_count": pat_status_counts.get("suspended", 0),
            "retired_pattern_count": pat_status_counts.get("retired", 0),
            "average_source_coverage": avg_coverage,
            "total_fingerprinted_cases": len(fps),
            "recent_reviews": recent_revs,
        }
