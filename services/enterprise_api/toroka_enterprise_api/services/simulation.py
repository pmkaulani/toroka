from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise.intelligence.models import (
    SimulationApprovalRecord,
    SimulationCaseOutcomeRecord,
    SimulationRunRecord,
    SimulationStrategyRecord,
    IntelligenceEventRecord,
)
from toroka_enterprise.intelligence.simulation import (
    CaseOutcome,
    OutcomeLabel,
    ReplayObservation,
    SimulationMetrics,
    SimulationStrategy,
    calculate_metrics,
    calculate_metrics_delta,
    compare_strategies,
    replay_strategy,
)
from ..persistence.audit import append_audit
from ..persistence.models import EnterpriseCase
from ..simulation_schemas import (
    CaseOutcomeCreate,
    SimulationApprovalRequestCreate,
    SimulationApprovalReviewCreate,
    SimulationRunRequest,
    SimulationStrategyCreate,
)


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class SimulationService:
    """Service orchestrating counterfactual detection strategy evaluation and governance."""

    def __init__(self, session: Session, installation_id: str):
        self.session = session
        self.installation_id = installation_id

    # -------------------------------------------------------------------------
    # 1. Strategy Version Management
    # -------------------------------------------------------------------------

    def create_strategy(
        self,
        data: SimulationStrategyCreate,
        creator_subject: str,
        creator_role: str,
    ) -> SimulationStrategyRecord:
        """Create a new version of an immutable detection strategy."""
        # Find latest version for this strategy_id in this installation
        stmt = (
            select(func.max(SimulationStrategyRecord.version))
            .where(
                SimulationStrategyRecord.installation_id == self.installation_id,
                SimulationStrategyRecord.strategy_id == data.strategy_id,
            )
        )
        max_v = self.session.execute(stmt).scalar()
        next_version = (max_v or 0) + 1

        record = SimulationStrategyRecord(
            strategy_id=data.strategy_id,
            version=next_version,
            installation_id=self.installation_id,
            title=data.title,
            description=data.description,
            rules_enabled=list(data.rules_enabled),
            parameters=dict(data.parameters),
            min_severity=data.min_severity,
            min_confidence=data.min_confidence,
            status="draft",
            created_by=creator_subject,
            created_at=datetime.now(timezone.utc),
        )
        self.session.add(record)

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=creator_subject,
            actor_role=creator_role,
            action="strategy_created",
            target_type="strategy",
            target_id=f"{data.strategy_id}:v{next_version}",
            safe_metadata={
                "strategy_id": data.strategy_id,
                "strategy_version": next_version,
                "installation_id": self.installation_id,
            },
        )
        self.session.commit()
        return record

    def list_strategies(self) -> list[SimulationStrategyRecord]:
        """List all strategies and versions for this installation."""
        stmt = (
            select(SimulationStrategyRecord)
            .where(SimulationStrategyRecord.installation_id == self.installation_id)
            .order_by(
                SimulationStrategyRecord.strategy_id.asc(),
                SimulationStrategyRecord.version.desc(),
            )
        )
        return list(self.session.execute(stmt).scalars().all())

    def get_strategy(
        self,
        strategy_id: str,
        version: int | None = None,
    ) -> SimulationStrategyRecord:
        """Retrieve a specific version or the latest version of a strategy."""
        stmt = select(SimulationStrategyRecord).where(
            SimulationStrategyRecord.installation_id == self.installation_id,
            SimulationStrategyRecord.strategy_id == strategy_id,
        )
        if version is not None:
            stmt = stmt.where(SimulationStrategyRecord.version == version)
        else:
            stmt = stmt.order_by(SimulationStrategyRecord.version.desc())

        record = self.session.execute(stmt).scalars().first()
        if not record:
            ver_str = f" v{version}" if version else ""
            raise HTTPException(
                status_code=404,
                detail=f"Strategy '{strategy_id}'{ver_str} not found in installation",
            )
        return record

    # -------------------------------------------------------------------------
    # 2. Case Outcome Adjudication (Ground Truth)
    # -------------------------------------------------------------------------

    def adjudicate_case_outcome(
        self,
        data: CaseOutcomeCreate,
        adjudicator_subject: str,
        adjudicator_role: str,
    ) -> SimulationCaseOutcomeRecord:
        """Adjudicate the historical ground truth outcome for a case."""
        # Validate label
        try:
            valid_label = OutcomeLabel(data.label)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Invalid outcome label '{data.label}'. "
                    f"Must be one of: {[l.value for l in OutcomeLabel]}"
                ),
            )

        now = datetime.now(timezone.utc)
        record = self.session.get(
            SimulationCaseOutcomeRecord,
            (data.case_id, self.installation_id),
        )
        if record is None:
            record = SimulationCaseOutcomeRecord(
                case_id=data.case_id,
                installation_id=self.installation_id,
                label=valid_label.value,
                first_fraud_event_time=_ensure_utc(data.first_fraud_event_time),
                adjudicated_at=now,
                adjudicated_by=adjudicator_subject,
                notes=data.notes,
            )
            self.session.add(record)
        else:
            record.label = valid_label.value
            if data.first_fraud_event_time is not None:
                record.first_fraud_event_time = _ensure_utc(data.first_fraud_event_time)
            record.adjudicated_at = now
            record.adjudicated_by = adjudicator_subject
            if data.notes is not None:
                record.notes = data.notes

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=adjudicator_subject,
            actor_role=adjudicator_role,
            action="case_outcome_adjudicated",
            target_type="case_outcome",
            target_id=data.case_id,
            safe_metadata={
                "case_id": data.case_id,
                "label": valid_label.value,
                "installation_id": self.installation_id,
            },
        )
        self.session.commit()
        return record

    def list_case_outcomes(self) -> list[SimulationCaseOutcomeRecord]:
        """List all ground truth adjudicated case outcomes in this installation."""
        stmt = (
            select(SimulationCaseOutcomeRecord)
            .where(SimulationCaseOutcomeRecord.installation_id == self.installation_id)
            .order_by(SimulationCaseOutcomeRecord.adjudicated_at.desc())
        )
        return list(self.session.execute(stmt).scalars().all())

    # -------------------------------------------------------------------------
    # 3. Replay Simulation Execution
    # -------------------------------------------------------------------------

    def run_simulation(
        self,
        request: SimulationRunRequest,
        executor_subject: str,
        executor_role: str,
    ) -> SimulationRunRecord:
        """Execute counterfactual historical replay of a strategy, optionally comparing against a baseline."""
        # 1. Load proposed strategy
        prop_rec = self.get_strategy(
            request.strategy_id,
            request.strategy_version,
        )
        prop_strat = SimulationStrategy(
            strategy_id=prop_rec.strategy_id,
            version=prop_rec.version,
            title=prop_rec.title,
            description=prop_rec.description,
            rules_enabled=tuple(prop_rec.rules_enabled or ()),
            parameters=dict(prop_rec.parameters or {}),
            min_severity=prop_rec.min_severity,
            min_confidence=prop_rec.min_confidence,
            created_at=prop_rec.created_at,
            created_by=prop_rec.created_by,
            status=prop_rec.status,
        )

        # 2. Load baseline strategy if requested
        base_strat: SimulationStrategy | None = None
        base_rec: SimulationStrategyRecord | None = None
        if request.baseline_strategy_id:
            base_rec = self.get_strategy(
                request.baseline_strategy_id,
                request.baseline_strategy_version,
            )
            base_strat = SimulationStrategy(
                strategy_id=base_rec.strategy_id,
                version=base_rec.version,
                title=base_rec.title,
                description=base_rec.description,
                rules_enabled=tuple(base_rec.rules_enabled or ()),
                parameters=dict(base_rec.parameters or {}),
                min_severity=base_rec.min_severity,
                min_confidence=base_rec.min_confidence,
                created_at=base_rec.created_at,
                created_by=base_rec.created_by,
                status=base_rec.status,
            )

        # 3. Determine cohort cases
        cohort_ids: set[str] = set()
        if request.cohort_case_ids:
            cohort_ids = set(request.cohort_case_ids)
        else:
            # Query all adjudicated case outcomes
            outcomes_stmt = select(SimulationCaseOutcomeRecord.case_id).where(
                SimulationCaseOutcomeRecord.installation_id == self.installation_id
            )
            for c_id in self.session.execute(outcomes_stmt).scalars():
                cohort_ids.add(c_id)

            # Query all cases in EnterpriseCase
            cases_stmt = select(EnterpriseCase.id).where(
                EnterpriseCase.installation_id == self.installation_id
            )
            for c_id in self.session.execute(cases_stmt).scalars():
                cohort_ids.add(c_id)

        # 4. Build case outcomes map
        outcome_records_stmt = select(SimulationCaseOutcomeRecord).where(
            SimulationCaseOutcomeRecord.installation_id == self.installation_id,
            SimulationCaseOutcomeRecord.case_id.in_(cohort_ids) if cohort_ids else True,
        )
        outcome_records = self.session.execute(outcome_records_stmt).scalars().all()
        outcomes_by_case: dict[str, CaseOutcome] = {}
        for rec in outcome_records:
            try:
                l = OutcomeLabel(rec.label)
            except Exception:
                l = OutcomeLabel.UNLABELLED
            outcomes_by_case[rec.case_id] = CaseOutcome(
                case_id=rec.case_id,
                label=l,
                first_fraud_event_time=rec.first_fraud_event_time,
                adjudicated_at=rec.adjudicated_at,
                adjudicated_by=rec.adjudicated_by,
                notes=rec.notes,
            )

        # Ensure all cohort cases have at least an UNLABELLED outcome
        for c_id in cohort_ids:
            if c_id not in outcomes_by_case:
                outcomes_by_case[c_id] = CaseOutcome(
                    case_id=c_id,
                    label=OutcomeLabel.UNLABELLED,
                )

        # 5. Load and scope case events
        cases_events: dict[str, list[ReplayObservation]] = {c: [] for c in cohort_ids}
        if cohort_ids:
            # Load case entities for focus scoping
            case_entity_map: dict[str, set[str]] = {}
            c_records_stmt = select(EnterpriseCase).where(
                EnterpriseCase.installation_id == self.installation_id,
                EnterpriseCase.id.in_(cohort_ids),
            )
            for cr in self.session.execute(c_records_stmt).scalars():
                f_ents = {cr.focus} if cr.focus else set()
                if cr.snapshot and isinstance(cr.snapshot, dict):
                    for k in ("staff_ref", "customer_ref", "account_ref"):
                        val = cr.snapshot.get(k)
                        if val:
                            f_ents.add(str(val))
                case_entity_map[cr.id] = f_ents

            # Query intelligence events for installation
            events_stmt = (
                select(IntelligenceEventRecord)
                .where(IntelligenceEventRecord.installation_id == self.installation_id)
                .order_by(IntelligenceEventRecord.event_time.asc())
            )
            all_evs = self.session.execute(events_stmt).scalars().all()

            for ev in all_evs:
                ev_case_id = ev.attributes.get("case_id") if ev.attributes else None
                # Check which case(s) this event belongs to
                assigned_cases: set[str] = set()
                if ev_case_id and ev_case_id in cases_events:
                    assigned_cases.add(ev_case_id)

                # Match by focus entity
                for c_id, f_ents in case_entity_map.items():
                    if ev.actor in f_ents or ev.subject in f_ents:
                        assigned_cases.add(c_id)
                    elif ev.entities and any(e in f_ents for e in ev.entities):
                        assigned_cases.add(c_id)

                for target_cid in assigned_cases:
                    ie = IntelligenceEvent(
                        installation_id=ev.installation_id,
                        event_id=ev.event_id,
                        event_type=ev.event_type,
                        event_time=ev.event_time,
                        actor=ev.actor,
                        subject=ev.subject,
                        source_system=ev.source_system,
                        source_record_id=ev.source_record_id,
                        entities=tuple(ev.entities or ()),
                        attributes=dict(ev.attributes or {}),
                        provenance_digest=ev.provenance_digest,
                    )
                    obs = ReplayObservation.from_intelligence_event(
                        event=ie,
                        case_id=target_cid,
                    )
                    cases_events[target_cid].append(obs)

        # 6. Execute replay
        cutoff_utc = _ensure_utc(request.simulation_cutoff)
        sim_id = f"sim_{uuid.uuid4().hex[:12]}"

        if base_strat is not None:
            comparison = compare_strategies(
                baseline_strategy=base_strat,
                proposed_strategy=prop_strat,
                cases_events=cases_events,
                case_outcomes=outcomes_by_case,
                simulation_cutoff=cutoff_utc,
                installation_id=self.installation_id,
            )
            prop_result = comparison.proposed_run
            base_metrics_dict = comparison.baseline_run.metrics.to_dict()
            delta_dict = comparison.delta.to_dict()
        else:
            prop_result = replay_strategy(
                strategy=prop_strat,
                cases_events=cases_events,
                case_outcomes=outcomes_by_case,
                simulation_cutoff=cutoff_utc,
                installation_id=self.installation_id,
                simulation_id=sim_id,
            )
            base_metrics_dict = None
            delta_dict = None

        # 7. Persist simulation run
        sim_rec = SimulationRunRecord(
            simulation_id=sim_id,
            installation_id=self.installation_id,
            strategy_id=prop_strat.strategy_id,
            strategy_version=prop_strat.version,
            baseline_strategy_id=base_strat.strategy_id if base_strat else None,
            baseline_strategy_version=base_strat.version if base_strat else None,
            executed_by=executor_subject,
            executed_at=datetime.now(timezone.utc),
            simulation_cutoff=cutoff_utc,
            metrics=prop_result.metrics.to_dict(),
            baseline_metrics=base_metrics_dict,
            delta=delta_dict,
            total_events_replayed=prop_result.total_events_replayed,
            delayed_events_filtered=prop_result.delayed_events_filtered,
            case_detections={
                c_id: [d.to_dict() for d in dets]
                for c_id, dets in prop_result.case_detections.items()
            },
        )
        self.session.add(sim_rec)

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=executor_subject,
            actor_role=executor_role,
            action="simulation_executed",
            target_type="simulation_run",
            target_id=sim_id,
            safe_metadata={
                "simulation_id": sim_id,
                "strategy_id": prop_strat.strategy_id,
                "strategy_version": prop_strat.version,
                "installation_id": self.installation_id,
            },
        )
        self.session.commit()
        return sim_rec

    def list_simulation_runs(self) -> list[SimulationRunRecord]:
        """List historical simulation runs in reverse chronological order."""
        stmt = (
            select(SimulationRunRecord)
            .where(SimulationRunRecord.installation_id == self.installation_id)
            .order_by(SimulationRunRecord.executed_at.desc())
        )
        return list(self.session.execute(stmt).scalars().all())

    def get_simulation_run(self, simulation_id: str) -> SimulationRunRecord:
        """Retrieve a specific simulation run result by ID."""
        rec = self.session.get(
            SimulationRunRecord,
            (simulation_id, self.installation_id),
        )
        if not rec:
            raise HTTPException(
                status_code=404,
                detail=f"Simulation run '{simulation_id}' not found",
            )
        return rec

    # -------------------------------------------------------------------------
    # 4. Strategy Promotion Approval (Dual-Control Maker-Checker)
    # -------------------------------------------------------------------------

    def request_approval(
        self,
        data: SimulationApprovalRequestCreate,
        requester_subject: str,
        requester_role: str,
    ) -> SimulationApprovalRecord:
        """Submit a strategy version for promotion / shadow deployment review."""
        strat = self.get_strategy(data.strategy_id, data.strategy_version)

        # Check if already pending approval
        existing_stmt = select(SimulationApprovalRecord).where(
            SimulationApprovalRecord.installation_id == self.installation_id,
            SimulationApprovalRecord.strategy_id == strat.strategy_id,
            SimulationApprovalRecord.strategy_version == strat.version,
            SimulationApprovalRecord.status == "pending",
        )
        if self.session.execute(existing_stmt).scalars().first():
            raise HTTPException(
                status_code=409,
                detail=f"An approval request is already pending for strategy '{strat.strategy_id}' v{strat.version}",
            )

        appr_id = f"appr_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)

        appr_rec = SimulationApprovalRecord(
            approval_id=appr_id,
            installation_id=self.installation_id,
            strategy_id=strat.strategy_id,
            strategy_version=strat.version,
            requester_subject=requester_subject,
            requested_at=now,
            request_rationale=data.request_rationale,
            simulation_run_id=data.simulation_run_id,
            status="pending",
        )
        self.session.add(appr_rec)

        # Update strategy status
        strat.status = "pending_review"

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=requester_subject,
            actor_role=requester_role,
            action="approval_requested",
            target_type="strategy_approval",
            target_id=appr_id,
            safe_metadata={
                "approval_id": appr_id,
                "strategy_id": strat.strategy_id,
                "strategy_version": strat.version,
                "installation_id": self.installation_id,
            },
        )
        self.session.commit()
        return appr_rec

    def review_approval(
        self,
        approval_id: str,
        data: SimulationApprovalReviewCreate,
        reviewer_subject: str,
        reviewer_role: str,
    ) -> SimulationApprovalRecord:
        """Review and approve or reject a strategy promotion under dual control."""
        appr_rec = self.session.get(
            SimulationApprovalRecord,
            (approval_id, self.installation_id),
        )
        if not appr_rec:
            raise HTTPException(
                status_code=404,
                detail=f"Approval request '{approval_id}' not found",
            )

        if appr_rec.status != "pending":
            raise HTTPException(
                status_code=400,
                detail=f"Approval request '{approval_id}' has already been reviewed ({appr_rec.status})",
            )

        # STRICT DUAL CONTROL: Maker cannot be Checker!
        if reviewer_subject == appr_rec.requester_subject:
            raise HTTPException(
                status_code=403,
                detail="Dual control violation: Requester cannot approve their own strategy submission",
            )

        decision = data.decision.lower()
        if decision not in {"approved", "rejected"}:
            raise HTTPException(
                status_code=400,
                detail="Review decision must be 'approved' or 'rejected'",
            )

        now = datetime.now(timezone.utc)
        appr_rec.status = decision
        appr_rec.reviewer_subject = reviewer_subject
        appr_rec.reviewed_at = now
        appr_rec.review_decision = decision
        appr_rec.review_notes = data.notes

        strat = self.get_strategy(appr_rec.strategy_id, appr_rec.strategy_version)
        strat.status = "approved" if decision == "approved" else "rejected"

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=reviewer_subject,
            actor_role=reviewer_role,
            action="approval_reviewed",
            target_type="strategy_approval",
            target_id=approval_id,
            safe_metadata={
                "approval_id": approval_id,
                "decision": decision,
                "installation_id": self.installation_id,
            },
        )
        self.session.commit()
        return appr_rec

    def list_approvals(self) -> list[SimulationApprovalRecord]:
        """List all strategy approval requests."""
        stmt = (
            select(SimulationApprovalRecord)
            .where(SimulationApprovalRecord.installation_id == self.installation_id)
            .order_by(SimulationApprovalRecord.requested_at.desc())
        )
        return list(self.session.execute(stmt).scalars().all())
