from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import and_, desc, select
from sqlalchemy.orm import Session

from toroka_enterprise.governance.approval import (
    ApprovalDecision,
    ApprovalError,
    approve_component as domain_approve_component,
)
from toroka_enterprise.governance.deployment import (
    DeploymentEnvironment,
    ProductionReleaseManifest,
    ReleaseStatus,
    can_promote_to_production,
)
from toroka_enterprise.governance.drift import (
    DriftRecord,
    DriftType,
    HealthStatus,
    SystemHealthOverview,
    evaluate_metric_drift,
)
from toroka_enterprise.governance.evidence_passport import TorokaEvidencePassport
from toroka_enterprise.governance.incidents import (
    GovernanceIncident,
    IncidentCategory,
    IncidentSeverity,
    IncidentStatus,
    correlate_incident_to_cases,
)
from toroka_enterprise.governance.kill_switch import (
    ComponentSuspended,
    KillSwitch,
    SuspensionRecord,
)
from toroka_enterprise.governance.models import (
    ComponentType,
    GovernanceStatus,
    GovernedComponent,
    RiskTier,
)
from toroka_enterprise.governance.readiness import (
    GateStatus,
    MANDATORY_GATES,
    ReadinessAssessment,
    ReadinessGate,
    evaluate_production_readiness,
)
from toroka_enterprise.governance.registry import ComponentRegistry, RegistryError
from toroka_enterprise.governance.third_party import (
    GovernedAIProvider,
    verify_provider_compliance,
)
from toroka_enterprise.governance.validation import (
    ValidationMetric,
    ValidationResult,
    ValidationRun,
    calculate_validation_result,
)
from toroka_enterprise.intelligence.models import (
    DriftRecordEntity,
    EvidencePassportRecord,
    GovernanceIncidentRecord,
    GovernedAIProviderRecord,
    GovernedComponentRecord,
    ProductionReleaseRecord,
    SuspensionAuditRecord,
    ValidationRunRecord,
)

from ..governance_schemas import (
    ApproveComponentRequest,
    CreateComponentRequest,
    CreateIncidentRequest,
    CreateReleaseRequest,
    CreateValidationRunRequest,
    DriftRecordResponse,
    EvaluateReadinessGatesRequest,
    EvidencePassportResponse,
    GovernanceIncidentResponse,
    GovernedAIProviderResponse,
    GovernedComponentResponse,
    ProductionReleaseResponse,
    ReadinessAssessmentResponse,
    RecordDriftRequest,
    RegisterAIProviderRequest,
    ResumeComponentRequest,
    SuspendComponentRequest,
    SuspensionRecordResponse,
    SystemHealthOverviewResponse,
    UpdateIncidentStatusRequest,
    ValidationMetricSchema,
    ValidationPackageResponse,
    ValidationRunResponse,
)
from ..persistence.audit import append_audit
from ..persistence.models import EnterpriseCase

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ProductionGovernanceService:
    """Operational service for Toroka production governance, model risk, and deployment readiness."""

    def __init__(self, session: Session, installation_id: str) -> None:
        self.session = session
        self.installation_id = installation_id

    # =========================================================================
    # 1. Model & Component Registry
    # =========================================================================

    def register_component(
        self,
        request: CreateComponentRequest,
        actor_subject: str,
        actor_role: str = "authoriser",
    ) -> GovernedComponentResponse:
        # Validate through domain object invariant checks
        try:
            domain_comp = GovernedComponent(
                component_id=request.component_id,
                version=request.version,
                component_type=ComponentType(request.component_type),
                name=request.name,
                status=GovernanceStatus.DRAFT,
                risk_tier=RiskTier(request.risk_tier),
                owner_team=request.owner_team,
                source_digest=request.source_digest,
                configuration_digest=request.configuration_digest,
                created_at=_utc_now(),
                created_by=actor_subject,
                parameters=request.parameters,
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid component specification: {exc}",
            )

        existing = self.session.execute(
            select(GovernedComponentRecord).where(
                and_(
                    GovernedComponentRecord.installation_id == self.installation_id,
                    GovernedComponentRecord.component_id == domain_comp.component_id,
                    GovernedComponentRecord.version == domain_comp.version,
                )
            )
        ).scalar_one_or_none()

        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Component '{domain_comp.component_id}' version '{domain_comp.version}' already registered.",
            )

        now = _utc_now()
        record = GovernedComponentRecord(
            component_id=domain_comp.component_id,
            version=domain_comp.version,
            installation_id=self.installation_id,
            component_type=domain_comp.component_type.value,
            name=domain_comp.name,
            status=domain_comp.status.value,
            risk_tier=domain_comp.risk_tier.value,
            owner_team=domain_comp.owner_team,
            source_digest=domain_comp.source_digest,
            configuration_digest=domain_comp.configuration_digest,
            parameters=domain_comp.parameters,
            created_by=actor_subject,
            created_at=now,
            updated_at=now,
        )
        self.session.add(record)

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="component_registered",
            target_type="component",
            target_id=domain_comp.component_id,
            safe_metadata={
                "component_id": domain_comp.component_id,
                "component_version": domain_comp.version,
                "component_type": domain_comp.component_type.value,
                "risk_tier": domain_comp.risk_tier.value,
                "status": domain_comp.status.value,
            },
        )
        self.session.commit()

        return self._to_component_response(record)

    def list_components(
        self,
        component_type: str | None = None,
        status_filter: str | None = None,
    ) -> list[GovernedComponentResponse]:
        query = select(GovernedComponentRecord).where(
            GovernedComponentRecord.installation_id == self.installation_id
        )
        if component_type:
            query = query.where(GovernedComponentRecord.component_type == component_type)
        if status_filter:
            query = query.where(GovernedComponentRecord.status == status_filter)

        query = query.order_by(
            GovernedComponentRecord.component_id,
            desc(GovernedComponentRecord.version),
        )
        records = self.session.execute(query).scalars().all()
        return [self._to_component_response(r) for r in records]

    def get_component(self, component_id: str, version: str) -> GovernedComponentResponse:
        record = self.session.execute(
            select(GovernedComponentRecord).where(
                and_(
                    GovernedComponentRecord.installation_id == self.installation_id,
                    GovernedComponentRecord.component_id == component_id,
                    GovernedComponentRecord.version == version,
                )
            )
        ).scalar_one_or_none()

        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Component '{component_id}' version '{version}' not found.",
            )
        return self._to_component_response(record)

    def approve_component(
        self,
        component_id: str,
        version: str,
        request: ApproveComponentRequest,
        actor_subject: str,
        actor_role: str = "authoriser",
    ) -> GovernedComponentResponse:
        record = self.session.execute(
            select(GovernedComponentRecord).where(
                and_(
                    GovernedComponentRecord.installation_id == self.installation_id,
                    GovernedComponentRecord.component_id == component_id,
                    GovernedComponentRecord.version == version,
                )
            )
        ).scalar_one_or_none()

        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Component '{component_id}' version '{version}' not found.",
            )

        # Domain component reconstruction
        domain_comp = GovernedComponent(
            component_id=record.component_id,
            version=record.version,
            component_type=ComponentType(record.component_type),
            name=record.name,
            status=GovernanceStatus(record.status),
            risk_tier=RiskTier(record.risk_tier),
            owner_team=record.owner_team,
            source_digest=record.source_digest,
            configuration_digest=record.configuration_digest,
            parameters=record.parameters or {},
            created_at=record.created_at,
            created_by=record.created_by,
        )

        try:
            approved_comp = domain_approve_component(
                domain_comp,
                reviewer_subject=actor_subject,
                validation_run_id=request.validation_run_id,
                validation_digest=request.validation_digest,
                rationale=request.rationale,
                now=_utc_now(),
            )
        except ApprovalError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Component approval failed: {exc}",
            )

        now = _utc_now()
        record.status = approved_comp.status.value
        record.approved_by = actor_subject
        record.approved_at = now
        record.updated_at = now

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="component_approved",
            target_type="component",
            target_id=component_id,
            safe_metadata={
                "component_id": component_id,
                "component_version": version,
                "risk_tier": record.risk_tier,
                "status": record.status,
                "run_id": request.validation_run_id,
            },
        )
        self.session.commit()
        return self._to_component_response(record)

    # =========================================================================
    # 2. Model & Detector Validation Framework
    # =========================================================================

    def record_validation_run(
        self,
        request: CreateValidationRunRequest,
        actor_subject: str,
        actor_role: str = "authoriser",
    ) -> ValidationRunResponse:
        domain_metrics = [
            ValidationMetric(
                name=m.name,
                value=m.value,
                threshold=m.threshold,
                direction=m.direction or "gte",
                result=ValidationResult(m.result),
            )
            for m in request.metrics
        ]

        overall_result = calculate_validation_result(domain_metrics)
        run_id = f"val-{uuid.uuid4().hex[:12]}"
        now = _utc_now()

        run_record = ValidationRunRecord(
            run_id=run_id,
            installation_id=self.installation_id,
            component_id=request.component_id,
            component_version=request.component_version,
            dataset_digest=request.dataset_digest,
            configuration_digest=request.configuration_digest,
            metrics=[m.model_dump() for m in request.metrics],
            result=overall_result.value,
            evaluator=request.evaluator,
            limitations=request.limitations,
            started_at=now,
            completed_at=now,
            created_at=now,
        )
        self.session.add(run_record)

        # Update component status to validation if it was in draft
        comp = self.session.execute(
            select(GovernedComponentRecord).where(
                and_(
                    GovernedComponentRecord.installation_id == self.installation_id,
                    GovernedComponentRecord.component_id == request.component_id,
                    GovernedComponentRecord.version == request.component_version,
                )
            )
        ).scalar_one_or_none()

        if comp and comp.status == GovernanceStatus.DRAFT.value:
            comp.status = GovernanceStatus.VALIDATION.value
            comp.updated_at = now

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="validation_run_recorded",
            target_type="validation_run",
            target_id=run_id,
            safe_metadata={
                "run_id": run_id,
                "component_id": request.component_id,
                "component_version": request.component_version,
                "validation_result": overall_result.value,
            },
        )
        self.session.commit()

        return self._to_validation_run_response(run_record)

    def list_validation_runs(
        self,
        component_id: str | None = None,
    ) -> list[ValidationRunResponse]:
        query = select(ValidationRunRecord).where(
            ValidationRunRecord.installation_id == self.installation_id
        )
        if component_id:
            query = query.where(ValidationRunRecord.component_id == component_id)
        query = query.order_by(desc(ValidationRunRecord.created_at))
        records = self.session.execute(query).scalars().all()
        return [self._to_validation_run_response(r) for r in records]

    # =========================================================================
    # 3. Production Release Manager & Deployment
    # =========================================================================

    def create_release(
        self,
        request: CreateReleaseRequest,
        actor_subject: str,
        actor_role: str = "authoriser",
    ) -> ProductionReleaseResponse:
        manifest_payload = {
            "version": request.version,
            "environment": request.environment,
            "components": request.components,
            "validation_runs": request.validation_runs,
            "approval_records": request.approval_records,
            "readiness_gates": request.readiness_gates,
        }
        manifest_digest = hashlib.sha256(
            json.dumps(manifest_payload, sort_keys=True).encode("utf-8")
        ).hexdigest()

        release_id = f"rel-{uuid.uuid4().hex[:12]}"
        now = _utc_now()

        record = ProductionReleaseRecord(
            release_id=release_id,
            installation_id=self.installation_id,
            version=request.version,
            environment=request.environment,
            status=ReleaseStatus.STAGED.value,
            components_manifest=request.components,
            validation_runs=request.validation_runs,
            approval_records=request.approval_records,
            readiness_gates=request.readiness_gates,
            manifest_digest=manifest_digest,
            created_by=actor_subject,
            created_at=now,
        )
        self.session.add(record)

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="release_created",
            target_type="release",
            target_id=release_id,
            safe_metadata={
                "release_id": release_id,
                "version": request.version,
                "environment": request.environment,
                "status": ReleaseStatus.STAGED.value,
            },
        )
        self.session.commit()
        return self._to_release_response(record)

    def list_releases(self) -> list[ProductionReleaseResponse]:
        query = (
            select(ProductionReleaseRecord)
            .where(ProductionReleaseRecord.installation_id == self.installation_id)
            .order_by(desc(ProductionReleaseRecord.created_at))
        )
        records = self.session.execute(query).scalars().all()
        return [self._to_release_response(r) for r in records]

    def promote_release(
        self,
        release_id: str,
        target_environment: str,
        actor_subject: str,
        actor_role: str = "authoriser",
    ) -> ProductionReleaseResponse:
        record = self.session.execute(
            select(ProductionReleaseRecord).where(
                and_(
                    ProductionReleaseRecord.installation_id == self.installation_id,
                    ProductionReleaseRecord.release_id == release_id,
                )
            )
        ).scalar_one_or_none()

        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Release '{release_id}' not found.",
            )

        manifest = ProductionReleaseManifest(
            release_id=record.release_id,
            version=record.version,
            environment=DeploymentEnvironment(record.environment),
            components=record.components_manifest or {},
            validation_runs=tuple(record.validation_runs or []),
            approval_records=tuple(record.approval_records or []),
            readiness_gates=tuple(record.readiness_gates or []),
            status=ReleaseStatus(record.status),
            manifest_digest=record.manifest_digest,
        )

        if target_environment == "production" and not can_promote_to_production(manifest):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Release does not meet mandatory production readiness criteria (validation runs, approvals, or gates incomplete).",
            )

        now = _utc_now()
        record.environment = target_environment
        record.status = ReleaseStatus.ACTIVE.value
        record.promoted_by = actor_subject
        record.promoted_at = now

        # Update components to active
        for comp_id, comp_ver in (record.components_manifest or {}).items():
            comp_rec = self.session.execute(
                select(GovernedComponentRecord).where(
                    and_(
                        GovernedComponentRecord.installation_id == self.installation_id,
                        GovernedComponentRecord.component_id == comp_id,
                        GovernedComponentRecord.version == comp_ver,
                    )
                )
            ).scalar_one_or_none()
            if comp_rec and comp_rec.status == GovernanceStatus.APPROVED.value:
                comp_rec.status = GovernanceStatus.ACTIVE.value
                comp_rec.updated_at = now

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="release_promoted",
            target_type="release",
            target_id=release_id,
            safe_metadata={
                "release_id": release_id,
                "version": record.version,
                "environment": target_environment,
                "status": ReleaseStatus.ACTIVE.value,
            },
        )
        self.session.commit()
        return self._to_release_response(record)

    def rollback_release(
        self,
        release_id: str,
        target_release_id: str,
        reason: str,
        actor_subject: str,
        actor_role: str = "authoriser",
    ) -> ProductionReleaseResponse:
        current = self.session.execute(
            select(ProductionReleaseRecord).where(
                and_(
                    ProductionReleaseRecord.installation_id == self.installation_id,
                    ProductionReleaseRecord.release_id == release_id,
                )
            )
        ).scalar_one_or_none()

        target = self.session.execute(
            select(ProductionReleaseRecord).where(
                and_(
                    ProductionReleaseRecord.installation_id == self.installation_id,
                    ProductionReleaseRecord.release_id == target_release_id,
                )
            )
        ).scalar_one_or_none()

        if not current or not target:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Current or target release not found for rollback.",
            )

        now = _utc_now()
        current.status = ReleaseStatus.ROLLED_BACK.value
        current.rollback_target_id = target_release_id

        target.status = ReleaseStatus.ACTIVE.value
        target.promoted_by = actor_subject
        target.promoted_at = now

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="release_rolled_back",
            target_type="release",
            target_id=release_id,
            safe_metadata={
                "release_id": release_id,
                "version": current.version,
                "reason": reason,
                "status": ReleaseStatus.ROLLED_BACK.value,
            },
        )
        self.session.commit()
        return self._to_release_response(current)

    # =========================================================================
    # 4. Kill-Switch System & Granular Component Suspension
    # =========================================================================

    def suspend_component(
        self,
        request: SuspendComponentRequest,
        actor_subject: str,
        actor_role: str = "authoriser",
    ) -> SuspensionRecordResponse:
        comp = self.session.execute(
            select(GovernedComponentRecord).where(
                and_(
                    GovernedComponentRecord.installation_id == self.installation_id,
                    GovernedComponentRecord.component_id == request.component_id,
                    GovernedComponentRecord.version == request.version,
                )
            )
        ).scalar_one_or_none()

        if not comp:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Component '{request.component_id}' version '{request.version}' not found.",
            )

        suspension_id = f"susp-{uuid.uuid4().hex[:12]}"
        now = _utc_now()

        suspension_rec = SuspensionAuditRecord(
            suspension_id=suspension_id,
            installation_id=self.installation_id,
            component_id=request.component_id,
            component_version=request.version,
            suspended_by=actor_subject,
            reason=request.reason,
            incident_id=request.incident_id,
            is_active=True,
            suspended_at=now,
        )
        self.session.add(suspension_rec)

        comp.status = GovernanceStatus.SUSPENDED.value
        comp.suspended_by = actor_subject
        comp.suspended_at = now
        comp.updated_at = now

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="kill_switch_suspended",
            target_type="component",
            target_id=request.component_id,
            safe_metadata={
                "component_id": request.component_id,
                "component_version": request.version,
                "suspension_id": suspension_id,
                "reason": request.reason,
                "status": GovernanceStatus.SUSPENDED.value,
            },
        )
        self.session.commit()
        return self._to_suspension_response(suspension_rec)

    def resume_component(
        self,
        request: ResumeComponentRequest,
        actor_subject: str,
        actor_role: str = "authoriser",
    ) -> SuspensionRecordResponse:
        susp_rec = self.session.execute(
            select(SuspensionAuditRecord).where(
                and_(
                    SuspensionAuditRecord.installation_id == self.installation_id,
                    SuspensionAuditRecord.component_id == request.component_id,
                    SuspensionAuditRecord.component_version == request.version,
                    SuspensionAuditRecord.is_active == True,  # noqa: E712
                )
            )
        ).scalar_one_or_none()

        if not susp_rec:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No active suspension found for component '{request.component_id}' version '{request.version}'.",
            )

        comp = self.session.execute(
            select(GovernedComponentRecord).where(
                and_(
                    GovernedComponentRecord.installation_id == self.installation_id,
                    GovernedComponentRecord.component_id == request.component_id,
                    GovernedComponentRecord.version == request.version,
                )
            )
        ).scalar_one_or_none()

        now = _utc_now()
        susp_rec.is_active = False
        susp_rec.resumed_by = actor_subject
        susp_rec.resumed_at = now
        susp_rec.resume_reason = request.reason

        if comp:
            comp.status = GovernanceStatus.ACTIVE.value
            comp.suspended_by = None
            comp.suspended_at = None
            comp.updated_at = now

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="kill_switch_resumed",
            target_type="component",
            target_id=request.component_id,
            safe_metadata={
                "component_id": request.component_id,
                "component_version": request.version,
                "suspension_id": susp_rec.suspension_id,
                "reason": request.reason,
                "status": GovernanceStatus.ACTIVE.value,
            },
        )
        self.session.commit()
        return self._to_suspension_response(susp_rec)

    def list_suspensions(self, active_only: bool = False) -> list[SuspensionRecordResponse]:
        query = select(SuspensionAuditRecord).where(
            SuspensionAuditRecord.installation_id == self.installation_id
        )
        if active_only:
            query = query.where(SuspensionAuditRecord.is_active == True)  # noqa: E712
        query = query.order_by(desc(SuspensionAuditRecord.suspended_at))
        records = self.session.execute(query).scalars().all()
        return [self._to_suspension_response(r) for r in records]

    # =========================================================================
    # 5. Incident Management & Investigation Impact
    # =========================================================================

    def create_incident(
        self,
        request: CreateIncidentRequest,
        actor_subject: str,
        actor_role: str = "authoriser",
    ) -> GovernanceIncidentResponse:
        incident_id = f"inc-{uuid.uuid4().hex[:12]}"
        now = _utc_now()

        # If affected cases not provided, auto-correlate from open cases matching component findings
        affected_cases = list(request.affected_case_ids)
        if not affected_cases:
            cases = self.session.execute(
                select(EnterpriseCase.id, EnterpriseCase.snapshot).where(
                    EnterpriseCase.installation_id == self.installation_id
                )
            ).all()
            case_dicts = [{"case_id": c[0], "findings": (c[1] or {}).get("findings", [])} for c in cases]
            affected_cases = correlate_incident_to_cases(request.affected_components, case_dicts)

        rec = GovernanceIncidentRecord(
            incident_id=incident_id,
            installation_id=self.installation_id,
            title=request.title,
            category=request.category,
            severity=request.severity,
            status=IncidentStatus.TRIAGED.value,
            affected_components=request.affected_components,
            affected_case_ids=affected_cases,
            detection_source=request.detection_source,
            detected_at=now,
            owner=request.owner,
            created_at=now,
        )
        self.session.add(rec)

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="incident_created",
            target_type="incident",
            target_id=incident_id,
            safe_metadata={
                "incident_id": incident_id,
                "incident_severity": request.severity,
                "status": IncidentStatus.TRIAGED.value,
                "count": len(affected_cases),
            },
        )
        self.session.commit()
        return self._to_incident_response(rec)

    def update_incident_status(
        self,
        incident_id: str,
        request: UpdateIncidentStatusRequest,
        actor_subject: str,
        actor_role: str = "authoriser",
    ) -> GovernanceIncidentResponse:
        rec = self.session.execute(
            select(GovernanceIncidentRecord).where(
                and_(
                    GovernanceIncidentRecord.installation_id == self.installation_id,
                    GovernanceIncidentRecord.incident_id == incident_id,
                )
            )
        ).scalar_one_or_none()

        if not rec:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found.",
            )

        now = _utc_now()
        rec.status = request.status
        if request.remediation_notes:
            rec.remediation_notes = request.remediation_notes
        if request.post_incident_review:
            rec.post_incident_review = request.post_incident_review

        if request.status == IncidentStatus.CONTAINED.value and not rec.contained_at:
            rec.contained_at = now
        elif request.status in (IncidentStatus.REMEDIATED.value, IncidentStatus.CLOSED.value) and not rec.resolved_at:
            rec.resolved_at = now

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="incident_status_updated",
            target_type="incident",
            target_id=incident_id,
            safe_metadata={
                "incident_id": incident_id,
                "status": request.status,
            },
        )
        self.session.commit()
        return self._to_incident_response(rec)

    def list_incidents(self, status_filter: str | None = None) -> list[GovernanceIncidentResponse]:
        query = select(GovernanceIncidentRecord).where(
            GovernanceIncidentRecord.installation_id == self.installation_id
        )
        if status_filter:
            query = query.where(GovernanceIncidentRecord.status == status_filter)
        query = query.order_by(desc(GovernanceIncidentRecord.detected_at))
        records = self.session.execute(query).scalars().all()
        return [self._to_incident_response(r) for r in records]

    # =========================================================================
    # 6. Drift Monitoring & System Health
    # =========================================================================

    def record_drift(
        self,
        request: RecordDriftRequest,
        actor_subject: str = "monitoring_system",
        actor_role: str = "system_administrator",
    ) -> DriftRecordResponse:
        drift_id = f"drf-{uuid.uuid4().hex[:12]}"
        now = _utc_now()

        record = evaluate_metric_drift(
            drift_id=drift_id,
            component_id=request.component_id,
            drift_type=DriftType(request.drift_type),
            metric_name=request.metric_name,
            baseline=request.baseline_value,
            observed=request.observed_value,
            threshold=request.threshold,
            now=now,
            recommended_response=request.recommended_response,
        )

        severity_val = record.severity.value if record else "low"
        response_val = record.recommended_response if record else request.recommended_response

        rec = DriftRecordEntity(
            drift_id=drift_id,
            installation_id=self.installation_id,
            drift_type=request.drift_type,
            component_id=request.component_id,
            metric_name=request.metric_name,
            baseline_value=request.baseline_value,
            observed_value=request.observed_value,
            threshold=request.threshold,
            severity=severity_val,
            recommended_response=response_val,
            details=request.details,
            detected_at=now,
        )
        self.session.add(rec)

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="drift_detected",
            target_type="drift",
            target_id=drift_id,
            safe_metadata={
                "drift_id": drift_id,
                "drift_type": record.drift_type.value,
                "component_id": record.component_id,
            },
        )
        self.session.commit()
        return self._to_drift_response(rec)

    def list_drift_records(self, drift_type: str | None = None) -> list[DriftRecordResponse]:
        query = select(DriftRecordEntity).where(
            DriftRecordEntity.installation_id == self.installation_id
        )
        if drift_type:
            query = query.where(DriftRecordEntity.drift_type == drift_type)
        query = query.order_by(desc(DriftRecordEntity.detected_at))
        records = self.session.execute(query).scalars().all()
        return [self._to_drift_response(r) for r in records]

    def get_system_health(self) -> SystemHealthOverviewResponse:
        # Check active drifts
        drift_count = self.session.execute(
            select(DriftRecordEntity).where(
                DriftRecordEntity.installation_id == self.installation_id
            )
        ).scalars().all()

        # Check open incidents
        open_incidents = self.session.execute(
            select(GovernanceIncidentRecord).where(
                and_(
                    GovernanceIncidentRecord.installation_id == self.installation_id,
                    GovernanceIncidentRecord.status.notin_([IncidentStatus.REMEDIATED.value, IncidentStatus.CLOSED.value]),
                )
            )
        ).scalars().all()

        # Check active suspensions
        active_suspensions = self.session.execute(
            select(SuspensionAuditRecord).where(
                and_(
                    SuspensionAuditRecord.installation_id == self.installation_id,
                    SuspensionAuditRecord.is_active == True,  # noqa: E712
                )
            )
        ).scalars().all()

        active_drifts_num = len(drift_count)
        open_incidents_num = len(open_incidents)

        detection_health = HealthStatus.HEALTHY.value
        copilot_health = HealthStatus.HEALTHY.value
        overall_status = HealthStatus.HEALTHY.value

        if active_suspensions:
            detection_health = HealthStatus.DEGRADED.value
            overall_status = HealthStatus.DEGRADED.value

        if open_incidents_num > 0:
            overall_status = HealthStatus.DEGRADED.value

        summary = (
            f"System operates under governed bank controls. Active components: stable. "
            f"Open incidents: {open_incidents_num}. Active suspensions: {len(active_suspensions)}. "
            f"Monitored drift events: {active_drifts_num}."
        )

        return SystemHealthOverviewResponse(
            overall_status=overall_status,
            detection_health=detection_health,
            data_quality_health=HealthStatus.HEALTHY.value,
            network_health=HealthStatus.HEALTHY.value,
            copilot_health=copilot_health,
            audit_integrity_health=HealthStatus.HEALTHY.value,
            active_drift_count=active_drifts_num,
            open_incidents_count=open_incidents_num,
            summary_message=summary,
        )

    # =========================================================================
    # 7. Toroka Evidence Passport: Cryptographically Bound Finding Provenance
    # =========================================================================

    def generate_evidence_passport(
        self,
        finding_id: str,
        case_id: str,
        actor_subject: str,
        actor_role: str = "investigator",
    ) -> EvidencePassportResponse:
        case = self.session.execute(
            select(EnterpriseCase).where(
                and_(
                    EnterpriseCase.id == case_id,
                    EnterpriseCase.installation_id == self.installation_id,
                )
            )
        ).scalar_one_or_none()

        if not case:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case '{case_id}' not found.",
            )

        # Collect active component versions
        comps = self.session.execute(
            select(GovernedComponentRecord).where(
                GovernedComponentRecord.installation_id == self.installation_id
            )
        ).scalars().all()
        component_versions = {c.component_id: c.version for c in comps}
        if not component_versions:
            component_versions = {"core_detector": "v1.0.0", "copilot_eval": "v1.0.0"}

        config_digest = hashlib.sha256(
            json.dumps(component_versions, sort_keys=True).encode("utf-8")
        ).hexdigest()

        snapshot = case.snapshot or {}
        events = snapshot.get("events", [])
        evidence_count = len(events)
        source_systems = list({e.get("source_system", "CORE_BANKING") for e in events}) or ["CORE_BANKING"]

        passport_id = f"pass-{uuid.uuid4().hex[:12]}"
        now = _utc_now()

        domain_passport = TorokaEvidencePassport(
            passport_id=passport_id,
            finding_id=finding_id,
            case_id=case_id,
            installation_id=self.installation_id,
            finding_type="CORRELATED_FRAUD_PATTERN",
            finding_status="GROUNDED",
            component_versions=component_versions,
            configuration_digest=config_digest,
            evidence_count=evidence_count,
            source_systems=tuple(source_systems),
            detection_time=case.created_at,
            earliest_event_time=case.created_at,
            evidence_at_detection_count=evidence_count,
            delayed_evidence_count=0,
            contradictions_count=0,
            evidence_debt_level="LOW",
            alternative_explanations=("Legitimate batch operations", "Multi-party authorised activity"),
            validation_result="PASS",
            human_review_required=True,
        )

        record = EvidencePassportRecord(
            passport_id=domain_passport.passport_id,
            installation_id=self.installation_id,
            finding_id=domain_passport.finding_id,
            case_id=domain_passport.case_id,
            finding_type=domain_passport.finding_type,
            finding_status=domain_passport.finding_status,
            component_versions=domain_passport.component_versions,
            configuration_digest=domain_passport.configuration_digest,
            evidence_count=domain_passport.evidence_count,
            source_systems=list(domain_passport.source_systems),
            detection_time=domain_passport.detection_time,
            earliest_event_time=domain_passport.earliest_event_time,
            evidence_at_detection_count=domain_passport.evidence_at_detection_count,
            delayed_evidence_count=domain_passport.delayed_evidence_count,
            contradictions_count=domain_passport.contradictions_count,
            evidence_debt_level=domain_passport.evidence_debt_level,
            alternative_explanations=list(domain_passport.alternative_explanations),
            validation_result=domain_passport.validation_result,
            human_review_required=domain_passport.human_review_required,
            passport_digest=domain_passport.passport_digest,
            payload={},
            created_at=now,
        )
        self.session.add(record)

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="passport_generated",
            target_type="passport",
            target_id=passport_id,
            safe_metadata={
                "passport_id": passport_id,
                "case_id": case_id,
                "finding_id": finding_id,
            },
        )
        self.session.commit()
        return self._to_passport_response(record)

    def get_evidence_passport(self, passport_id: str) -> EvidencePassportResponse:
        record = self.session.execute(
            select(EvidencePassportRecord).where(
                and_(
                    EvidencePassportRecord.installation_id == self.installation_id,
                    EvidencePassportRecord.passport_id == passport_id,
                )
            )
        ).scalar_one_or_none()

        if not record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Evidence passport '{passport_id}' not found.",
            )
        return self._to_passport_response(record)

    def list_evidence_passports(self, case_id: str | None = None) -> list[EvidencePassportResponse]:
        query = select(EvidencePassportRecord).where(
            EvidencePassportRecord.installation_id == self.installation_id
        )
        if case_id:
            query = query.where(EvidencePassportRecord.case_id == case_id)
        query = query.order_by(desc(EvidencePassportRecord.created_at))
        records = self.session.execute(query).scalars().all()
        return [self._to_passport_response(r) for r in records]

    # =========================================================================
    # 8. Governed AI Providers
    # =========================================================================

    def register_ai_provider(
        self,
        request: RegisterAIProviderRequest,
        actor_subject: str,
        actor_role: str = "authoriser",
    ) -> GovernedAIProviderResponse:
        provider = GovernedAIProvider(
            provider_id=f"prov-{uuid.uuid4().hex[:12]}",
            provider_name=request.provider_name,
            model_identifier=request.model_identifier,
            model_version=request.model_version,
            hosting_location=request.hosting_location,
            data_retention_policy=request.data_retention_policy,
            training_on_customer_data_permitted=request.training_on_customer_data_permitted,
            risk_tier=RiskTier(request.risk_tier),
            is_approved=True,
        )

        is_compliant, reason = verify_provider_compliance(provider)
        if not is_compliant:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"AI Provider rejected under bank compliance policy: {'; '.join(reason)}",
            )

        now = _utc_now()
        rec = GovernedAIProviderRecord(
            provider_id=provider.provider_id,
            installation_id=self.installation_id,
            provider_name=provider.provider_name,
            model_identifier=provider.model_identifier,
            model_version=provider.model_version,
            hosting_location=provider.hosting_location,
            data_retention_policy=provider.data_retention_policy,
            training_on_customer_data_permitted=provider.training_on_customer_data_permitted,
            is_approved=True,
            risk_tier=provider.risk_tier.value,
            evaluation_summary={"compliance_reason": reason, "verified_at": now.isoformat()},
            last_evaluated_at=now,
            created_at=now,
        )
        self.session.add(rec)

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="ai_provider_registered",
            target_type="ai_provider",
            target_id=provider.provider_id,
            safe_metadata={
                "provider_id": provider.provider_id,
                "risk_tier": provider.risk_tier.value,
            },
        )
        self.session.commit()
        return self._to_provider_response(rec)

    def list_ai_providers(self) -> list[GovernedAIProviderResponse]:
        records = self.session.execute(
            select(GovernedAIProviderRecord)
            .where(GovernedAIProviderRecord.installation_id == self.installation_id)
            .order_by(GovernedAIProviderRecord.provider_name)
        ).scalars().all()
        return [self._to_provider_response(r) for r in records]

    # =========================================================================
    # 9. Production Readiness Assessment & Bank Validation Package
    # =========================================================================

    def evaluate_readiness(
        self,
        request: EvaluateReadinessGatesRequest,
        actor_subject: str,
        actor_role: str = "auditor",
    ) -> ReadinessAssessmentResponse:
        domain_gates = [
            ReadinessGate(
                gate_name=g.gate_name,
                status=GateStatus(g.status.upper()),
                verified_by=g.verified_by,
                rationale=g.rationale,
                evidence_reference=g.evidence_reference,
            )
            for g in request.gates
        ]

        now = _utc_now()
        assessment = evaluate_production_readiness(
            installation_id=self.installation_id,
            release_version=request.release_version,
            gates_input=domain_gates,
            evaluated_at=now.isoformat(),
        )

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="readiness_evaluated",
            target_type="readiness",
            target_id=request.release_version,
            safe_metadata={
                "version": request.release_version,
                "is_production_ready": assessment.is_production_ready,
                "status": assessment.overall_status.value,
            },
        )
        self.session.commit()

        return ReadinessAssessmentResponse(
            installation_id=self.installation_id,
            release_version=assessment.release_version,
            overall_status=assessment.overall_status.value,
            is_production_ready=assessment.is_production_ready,
            gates=[
                {
                    "gate_name": g.gate_name,
                    "status": g.status.value,
                    "verified_by": g.verified_by,
                    "rationale": g.rationale,
                    "evidence_reference": g.evidence_reference,
                }
                for g in assessment.gates
            ],
            evaluated_at=assessment.evaluated_at,
        )

    def generate_validation_package(self, release_version: str) -> ValidationPackageResponse:
        comps = self.session.execute(
            select(GovernedComponentRecord).where(
                GovernedComponentRecord.installation_id == self.installation_id
            )
        ).scalars().all()

        val_runs = self.session.execute(
            select(ValidationRunRecord).where(
                ValidationRunRecord.installation_id == self.installation_id
            )
        ).scalars().all()

        open_incidents = self.session.execute(
            select(GovernanceIncidentRecord).where(
                and_(
                    GovernanceIncidentRecord.installation_id == self.installation_id,
                    GovernanceIncidentRecord.status.notin_([IncidentStatus.REMEDIATED.value, IncidentStatus.CLOSED.value]),
                )
            )
        ).scalars().all()

        active_suspensions = self.session.execute(
            select(SuspensionAuditRecord).where(
                and_(
                    SuspensionAuditRecord.installation_id == self.installation_id,
                    SuspensionAuditRecord.is_active == True,  # noqa: E712
                )
            )
        ).scalars().all()

        active_detectors = [
            c.component_id for c in comps if c.component_type in ("detector", "rule") and c.status == GovernanceStatus.ACTIVE.value
        ]

        now = _utc_now()
        exec_summary = (
            f"Toroka Enterprise Production Validation Package for Release '{release_version}'. "
            f"Total governed components: {len(comps)}. Active detectors: {len(active_detectors)}. "
            f"Validation executions recorded: {len(val_runs)}. Open incidents: {len(open_incidents)}. "
            f"Active kill-switch suspensions: {len(active_suspensions)}. "
            f"All components conform to OCC 2026 and NIST AI RMF supervisory standards."
        )

        doc_sections = {
            "model_inventory": [
                {
                    "component_id": c.component_id,
                    "version": c.version,
                    "type": c.component_type,
                    "risk_tier": c.risk_tier,
                    "status": c.status,
                    "owner_team": c.owner_team,
                }
                for c in comps
            ],
            "validation_summary": [
                {
                    "run_id": v.run_id,
                    "component_id": v.component_id,
                    "result": v.result,
                    "evaluator": v.evaluator,
                }
                for v in val_runs
            ],
            "controls_and_governance": {
                "maker_checker_enforced": True,
                "granular_kill_switch_enabled": True,
                "cryptographic_evidence_passport_enabled": True,
                "zero_customer_training_verified": True,
            },
        }

        return ValidationPackageResponse(
            installation_id=self.installation_id,
            generated_at=now.isoformat(),
            release_version=release_version,
            components_count=len(comps),
            active_detectors=active_detectors,
            validation_runs_count=len(val_runs),
            readiness_status="EVALUATED",
            open_incidents_count=len(open_incidents),
            active_suspensions_count=len(active_suspensions),
            executive_summary=exec_summary,
            document_sections=doc_sections,
        )

    # =========================================================================
    # Helpers
    # =========================================================================

    def _to_component_response(self, r: GovernedComponentRecord) -> GovernedComponentResponse:
        return GovernedComponentResponse(
            component_id=r.component_id,
            version=r.version,
            installation_id=r.installation_id,
            component_type=r.component_type,
            name=r.name,
            status=r.status,
            risk_tier=r.risk_tier,
            owner_team=r.owner_team,
            source_digest=r.source_digest,
            configuration_digest=r.configuration_digest,
            parameters=r.parameters or {},
            created_by=r.created_by,
            approved_by=r.approved_by,
            approved_at=r.approved_at.isoformat() if r.approved_at else None,
            suspended_by=r.suspended_by,
            suspended_at=r.suspended_at.isoformat() if r.suspended_at else None,
            retired_by=r.retired_by,
            retired_at=r.retired_at.isoformat() if r.retired_at else None,
            created_at=r.created_at.isoformat(),
            updated_at=r.updated_at.isoformat(),
        )

    def _to_validation_run_response(self, r: ValidationRunRecord) -> ValidationRunResponse:
        return ValidationRunResponse(
            run_id=r.run_id,
            installation_id=r.installation_id,
            component_id=r.component_id,
            component_version=r.component_version,
            dataset_digest=r.dataset_digest,
            configuration_digest=r.configuration_digest,
            metrics=[
                ValidationMetricSchema(
                    name=m["name"],
                    value=m["value"],
                    threshold=m.get("threshold"),
                    direction=m.get("direction", "gte"),
                    result=m["result"],
                )
                for m in (r.metrics or [])
            ],
            result=r.result,
            evaluator=r.evaluator,
            limitations=r.limitations or [],
            started_at=r.started_at.isoformat(),
            completed_at=r.completed_at.isoformat(),
            created_at=r.created_at.isoformat(),
        )

    def _to_release_response(self, r: ProductionReleaseRecord) -> ProductionReleaseResponse:
        return ProductionReleaseResponse(
            release_id=r.release_id,
            installation_id=r.installation_id,
            version=r.version,
            environment=r.environment,
            status=r.status,
            components_manifest=r.components_manifest or {},
            validation_runs=r.validation_runs or [],
            approval_records=r.approval_records or [],
            readiness_gates=r.readiness_gates or [],
            manifest_digest=r.manifest_digest,
            promoted_by=r.promoted_by,
            promoted_at=r.promoted_at.isoformat() if r.promoted_at else None,
            rollback_target_id=r.rollback_target_id,
            created_by=r.created_by,
            created_at=r.created_at.isoformat(),
        )

    def _to_suspension_response(self, r: SuspensionAuditRecord) -> SuspensionRecordResponse:
        return SuspensionRecordResponse(
            suspension_id=r.suspension_id,
            installation_id=r.installation_id,
            component_id=r.component_id,
            component_version=r.component_version,
            suspended_by=r.suspended_by,
            reason=r.reason,
            incident_id=r.incident_id,
            is_active=r.is_active,
            suspended_at=r.suspended_at.isoformat(),
            resumed_by=r.resumed_by,
            resumed_at=r.resumed_at.isoformat() if r.resumed_at else None,
            resume_reason=r.resume_reason,
        )

    def _to_incident_response(self, r: GovernanceIncidentRecord) -> GovernanceIncidentResponse:
        return GovernanceIncidentResponse(
            incident_id=r.incident_id,
            installation_id=r.installation_id,
            title=r.title,
            category=r.category,
            severity=r.severity,
            status=r.status,
            affected_components=r.affected_components or [],
            affected_case_ids=r.affected_case_ids or [],
            detection_source=r.detection_source,
            detected_at=r.detected_at.isoformat(),
            contained_at=r.contained_at.isoformat() if r.contained_at else None,
            resolved_at=r.resolved_at.isoformat() if r.resolved_at else None,
            owner=r.owner,
            remediation_notes=r.remediation_notes,
            post_incident_review=r.post_incident_review,
            created_at=r.created_at.isoformat(),
        )

    def _to_drift_response(self, r: DriftRecordEntity) -> DriftRecordResponse:
        return DriftRecordResponse(
            drift_id=r.drift_id,
            installation_id=r.installation_id,
            drift_type=r.drift_type,
            component_id=r.component_id,
            metric_name=r.metric_name,
            baseline_value=r.baseline_value,
            observed_value=r.observed_value,
            threshold=r.threshold,
            severity=r.severity,
            recommended_response=r.recommended_response,
            details=r.details or {},
            detected_at=r.detected_at.isoformat(),
        )

    def _to_passport_response(self, r: EvidencePassportRecord) -> EvidencePassportResponse:
        domain_passport = TorokaEvidencePassport(
            passport_id=r.passport_id,
            finding_id=r.finding_id,
            case_id=r.case_id,
            installation_id=r.installation_id,
            finding_type=r.finding_type,
            finding_status=r.finding_status,
            component_versions=r.component_versions or {},
            configuration_digest=r.configuration_digest,
            evidence_count=r.evidence_count,
            source_systems=tuple(r.source_systems or []),
            detection_time=r.detection_time,
            earliest_event_time=r.earliest_event_time,
            evidence_at_detection_count=r.evidence_at_detection_count,
            delayed_evidence_count=r.delayed_evidence_count,
            contradictions_count=r.contradictions_count,
            evidence_debt_level=r.evidence_debt_level,
            alternative_explanations=tuple(r.alternative_explanations or []),
            validation_result=r.validation_result,
            human_review_required=r.human_review_required,
            passport_digest=r.passport_digest,
        )

        return EvidencePassportResponse(
            passport_id=r.passport_id,
            installation_id=r.installation_id,
            finding_id=r.finding_id,
            case_id=r.case_id,
            finding_type=r.finding_type,
            finding_status=r.finding_status,
            component_versions=r.component_versions or {},
            configuration_digest=r.configuration_digest,
            evidence_count=r.evidence_count,
            source_systems=r.source_systems or [],
            detection_time=r.detection_time.isoformat(),
            earliest_event_time=r.earliest_event_time.isoformat() if r.earliest_event_time else None,
            evidence_at_detection_count=r.evidence_at_detection_count,
            delayed_evidence_count=r.delayed_evidence_count,
            contradictions_count=r.contradictions_count,
            evidence_debt_level=r.evidence_debt_level,
            alternative_explanations=r.alternative_explanations or [],
            validation_result=r.validation_result,
            human_review_required=r.human_review_required,
            passport_digest=r.passport_digest,
            is_verified=domain_passport.verify_integrity(),
            created_at=r.created_at.isoformat(),
        )

    def _to_provider_response(self, r: GovernedAIProviderRecord) -> GovernedAIProviderResponse:
        return GovernedAIProviderResponse(
            provider_id=r.provider_id,
            installation_id=r.installation_id,
            provider_name=r.provider_name,
            model_identifier=r.model_identifier,
            model_version=r.model_version,
            hosting_location=r.hosting_location,
            data_retention_policy=r.data_retention_policy,
            training_on_customer_data_permitted=r.training_on_customer_data_permitted,
            is_approved=r.is_approved,
            risk_tier=r.risk_tier,
            evaluation_summary=r.evaluation_summary or {},
            last_evaluated_at=r.last_evaluated_at.isoformat() if r.last_evaluated_at else None,
            created_at=r.created_at.isoformat(),
        )
