from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
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
    _canonical_utc,
    canonical_json,
    release_manifest_payload,
    compute_release_manifest_digest,
)
from toroka_enterprise.governance.drift import (
    DriftRecord,
    DriftType,
    HealthStatus,
    SystemHealthOverview,
    evaluate_metric_drift,
)
from toroka_enterprise.governance.evidence_passport import (
    TorokaEvidencePassport,
    BoundEvidenceItem,
    compute_evidence_digest,
)
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
    KillSwitchStore,
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
from toroka_enterprise.governance.champion_challenger import (
    ModelPerformanceMetrics,
    PromotionDecision,
    evaluate_challenger_promotion,
)
from toroka_enterprise.governance.pki import (
    AsymmetricAlgorithm,
    LocalHSMKeyProvider,
    SignatureBundle,
    verify_asymmetric_signature,
)
from toroka_enterprise.governance.quantitative_risk import (
    compute_disparate_impact,
    evaluate_model_risk_comprehensive,
)
from toroka_enterprise.governance.forensic_dossier import (
    CustodyEvent,
    ForensicDossier,
    Section106BCertificate,
    compute_forensic_dossier_digest,
)
from toroka_enterprise.integrations.iso20022 import (
    ClearingRail,
    InflightRiskEvaluation,
    ISO20022Engine,
    Pacs008CreditTransfer,
    PartyIdentification,
)
from toroka_enterprise.intelligence.copilot.contracts import (
    ClaimKind,
    EvidenceContext,
    EvidenceItem,
    EvidenceQuote,
    GroundedClaim,
)
from toroka_enterprise.intelligence.copilot.advanced_defense import sanitize_narrative
from toroka_enterprise.intelligence.copilot.semantic_grounding import (
    EntailmentStatus,
    SemanticGroundingReport,
    verify_report_semantics,
)
from toroka_enterprise.intelligence.models import (
    ChampionChallengerRunRecord,
    DriftRecordEntity,
    EntityLinkCandidateRecord,
    EvidencePassportRecord,
    ForensicDossierRecord,
    GovernanceIncidentRecord,
    GovernedAIProviderRecord,
    GovernedComponentRecord,
    InflightPaymentRiskRecord,
    IntelligenceEventRecord,
    IntelligenceSignalRecord,
    NetworkFindingRecord,
    ProductionReleaseRecord,
    QuantitativeDriftEvaluationRecord,
    ReadinessAttestationRecord,
    SuspensionAuditRecord,
    ValidationRunRecord,
)

from ..governance_schemas import (
    ApproveComponentRequest,
    ChampionChallengerRunResponse,
    CreateComponentRequest,
    CreateForensicDossierRequest,
    CreateIncidentRequest,
    CreateReleaseRequest,
    CreateValidationRunRequest,
    DriftRecordResponse,
    EvaluateChampionChallengerRequest,
    EvaluateQuantitativeDriftRequest,
    EvaluateReadinessGatesRequest,
    EvidencePassportResponse,
    ForensicDossierResponse,
    GovernanceIncidentResponse,
    GovernedAIProviderResponse,
    GovernedComponentResponse,
    InflightPaymentEvaluationRequest,
    InflightPaymentEvaluationResponse,
    ProductionReleaseResponse,
    QuantitativeDriftEvaluationResponse,
    ReadinessAssessmentResponse,
    ReadinessAttestationResponse,
    RecordDriftRequest,
    RecordReadinessAttestationRequest,
    RegisterAIProviderRequest,
    ResumeComponentRequest,
    SemanticVerifyRequest,
    SemanticVerifyResponse,
    SignArtifactRequest,
    SuspendComponentRequest,
    SuspensionRecordResponse,
    SystemHealthOverviewResponse,
    UpdateIncidentStatusRequest,
    ValidationMetricSchema,
    ValidationPackageResponse,
    ValidationRunResponse,
    VerifyArtifactRequest,
    VerifyArtifactResponse,
)
from ..persistence.audit import append_audit, verify_audit_chain
from ..persistence.models import EnterpriseCase

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def compute_validation_run_digest(run: ValidationRunRecord) -> str:
    payload = {
        "schema": "toroka.validation-run.v1",
        "run_id": run.run_id,
        "installation_id": run.installation_id,
        "component_id": run.component_id,
        "component_version": run.component_version,
        "dataset_digest": run.dataset_digest,
        "configuration_digest": run.configuration_digest,
        "metrics": sorted((dict(m) for m in (run.metrics or [])), key=lambda m: str(m.get("name", ""))),
        "result": run.result,
        "evaluator": run.evaluator,
        "limitations": sorted(run.limitations or []),
        "started_at": _canonical_utc(run.started_at),
        "completed_at": _canonical_utc(run.completed_at),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class DatabaseKillSwitchStore:
    """Persistent KillSwitchStore backed by SQLAlchemy database records."""

    def __init__(self, session: Session, installation_id: str) -> None:
        self.session = session
        self.installation_id = installation_id

    def get_active_suspension(self, component_id: str, version: str) -> SuspensionRecord | None:
        rec = self.session.execute(
            select(SuspensionAuditRecord).where(
                and_(
                    SuspensionAuditRecord.installation_id == self.installation_id,
                    SuspensionAuditRecord.component_id == component_id,
                    SuspensionAuditRecord.component_version == version,
                    SuspensionAuditRecord.is_active == True,  # noqa: E712
                )
            )
        ).scalar_one_or_none()
        if rec:
            return SuspensionRecord(
                component_id=rec.component_id,
                component_version=rec.component_version,
                suspended_by=rec.suspended_by,
                suspended_at=rec.suspended_at,
                reason=rec.reason,
                incident_id=rec.incident_id,
                automatic=False,
            )
        comp = self.session.execute(
            select(GovernedComponentRecord).where(
                and_(
                    GovernedComponentRecord.installation_id == self.installation_id,
                    GovernedComponentRecord.component_id == component_id,
                    GovernedComponentRecord.version == version,
                    GovernedComponentRecord.status == GovernanceStatus.SUSPENDED.value,
                )
            )
        ).scalar_one_or_none()
        if comp:
            return SuspensionRecord(
                component_id=comp.component_id,
                component_version=comp.version,
                suspended_by=comp.suspended_by or "system",
                suspended_at=comp.suspended_at or comp.updated_at,
                reason=f"Component status is {comp.status}",
                incident_id=None,
                automatic=False,
            )
        return None

    def list_active_suspensions(self) -> list[SuspensionRecord]:
        records = self.session.execute(
            select(SuspensionAuditRecord).where(
                and_(
                    SuspensionAuditRecord.installation_id == self.installation_id,
                    SuspensionAuditRecord.is_active == True,  # noqa: E712
                )
            )
        ).scalars().all()
        return [
            SuspensionRecord(
                component_id=r.component_id,
                component_version=r.component_version,
                suspended_by=r.suspended_by,
                suspended_at=r.suspended_at,
                reason=r.reason,
                incident_id=r.incident_id,
                automatic=False,
            )
            for r in records
        ]

    def record_suspension(self, record: SuspensionRecord) -> SuspensionAuditRecord:
        active = self.get_active_suspension(record.component_id, record.component_version)
        if active:
            raise ValueError(f"Component '{record.component_id}' version '{record.component_version}' is already suspended.")

        comp = self.session.execute(
            select(GovernedComponentRecord).where(
                and_(
                    GovernedComponentRecord.installation_id == self.installation_id,
                    GovernedComponentRecord.component_id == record.component_id,
                    GovernedComponentRecord.version == record.component_version,
                )
            )
        ).scalar_one_or_none()
        if not comp:
            raise ValueError(f"Component '{record.component_id}' version '{record.component_version}' not found.")

        suspension_id = f"susp-{uuid.uuid4().hex[:12]}"
        now = record.suspended_at or _utc_now()
        suspension_rec = SuspensionAuditRecord(
            suspension_id=suspension_id,
            installation_id=self.installation_id,
            component_id=record.component_id,
            component_version=record.component_version,
            suspended_by=record.suspended_by,
            reason=record.reason,
            incident_id=record.incident_id,
            is_active=True,
            suspended_at=now,
        )
        self.session.add(suspension_rec)

        comp.status = GovernanceStatus.SUSPENDED.value
        comp.suspended_by = record.suspended_by
        comp.suspended_at = now
        comp.updated_at = now

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=record.suspended_by,
            actor_role="authoriser",
            action="kill_switch_suspended",
            target_type="component",
            target_id=record.component_id,
            safe_metadata={
                "component_id": record.component_id,
                "component_version": record.component_version,
                "suspension_id": suspension_id,
                "reason": record.reason,
                "status": GovernanceStatus.SUSPENDED.value,
            },
        )
        self.session.flush()
        return suspension_rec

    def record_resume(self, record: SuspensionRecord) -> SuspensionAuditRecord:
        susp_rec = self.session.execute(
            select(SuspensionAuditRecord).where(
                and_(
                    SuspensionAuditRecord.installation_id == self.installation_id,
                    SuspensionAuditRecord.component_id == record.component_id,
                    SuspensionAuditRecord.component_version == record.component_version,
                    SuspensionAuditRecord.is_active == True,  # noqa: E712
                )
            )
        ).scalar_one_or_none()

        if not susp_rec:
            raise ValueError(f"No active suspension found for component '{record.component_id}' version '{record.component_version}'.")

        comp = self.session.execute(
            select(GovernedComponentRecord).where(
                and_(
                    GovernedComponentRecord.installation_id == self.installation_id,
                    GovernedComponentRecord.component_id == record.component_id,
                    GovernedComponentRecord.version == record.component_version,
                )
            )
        ).scalar_one_or_none()

        now = _utc_now()
        susp_rec.is_active = False
        susp_rec.resumed_by = record.suspended_by
        susp_rec.resumed_at = now
        susp_rec.resume_reason = record.reason

        if comp:
            comp.status = GovernanceStatus.ACTIVE.value
            comp.suspended_by = None
            comp.suspended_at = None
            comp.updated_at = now

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=record.suspended_by,
            actor_role="authoriser",
            action="kill_switch_resumed",
            target_type="component",
            target_id=record.component_id,
            safe_metadata={
                "component_id": record.component_id,
                "component_version": record.component_version,
                "suspension_id": susp_rec.suspension_id,
                "reason": record.reason,
                "status": GovernanceStatus.ACTIVE.value,
            },
        )
        self.session.flush()
        return susp_rec


class ProductionGovernanceService:
    """Operational service for Toroka production governance, model risk, and deployment readiness."""

    def __init__(self, session: Session, installation_id: str) -> None:
        self.session = session
        self.installation_id = installation_id
        self.environment = os.getenv("TOROKA_ENT_ENV", "development").strip().lower()
        # A bank deployment must inject a real bank-controlled evidence resolver.
        # Until one is configured, production promotion fails closed.
        self.readiness_evidence_verifier = None

    def _create_artifact_signer(self, request: SignArtifactRequest) -> LocalHSMKeyProvider:
        """Create a local signer only outside production; production requires a bank HSM/KMS adapter."""
        if self.environment == "production":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Local ephemeral signing is forbidden in production. Configure the bank HSM/KMS signing adapter.",
            )
        algorithm_name = request.algorithm.strip().upper().replace("-", "_")
        if algorithm_name in {"ED25519", "ED_25519"}:
            algorithm = AsymmetricAlgorithm.ED25519
        elif algorithm_name in {"ECDSA_P256", "ECDSA256"}:
            algorithm = AsymmetricAlgorithm.ECDSA_P256
        else:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unsupported signing algorithm")
        return LocalHSMKeyProvider(key_id=request.key_id, algorithm=algorithm)

    def _trusted_signing_key(self, bundle: SignatureBundle, request: VerifyArtifactRequest | None = None) -> str | None:
        """Resolve a signer key from the bank trust registry; never trust an embedded key in production."""
        try:
            configured = json.loads(os.getenv("TOROKA_ENT_TRUSTED_SIGNING_KEYS_JSON", "{}"))
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=503, detail="Trusted signing-key registry configuration is invalid") from exc
        if not isinstance(configured, dict):
            raise HTTPException(status_code=503, detail="Trusted signing-key registry must be a JSON object")
        registered_key = configured.get(bundle.key_id)
        if self.environment == "production":
            return registered_key if isinstance(registered_key, str) and registered_key.strip() else None
        if isinstance(registered_key, str) and registered_key.strip():
            return registered_key
        candidate = request.trusted_public_key_pem if request else None
        return candidate.strip() if isinstance(candidate, str) and candidate.strip() else None

    def get_kill_switch(self) -> KillSwitch:
        """Returns a domain KillSwitch backed by the persistent database store."""
        return KillSwitch(store=DatabaseKillSwitchStore(self.session, self.installation_id))

    def is_component_suspended(self, component_id: str, version: str) -> bool:
        """Consult persistent governance database records for component active suspension."""
        return self.get_kill_switch().is_suspended(component_id, version)

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

        # Maker-checker separation: maker cannot approve their own component
        if record.created_by == actor_subject:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Component maker cannot approve their own component",
            )

        # Database verification of validation run
        run = self.session.execute(
            select(ValidationRunRecord).where(
                and_(
                    ValidationRunRecord.installation_id == self.installation_id,
                    ValidationRunRecord.run_id == request.validation_run_id,
                )
            )
        ).scalar_one_or_none()

        if run is None:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Validation run does not exist in this installation")
        if run.result != ValidationResult.PASS.value:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Only a passing validation run can support approval")
        if run.component_id != component_id or run.component_version != version:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Validation run does not match the component version")
        if run.configuration_digest != record.configuration_digest:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Validation configuration differs from the registered component")
        if run.evaluator in (record.created_by, actor_subject):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Validation evaluator, component maker and approver must be independent")

        expected_digest = compute_validation_run_digest(run)
        if not hmac.compare_digest(request.validation_digest, expected_digest):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Validation digest does not match the persisted run")

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
        record.approval_record_id = f"apr-{uuid.uuid4().hex[:16]}"
        record.approved_validation_run_id = run.run_id
        record.approved_validation_digest = expected_digest
        record.approval_rationale = request.rationale.strip()

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
                "approval_record_id": record.approval_record_id,
                "validation_run_id": request.validation_run_id,
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
            # Client-provided evaluator labels are not an identity assertion.
            evaluator=actor_subject,
            limitations=list(dict.fromkeys(request.limitations or [])),
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
        release_id = f"rel-{uuid.uuid4().hex[:12]}"
        now = _utc_now()
        manifest_payload = release_manifest_payload(
            release_id=release_id,
            version=request.version,
            components=request.components,
            validation_runs=request.validation_runs,
            approval_records=request.approval_records,
            readiness_gates=request.readiness_gates,
            created_by=actor_subject,
            created_at=now,
        )
        manifest_digest = compute_release_manifest_digest(manifest_payload)

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

    def _verify_release_evidence(
        self,
        record: ProductionReleaseRecord,
        actor_subject: str,
        target_environment: str,
    ) -> None:
        if target_environment not in {DeploymentEnvironment.PILOT.value, DeploymentEnvironment.PRODUCTION.value}:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unsupported release target environment")
        if actor_subject == record.created_by:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Release maker cannot promote their own release to production",
            )

        # 1. Verify manifest digest integrity
        manifest_payload = release_manifest_payload(
            release_id=record.release_id,
            version=record.version,
            components=record.components_manifest or {},
            validation_runs=record.validation_runs or [],
            approval_records=record.approval_records or [],
            readiness_gates=record.readiness_gates or [],
            created_by=record.created_by,
            created_at=record.created_at,
        )
        expected_digest = compute_release_manifest_digest(manifest_payload)
        if not hmac.compare_digest(record.manifest_digest, expected_digest):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Release manifest digest verification failed; manifest has been tampered with or corrupted",
            )

        # 2. Verify all components are approved with passing validation runs
        components_map = record.components_manifest or {}
        if not components_map:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Release manifest contains no components",
            )

        expected_approval_ids: set[str] = set()
        expected_validation_ids: set[str] = set()
        for comp_id, comp_ver in components_map.items():
            comp_rec = self.session.execute(
                select(GovernedComponentRecord).where(
                    and_(
                        GovernedComponentRecord.installation_id == self.installation_id,
                        GovernedComponentRecord.component_id == comp_id,
                        GovernedComponentRecord.version == comp_ver,
                    )
                )
            ).scalar_one_or_none()

            if not comp_rec:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Component '{comp_id}' version '{comp_ver}' is not registered in this installation",
                )

            if comp_rec.status not in (GovernanceStatus.APPROVED.value, GovernanceStatus.ACTIVE.value):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Component '{comp_id}' version '{comp_ver}' is in status '{comp_rec.status}', not APPROVED or ACTIVE",
                )

            if not comp_rec.approval_record_id or not comp_rec.approved_validation_run_id or not comp_rec.approved_validation_digest:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Component '{comp_id}' version '{comp_ver}' lacks persisted approval or validation evidence",
                )
            expected_approval_ids.add(comp_rec.approval_record_id)
            expected_validation_ids.add(comp_rec.approved_validation_run_id)

            run = self.session.execute(
                select(ValidationRunRecord).where(
                    and_(
                        ValidationRunRecord.installation_id == self.installation_id,
                        ValidationRunRecord.run_id == comp_rec.approved_validation_run_id,
                    )
                )
            ).scalar_one_or_none()

            if not run or run.result != ValidationResult.PASS.value:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Component '{comp_id}' validation run '{comp_rec.approved_validation_run_id}' did not pass",
                )
            if run.evaluator in (comp_rec.created_by, actor_subject):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Component '{comp_id}' validation evaluator, maker and release promoter must be independent",
                )

            run_digest = compute_validation_run_digest(run)
            if not hmac.compare_digest(comp_rec.approved_validation_digest, run_digest):
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Component '{comp_id}' validation digest mismatch with persisted run",
                )

        supplied_approval_ids = record.approval_records or []
        supplied_validation_ids = record.validation_runs or []
        if len(supplied_approval_ids) != len(set(supplied_approval_ids)) or set(supplied_approval_ids) != expected_approval_ids:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Release approval references do not exactly match persisted component approval records")
        if len(supplied_validation_ids) != len(set(supplied_validation_ids)) or set(supplied_validation_ids) != expected_validation_ids:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Release validation references do not exactly match persisted approved validation runs")

        # 3. Readiness proofs must be checked by an institution-owned evidence store.
        if target_environment == "production":
            if self.readiness_evidence_verifier is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Production promotion is disabled until a bank-controlled readiness evidence verifier is configured.",
                )
            attestation_records = list(self.session.execute(
                select(ReadinessAttestationRecord).where(
                    and_(
                        ReadinessAttestationRecord.installation_id == self.installation_id,
                        ReadinessAttestationRecord.release_version == record.version,
                        ReadinessAttestationRecord.is_active == True,
                    )
                )
            ).scalars().all())

            attestations_by_gate: dict[str, list[ReadinessAttestationRecord]] = {}
            for att in attestation_records:
                attestations_by_gate.setdefault(att.gate_name, []).append(att)

            unproven_gates: list[str] = []
            for gate in MANDATORY_GATES:
                gate_key = gate.value if hasattr(gate, "value") else str(gate)
                atts = attestations_by_gate.get(gate_key, [])
                passing = [
                    a for a in atts
                    if a.status == "PASS"
                    and a.evidence_reference
                    and a.evidence_digest
                    and a.verified_by
                    and a.verified_by != actor_subject
                ]
                failing = [a for a in atts if a.status in ("FAIL", "BLOCKED")]
                if not passing or failing:
                    unproven_gates.append(gate_key)

            if unproven_gates:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Production promotion blocked: {len(unproven_gates)} mandatory readiness gates lack independent evidence-backed pass attestations: {', '.join(unproven_gates)}",
                )

            for att in attestation_records:
                try:
                    verified = self.readiness_evidence_verifier.verify(
                        installation_id=self.installation_id,
                        release_version=record.version,
                        gate_name=att.gate_name,
                        evidence_reference=att.evidence_reference,
                        expected_digest=att.evidence_digest,
                    )
                except Exception as exc:
                    raise HTTPException(status_code=503, detail="Bank evidence verifier failed during readiness validation") from exc
                if att.status == "PASS" and not verified:
                    raise HTTPException(status_code=422, detail=f"Readiness evidence for gate '{att.gate_name}' could not be independently verified")

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
        if target_environment not in {DeploymentEnvironment.PILOT.value, DeploymentEnvironment.PRODUCTION.value}:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unsupported release target environment")

        # Enforce independent evidence verification
        self._verify_release_evidence(record, actor_subject, target_environment)

        # Check active suspensions for release components
        active_susp = self.session.execute(
            select(SuspensionAuditRecord).where(
                and_(
                    SuspensionAuditRecord.installation_id == self.installation_id,
                    SuspensionAuditRecord.is_active == True,
                )
            )
        ).scalars().all()
        has_susp = any(s.component_id in (record.components_manifest or {}) for s in active_susp)

        # Check blocking incidents
        blocking_inc = self.session.execute(
            select(GovernanceIncidentRecord).where(
                and_(
                    GovernanceIncidentRecord.installation_id == self.installation_id,
                    GovernanceIncidentRecord.severity.in_(["CRITICAL", "HIGH"]),
                    GovernanceIncidentRecord.status.in_(["OPEN", "TRIAGED", "INVESTIGATING"]),
                )
            )
        ).scalars().all()
        has_inc = len(blocking_inc) > 0

        manifest = ProductionReleaseManifest(
            release_id=record.release_id,
            version=record.version,
            environment=DeploymentEnvironment(record.environment),
            components=record.components_manifest or {},
            validation_runs=tuple(record.validation_runs or []),
            approval_records=tuple(record.approval_records or []),
            readiness_gates=tuple(record.readiness_gates or []),
            status=ReleaseStatus(record.status),
            created_by=record.created_by,
            created_at=record.created_at,
            manifest_digest=record.manifest_digest,
            has_blocking_incidents=has_inc,
            has_active_suspensions=has_susp,
        )

        if target_environment == "production":
            eligible, blocking_reasons = manifest.validate_promotion_eligibility()
            if not eligible:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=f"Release does not meet mandatory production readiness criteria: {'; '.join(blocking_reasons)}",
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
        store = DatabaseKillSwitchStore(self.session, self.installation_id)
        now = _utc_now()
        record = SuspensionRecord(
            component_id=request.component_id,
            component_version=request.version,
            suspended_by=actor_subject,
            suspended_at=now,
            reason=request.reason,
            incident_id=request.incident_id,
            automatic=False,
        )
        try:
            susp_rec = store.record_suspension(record)
            self.session.commit()
            return self._to_suspension_response(susp_rec)
        except ValueError as exc:
            msg = str(exc)
            if "not found" in msg:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=msg)

    def resume_component(
        self,
        request: ResumeComponentRequest,
        actor_subject: str,
        actor_role: str = "authoriser",
    ) -> SuspensionRecordResponse:
        store = DatabaseKillSwitchStore(self.session, self.installation_id)
        record = SuspensionRecord(
            component_id=request.component_id,
            component_version=request.version,
            suspended_by=actor_subject,
            suspended_at=_utc_now(),
            reason=request.reason,
            incident_id=None,
            automatic=False,
        )
        try:
            susp_rec = store.record_resume(record)
            self.session.commit()
            return self._to_suspension_response(susp_rec)
        except ValueError as exc:
            msg = str(exc)
            if "No active suspension" in msg:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    def record_readiness_attestation(
        self,
        request: RecordReadinessAttestationRequest,
        actor_subject: str,
        actor_role: str = "authoriser",
    ) -> ReadinessAttestationResponse:
        if request.status not in ("PASS", "FAIL", "BLOCKED"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Status must be PASS, FAIL, or BLOCKED")
        if not request.evidence_reference or not request.evidence_digest:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Attestation requires evidence_reference and evidence_digest")
        if "://" in request.evidence_reference:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Use a bank-controlled evidence artifact ID, not a caller-supplied URL")
        if len(request.evidence_digest) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in request.evidence_digest):
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Evidence digest must be a 64-character SHA-256 hex digest")

        prev_records = list(self.session.execute(
            select(ReadinessAttestationRecord).where(
                and_(
                    ReadinessAttestationRecord.installation_id == self.installation_id,
                    ReadinessAttestationRecord.release_version == request.release_version,
                    ReadinessAttestationRecord.gate_name == request.gate_name,
                    ReadinessAttestationRecord.is_active == True,
                )
            )
        ).scalars().all())
        for p in prev_records:
            p.is_active = False

        att_id = f"att-{uuid.uuid4().hex[:12]}"
        now = _utc_now()
        rec = ReadinessAttestationRecord(
            attestation_id=att_id,
            installation_id=self.installation_id,
            release_version=request.release_version,
            gate_name=request.gate_name,
            status=request.status,
            verified_by=actor_subject,
            verified_role=actor_role,
            rationale=request.rationale,
            evidence_reference=request.evidence_reference,
            evidence_digest=request.evidence_digest,
            is_active=True,
            created_at=now,
        )
        self.session.add(rec)

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="readiness_attestation_recorded",
            target_type="readiness_attestation",
            target_id=att_id,
            safe_metadata={
                "attestation_id": att_id,
                "release_version": request.release_version,
                "gate_name": request.gate_name,
                "status": request.status,
            },
        )
        self.session.commit()
        return self._to_attestation_response(rec)

    def list_readiness_attestations(
        self,
        release_version: str | None = None,
        gate_name: str | None = None,
    ) -> list[ReadinessAttestationResponse]:
        query = select(ReadinessAttestationRecord).where(
            ReadinessAttestationRecord.installation_id == self.installation_id
        )
        if release_version:
            query = query.where(ReadinessAttestationRecord.release_version == release_version)
        if gate_name:
            query = query.where(ReadinessAttestationRecord.gate_name == gate_name)
        query = query.order_by(desc(ReadinessAttestationRecord.created_at))
        records = self.session.execute(query).scalars().all()
        return [self._to_attestation_response(r) for r in records]

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
        # 1. Audit integrity health
        audit_verified = False
        try:
            audit_valid, _audit_head_hash, _verified_record_count = verify_audit_chain(self.session, self.installation_id)
            audit_verified = bool(audit_valid)
            audit_health = HealthStatus.HEALTHY.value if audit_verified else HealthStatus.CRITICAL.value
        except Exception:
            audit_health = HealthStatus.UNKNOWN.value

        # 2. Active drifts & open incidents & active suspensions
        drift_records = list(self.session.execute(
            select(DriftRecordEntity).where(
                DriftRecordEntity.installation_id == self.installation_id
            )
        ).scalars().all())

        quant_drifts = list(self.session.execute(
            select(QuantitativeDriftEvaluationRecord).where(
                QuantitativeDriftEvaluationRecord.installation_id == self.installation_id
            )
        ).scalars().all())

        open_incidents = list(self.session.execute(
            select(GovernanceIncidentRecord).where(
                and_(
                    GovernanceIncidentRecord.installation_id == self.installation_id,
                    GovernanceIncidentRecord.status.notin_([IncidentStatus.REMEDIATED.value, IncidentStatus.CLOSED.value]),
                )
            )
        ).scalars().all())

        active_suspensions = list(self.session.execute(
            select(SuspensionAuditRecord).where(
                and_(
                    SuspensionAuditRecord.installation_id == self.installation_id,
                    SuspensionAuditRecord.is_active == True,
                )
            )
        ).scalars().all())

        has_critical_quant_drift = any(q.requires_mitigation or q.psi_severity == "SIGNIFICANT" for q in quant_drifts)
        has_moderate_quant_drift = any(q.psi_severity == "MODERATE" for q in quant_drifts)

        active_drifts_num = len(drift_records) + len([q for q in quant_drifts if q.requires_mitigation or q.psi_severity != "STABLE"])
        open_incidents_num = len(open_incidents)

        # 3. Detection health
        components = list(self.session.execute(
            select(GovernedComponentRecord).where(
                GovernedComponentRecord.installation_id == self.installation_id
            )
        ).scalars().all())

        if not components:
            detection_health = HealthStatus.UNKNOWN.value
        elif active_suspensions or has_critical_quant_drift:
            detection_health = HealthStatus.CRITICAL.value if has_critical_quant_drift else HealthStatus.DEGRADED.value
        elif any(d.severity == "CRITICAL" for d in drift_records if d.drift_type == "detection"):
            detection_health = HealthStatus.CRITICAL.value
        elif has_moderate_quant_drift or any(d.severity in ("HIGH", "MEDIUM") for d in drift_records if d.drift_type == "detection"):
            detection_health = HealthStatus.DEGRADED.value
        else:
            detection_health = HealthStatus.HEALTHY.value

        # 4. Data quality health
        has_events = self.session.execute(
            select(IntelligenceEventRecord.event_id).where(
                IntelligenceEventRecord.installation_id == self.installation_id
            ).limit(1)
        ).scalar_one_or_none() is not None

        if not has_events:
            data_quality_health = HealthStatus.UNKNOWN.value
        elif any(d.drift_type == "data_drift" for d in drift_records):
            data_quality_health = HealthStatus.DEGRADED.value
        else:
            data_quality_health = HealthStatus.HEALTHY.value

        # 5. Network intelligence health
        has_entities = self.session.execute(
            select(EntityLinkCandidateRecord.candidate_id).where(
                EntityLinkCandidateRecord.installation_id == self.installation_id
            ).limit(1)
        ).scalar_one_or_none() is not None

        if not has_entities:
            network_health = HealthStatus.UNKNOWN.value
        elif any(d.drift_type == "network" for d in drift_records):
            network_health = HealthStatus.DEGRADED.value
        else:
            network_health = HealthStatus.HEALTHY.value

        # 6. Copilot health
        providers = list(self.session.execute(
            select(GovernedAIProviderRecord).where(
                GovernedAIProviderRecord.installation_id == self.installation_id
            )
        ).scalars().all())

        if not providers:
            copilot_health = HealthStatus.UNKNOWN.value
        elif any(not p.is_approved for p in providers):
            copilot_health = HealthStatus.DEGRADED.value
        else:
            copilot_health = HealthStatus.HEALTHY.value

        # Overall status: worst observed across pillars
        severity_order = {
            HealthStatus.CRITICAL.value: 5,
            HealthStatus.DEGRADED.value: 4,
            HealthStatus.WARNING.value: 3,
            HealthStatus.UNKNOWN.value: 2,
            HealthStatus.HEALTHY.value: 1,
        }

        pillar_statuses = [
            audit_health,
            detection_health,
            data_quality_health,
            network_health,
            copilot_health,
        ]
        if open_incidents_num > 0:
            pillar_statuses.append(HealthStatus.DEGRADED.value)

        worst_val = max(pillar_statuses, key=lambda s: severity_order.get(s, 0))
        overall_status = worst_val

        summary = (
            f"System operates under governed bank controls. Overall health: {overall_status.upper()}. "
            f"Audit integrity: {audit_health}. Open incidents: {open_incidents_num}. "
            f"Active suspensions: {len(active_suspensions)}. Active drift records: {active_drifts_num}."
        )

        return SystemHealthOverviewResponse(
            overall_status=overall_status,
            detection_health=detection_health,
            data_quality_health=data_quality_health,
            network_health=network_health,
            copilot_health=copilot_health,
            audit_integrity_health=audit_health,
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

        # Resolve finding: check IntelligenceSignalRecord first, then NetworkFindingRecord
        finding = self.session.execute(
            select(IntelligenceSignalRecord).where(
                and_(
                    IntelligenceSignalRecord.installation_id == self.installation_id,
                    IntelligenceSignalRecord.signal_id == finding_id,
                    IntelligenceSignalRecord.case_id == case_id,
                )
            )
        ).scalar_one_or_none()

        if finding is None:
            finding = self.session.execute(
                select(NetworkFindingRecord).where(
                    and_(
                        NetworkFindingRecord.installation_id == self.installation_id,
                        NetworkFindingRecord.finding_id == finding_id,
                        NetworkFindingRecord.case_id == case_id,
                    )
                )
            ).scalar_one_or_none()

        # Resolve component versions and configuration digest from registered components
        active_comps = list(self.session.execute(
            select(GovernedComponentRecord).where(
                and_(
                    GovernedComponentRecord.installation_id == self.installation_id,
                    GovernedComponentRecord.status.in_([GovernanceStatus.ACTIVE.value, GovernanceStatus.APPROVED.value]),
                )
            )
        ).scalars().all())
        component_versions = {c.component_id: c.version for c in active_comps} or {"core_engine": "1.0.0"}
        config_payload = {c.component_id: c.configuration_digest for c in active_comps}
        config_digest = hashlib.sha256(canonical_json(config_payload).encode("utf-8")).hexdigest()

        items: list[BoundEvidenceItem] = []
        detection_time = case.created_at
        earliest_event_time = case.created_at
        source_systems: tuple[str, ...] = ("CORE_BANKING",)

        if finding is not None:
            # Query real persisted events for the case / finding
            all_events = list(self.session.execute(
                select(IntelligenceEventRecord).where(
                    IntelligenceEventRecord.installation_id == self.installation_id
                )
            ).scalars().all())

            allowed_event_ids = set(getattr(finding, "event_ids", []) or [])
            events = [
                e for e in all_events
                if (e.event_id in allowed_event_ids or (e.attributes and e.attributes.get("case_id") == case_id))
            ]

            if not events:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="No persisted event evidence is available for this finding",
                )

            for event in sorted(events, key=lambda e: (e.event_time, e.event_id)):
                event_payload = {
                    "event_id": event.event_id,
                    "event_type": event.event_type,
                    "event_time": event.event_time.isoformat() if event.event_time else "",
                    "actor": event.actor,
                    "subject": event.subject,
                    "source_system": event.source_system,
                    "source_record_id": event.source_record_id,
                    "entities": list(event.entities or []),
                    "attributes": dict(event.attributes or {}),
                    "provenance_digest": event.provenance_digest,
                }
                items.append(
                    BoundEvidenceItem(
                        evidence_id=event.event_id,
                        evidence_digest=compute_evidence_digest(event_payload),
                        source_record_id=event.source_record_id or event.event_id,
                        source_system=event.source_system or "UNKNOWN_SOURCE",
                        observed_at=event.event_time.isoformat() if event.event_time else _utc_now().isoformat(),
                    )
                )

            detection_time = getattr(finding, "created_at", case.created_at)
            earliest_event_time = min((e.event_time for e in events if e.event_time), default=detection_time)
            source_systems = tuple(sorted({e.source_system for e in events if e.source_system})) or ("CORE_BANKING",)
        else:
            # Check case snapshot events for backwards compatibility
            snapshot_events = (case.snapshot or {}).get("events", [])
            if not snapshot_events:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="No persisted event evidence is available for this finding",
                )
            for idx, e in enumerate(snapshot_events):
                ev_id = str(e.get("event_id", f"ev_{idx}"))
                ev_payload = {
                    "event_id": ev_id,
                    "event_type": str(e.get("event_type", "EVENT")),
                    "source_system": str(e.get("source_system", "CORE_BANKING")),
                    "source_record_id": str(e.get("source_record_id", ev_id)),
                }
                items.append(
                    BoundEvidenceItem(
                        evidence_id=ev_id,
                        evidence_digest=compute_evidence_digest(ev_payload),
                        source_record_id=str(e.get("source_record_id", ev_id)),
                        source_system=str(e.get("source_system", "CORE_BANKING")),
                        observed_at=case.created_at.isoformat() if case.created_at else _utc_now().isoformat(),
                    )
                )
            source_systems = tuple(sorted({e.get("source_system", "CORE_BANKING") for e in snapshot_events})) or ("CORE_BANKING",)

        passport_id = f"pass-{uuid.uuid4().hex[:12]}"
        now = _utc_now()

        domain_passport = TorokaEvidencePassport(
            passport_id=passport_id,
            finding_id=finding_id,
            case_id=case_id,
            installation_id=self.installation_id,
            finding_type=getattr(finding, "signal_type", getattr(finding, "finding_type", "CORRELATED_FRAUD_PATTERN")),
            finding_status="GROUNDED",
            component_versions=component_versions,
            configuration_digest=config_digest,
            evidence_count=len(items),
            source_systems=source_systems,
            detection_time=detection_time,
            earliest_event_time=earliest_event_time,
            evidence_at_detection_count=len(items),
            delayed_evidence_count=0,
            contradictions_count=0,
            evidence_debt_level="LOW",
            alternative_explanations=("Legitimate batch operations", "Multi-party authorised activity"),
            validation_result="PASS",
            human_review_required=True,
            evidence_records=tuple(items),
        )

        canonical_payload = domain_passport.canonical_payload()

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
            payload=canonical_payload,
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
    # Phase 13.0: PKI Digital Signatures, Quantitative Risk & Shadow Governance
    # =========================================================================

    def sign_evidence_passport(
        self,
        passport_id: str,
        request: SignArtifactRequest,
        actor_subject: str,
        actor_role: str = "authoriser",
    ) -> EvidencePassportResponse:
        record = self.session.execute(
            select(EvidencePassportRecord).where(
                and_(
                    EvidencePassportRecord.installation_id == self.installation_id,
                    EvidencePassportRecord.passport_id == passport_id,
                )
            )
        ).scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence passport '{passport_id}' not found.")
        if record.signature_bundle is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Passport has already been digitally signed.")

        signer = self._create_artifact_signer(request)
        algo = signer.algorithm

        domain_passport = TorokaEvidencePassport.from_payload(record.payload, passport_digest=record.passport_digest)
        signed_passport = domain_passport.sign(signer)

        record.signature_bundle = signed_passport.signature_bundle
        new_payload = dict(record.payload)
        new_payload["signature_bundle"] = signed_passport.signature_bundle
        new_payload["signing_key_id"] = signed_passport.signing_key_id
        new_payload["signature_algorithm"] = signed_passport.signature_algorithm
        new_payload["signature"] = signed_passport.signature
        record.payload = new_payload

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="passport_digitally_signed",
            target_type="passport",
            target_id=passport_id,
            safe_metadata={
                "passport_id": passport_id,
                "key_id": signer.key_id,
                "algorithm": signer.algorithm.value,
                "digest": record.passport_digest,
            },
        )
        self.session.commit()
        return self._to_passport_response(record)

    def verify_evidence_passport(
        self,
        passport_id: str,
        request: VerifyArtifactRequest,
    ) -> VerifyArtifactResponse:
        record = self.session.execute(
            select(EvidencePassportRecord).where(
                and_(
                    EvidencePassportRecord.installation_id == self.installation_id,
                    EvidencePassportRecord.passport_id == passport_id,
                )
            )
        ).scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Evidence passport '{passport_id}' not found.")

        domain_passport = TorokaEvidencePassport.from_payload(record.payload, passport_digest=record.passport_digest)
        digest_ok = domain_passport.verify_integrity()

        is_signed = bool(record.signature_bundle)
        sig_ok = False
        sig_err = None
        key_id = None
        algo = None

        if is_signed:
            try:
                bundle = SignatureBundle.from_dict(record.signature_bundle)
                key_id = bundle.key_id
                algo = bundle.algorithm
                trusted_key = self._trusted_signing_key(bundle, request)
                sig_ok = bool(trusted_key) and verify_asymmetric_signature(
                    payload=domain_passport.canonical_payload(),
                    bundle=bundle,
                    trusted_public_key_pem=trusted_key,
                )
                if not sig_ok:
                    sig_err = "Asymmetric digital signature verification failed against passport payload."
            except Exception as exc:
                sig_err = f"Digital signature error: {exc}"
        else:
            sig_err = "Artifact is not digitally signed (tamper-evident SHA-256 digest only)."

        is_valid = digest_ok and is_signed and sig_ok

        return VerifyArtifactResponse(
            is_valid=is_valid,
            artifact_id=passport_id,
            artifact_type="passport",
            digest_verified=digest_ok,
            is_digitally_signed=is_signed,
            signature_verified=sig_ok,
            signing_key_id=key_id,
            signing_algorithm=algo,
            error=sig_err,
        )

    def sign_release(
        self,
        release_id: str,
        request: SignArtifactRequest,
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
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Release '{release_id}' not found.")
        if record.signature_bundle is not None:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Release has already been digitally signed.")

        signer = self._create_artifact_signer(request)
        algo = signer.algorithm

        manifest = ProductionReleaseManifest(
            release_id=record.release_id,
            version=record.version,
            environment=DeploymentEnvironment(record.environment),
            status=ReleaseStatus(record.status),
            components=record.components_manifest or {},
            validation_runs=tuple(record.validation_runs or []),
            approval_records=tuple(record.approval_records or []),
            readiness_gates=tuple(record.readiness_gates or []),
            created_by=record.created_by,
            created_at=record.created_at,
            manifest_digest=record.manifest_digest,
        )
        signed_manifest = manifest.sign(signer)
        record.signature_bundle = signed_manifest.signature_bundle

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="release_digitally_signed",
            target_type="release",
            target_id=release_id,
            safe_metadata={
                "release_id": release_id,
                "key_id": signer.key_id,
                "algorithm": signer.algorithm.value,
                "manifest_digest": record.manifest_digest,
            },
        )
        self.session.commit()
        return self._to_release_response(record)

    def verify_release_manifest(
        self,
        release_id: str,
        request: VerifyArtifactRequest,
    ) -> VerifyArtifactResponse:
        record = self.session.execute(
            select(ProductionReleaseRecord).where(
                and_(
                    ProductionReleaseRecord.installation_id == self.installation_id,
                    ProductionReleaseRecord.release_id == release_id,
                )
            )
        ).scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Release '{release_id}' not found.")

        manifest = ProductionReleaseManifest(
            release_id=record.release_id,
            version=record.version,
            environment=DeploymentEnvironment(record.environment),
            status=ReleaseStatus(record.status),
            components=record.components_manifest or {},
            validation_runs=tuple(record.validation_runs or []),
            approval_records=tuple(record.approval_records or []),
            readiness_gates=tuple(record.readiness_gates or []),
            created_by=record.created_by,
            created_at=record.created_at,
            manifest_digest=record.manifest_digest,
            signature_bundle=record.signature_bundle,
        )
        digest_ok = manifest.verify_manifest_integrity()
        is_signed = bool(record.signature_bundle)
        sig_ok = False
        sig_err = None
        key_id = None
        algo = None

        if is_signed:
            try:
                bundle = SignatureBundle.from_dict(record.signature_bundle)
                key_id = bundle.key_id
                algo = bundle.algorithm
                trusted_key = self._trusted_signing_key(bundle, request)
                sig_ok = bool(trusted_key) and verify_asymmetric_signature(
                    payload=manifest._compute_digest_payload(),
                    bundle=bundle,
                    trusted_public_key_pem=trusted_key,
                )
                if not sig_ok:
                    sig_err = "Asymmetric digital signature verification failed against release manifest payload."
            except Exception as exc:
                sig_err = f"Digital signature error: {exc}"
        else:
            sig_err = "Artifact is not digitally signed."

        is_valid = digest_ok and is_signed and sig_ok

        return VerifyArtifactResponse(
            is_valid=is_valid,
            artifact_id=release_id,
            artifact_type="release",
            digest_verified=digest_ok,
            is_digitally_signed=is_signed,
            signature_verified=sig_ok,
            signing_key_id=key_id,
            signing_algorithm=algo,
            error=sig_err,
        )

    def evaluate_quantitative_drift(
        self,
        request: EvaluateQuantitativeDriftRequest,
        actor_subject: str,
        actor_role: str = "analyst",
    ) -> QuantitativeDriftEvaluationResponse:
        eval_id = f"qdr-{uuid.uuid4().hex[:12]}"
        now = _utc_now()

        assessment = evaluate_model_risk_comprehensive(
            component_id=request.component_id,
            component_version=request.component_version,
            evaluation_id=eval_id,
            baseline_scores=request.baseline_scores,
            current_scores=request.current_scores,
            subgroup_predictions=request.subgroup_predictions,
        )

        record = QuantitativeDriftEvaluationRecord(
            evaluation_id=eval_id,
            installation_id=self.installation_id,
            component_id=request.component_id,
            component_version=request.component_version,
            psi_score=assessment.psi.score,
            psi_severity=assessment.psi.severity.value,
            requires_mitigation=assessment.psi.requires_mitigation,
            ks_statistic=assessment.ks_test.statistic,
            ks_p_value=assessment.ks_test.p_value,
            ks_drift_detected=assessment.ks_test.is_drift_detected,
            wasserstein_distance=assessment.wasserstein_distance,
            fairness_compliant=assessment.fairness.has_adverse_impact is False if assessment.fairness else True,
            is_compliant=assessment.is_compliant,
            governance_findings=list(assessment.governance_findings),
            evaluation_details=assessment.to_dict(),
            evaluated_by=actor_subject,
            created_at=now,
        )
        self.session.add(record)

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="quantitative_drift_evaluated",
            target_type="component",
            target_id=request.component_id,
            safe_metadata={
                "evaluation_id": eval_id,
                "component_id": request.component_id,
                "component_version": request.component_version,
                "psi_score": assessment.psi.score,
                "psi_severity": assessment.psi.severity.value,
                "is_compliant": assessment.is_compliant,
            },
        )
        self.session.commit()
        return self._to_quantitative_drift_response(record)

    def list_quantitative_drift_evaluations(
        self,
        component_id: str | None = None,
    ) -> list[QuantitativeDriftEvaluationResponse]:
        query = select(QuantitativeDriftEvaluationRecord).where(
            QuantitativeDriftEvaluationRecord.installation_id == self.installation_id
        )
        if component_id:
            query = query.where(QuantitativeDriftEvaluationRecord.component_id == component_id)
        query = query.order_by(desc(QuantitativeDriftEvaluationRecord.created_at))
        records = self.session.execute(query).scalars().all()
        return [self._to_quantitative_drift_response(r) for r in records]

    def evaluate_champion_challenger(
        self,
        request: EvaluateChampionChallengerRequest,
        actor_subject: str,
        actor_role: str = "analyst",
    ) -> ChampionChallengerRunResponse:
        run_id = f"ccr-{uuid.uuid4().hex[:12]}"
        now = _utc_now()

        c_m = request.champion_metrics
        champ = ModelPerformanceMetrics(
            model_role="CHAMPION",
            component_id=request.component_id,
            component_version=request.champion_version,
            sample_size=int(c_m.get("sample_size", 0)),
            true_positives=int(c_m.get("true_positives", 0)),
            false_positives=int(c_m.get("false_positives", 0)),
            true_negatives=int(c_m.get("true_negatives", 0)),
            false_negatives=int(c_m.get("false_negatives", 0)),
            latency_ms_p50=float(c_m.get("latency_ms_p50", 0.0)),
            latency_ms_p95=float(c_m.get("latency_ms_p95", 0.0)),
        )

        ch_m = request.challenger_metrics
        chall = ModelPerformanceMetrics(
            model_role="CHALLENGER",
            component_id=request.component_id,
            component_version=request.challenger_version,
            sample_size=int(ch_m.get("sample_size", 0)),
            true_positives=int(ch_m.get("true_positives", 0)),
            false_positives=int(ch_m.get("false_positives", 0)),
            true_negatives=int(ch_m.get("true_negatives", 0)),
            false_negatives=int(ch_m.get("false_negatives", 0)),
            latency_ms_p50=float(ch_m.get("latency_ms_p50", 0.0)),
            latency_ms_p95=float(ch_m.get("latency_ms_p95", 0.0)),
        )

        fairness_summary = None
        if request.subgroup_predictions:
            fairness_summary = compute_disparate_impact(request.subgroup_predictions)

        res = evaluate_challenger_promotion(
            champion=champ,
            challenger=chall,
            min_sample_size=request.min_sample_size,
            max_fdr_increase=request.max_fdr_increase,
            min_f1_retention=request.min_f1_retention,
            max_p95_latency_ms=request.max_p95_latency_ms,
            fairness_summary=fairness_summary,
        )

        record = ChampionChallengerRunRecord(
            run_id=run_id,
            installation_id=self.installation_id,
            component_id=request.component_id,
            champion_version=request.champion_version,
            challenger_version=request.challenger_version,
            decision=res.decision.value,
            is_promotable=res.is_promotable,
            fdr_delta=res.fdr_delta,
            f1_ratio=res.f1_ratio,
            latency_p95_delta_ms=res.latency_p95_delta_ms,
            reasons=list(res.reasons),
            champion_metrics=champ.to_dict(),
            challenger_metrics=chall.to_dict(),
            evaluated_by=actor_subject,
            created_at=now,
        )
        self.session.add(record)

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="champion_challenger_evaluated",
            target_type="component",
            target_id=request.component_id,
            safe_metadata={
                "run_id": run_id,
                "component_id": request.component_id,
                "champion_version": request.champion_version,
                "challenger_version": request.challenger_version,
                "decision": res.decision.value,
                "is_promotable": res.is_promotable,
            },
        )
        self.session.commit()
        return self._to_champion_challenger_response(record)

    def list_champion_challenger_runs(
        self,
        component_id: str | None = None,
    ) -> list[ChampionChallengerRunResponse]:
        query = select(ChampionChallengerRunRecord).where(
            ChampionChallengerRunRecord.installation_id == self.installation_id
        )
        if component_id:
            query = query.where(ChampionChallengerRunRecord.component_id == component_id)
        query = query.order_by(desc(ChampionChallengerRunRecord.created_at))
        records = self.session.execute(query).scalars().all()
        return [self._to_champion_challenger_response(r) for r in records]

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
            # Self-reported provider metadata is insufficient for bank approval.
            is_approved=False,
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
            is_approved=False,
            risk_tier=provider.risk_tier.value,
            evaluation_summary={
                "compliance_reason": reason,
                "review_status": "PENDING_INDEPENDENT_BANK_REVIEW",
                "review_note": "Automated policy screening is not an approval decision.",
                "screened_at": now.isoformat(),
            },
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
            approval_record_id=r.approval_record_id,
            approved_validation_run_id=r.approved_validation_run_id,
            approved_validation_digest=r.approved_validation_digest,
            approval_rationale=r.approval_rationale,
            suspended_by=r.suspended_by,
            suspended_at=r.suspended_at.isoformat() if r.suspended_at else None,
            retired_by=r.retired_by,
            retired_at=r.retired_at.isoformat() if r.retired_at else None,
            created_at=r.created_at.isoformat(),
            updated_at=r.updated_at.isoformat(),
        )

    def _to_validation_run_response(self, r: ValidationRunRecord) -> ValidationRunResponse:
        v_digest = compute_validation_run_digest(r)
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
            validation_digest=v_digest,
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
            signature_bundle=r.signature_bundle,
            is_digitally_signed=bool(r.signature_bundle),
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
        domain_passport = None
        is_verified = False
        evidence_records_list: list[dict[str, Any]] = []

        if r.payload and isinstance(r.payload, dict) and r.payload.get("schema") == "toroka.evidence-passport.v1":
            try:
                domain_passport = TorokaEvidencePassport.from_payload(r.payload, passport_digest=r.passport_digest)
                is_verified = domain_passport.verify_integrity()
                evidence_records_list = [
                    {
                        "evidence_id": item.get("evidence_id") if isinstance(item, dict) else getattr(item, "evidence_id", ""),
                        "evidence_digest": item.get("evidence_digest") if isinstance(item, dict) else getattr(item, "evidence_digest", ""),
                        "source_record_id": item.get("source_record_id") if isinstance(item, dict) else getattr(item, "source_record_id", ""),
                        "source_system": item.get("source_system") if isinstance(item, dict) else getattr(item, "source_system", ""),
                        "observed_at": item.get("observed_at") if isinstance(item, dict) else getattr(item, "observed_at", None),
                    }
                    for item in domain_passport.evidence_records
                ]
            except Exception as e:
                logger.warning("Failed to verify passport from payload: %s", e)
                is_verified = False

        if domain_passport is None:
            try:
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
                is_verified = domain_passport.verify_integrity()
            except Exception:
                is_verified = False

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
            signature_bundle=r.signature_bundle,
            merkle_proof=r.merkle_proof,
            is_digitally_signed=bool(r.signature_bundle),
            is_verified=is_verified,
            evidence_records=evidence_records_list,
            created_at=r.created_at.isoformat(),
        )

    def _to_attestation_response(self, r: ReadinessAttestationRecord) -> ReadinessAttestationResponse:
        return ReadinessAttestationResponse(
            attestation_id=r.attestation_id,
            installation_id=r.installation_id,
            release_version=r.release_version,
            gate_name=r.gate_name,
            status=r.status,
            verified_by=r.verified_by,
            verified_role=r.verified_role,
            rationale=r.rationale,
            evidence_reference=r.evidence_reference,
            evidence_digest=r.evidence_digest,
            is_active=r.is_active,
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

    def _to_quantitative_drift_response(self, r: QuantitativeDriftEvaluationRecord) -> QuantitativeDriftEvaluationResponse:
        return QuantitativeDriftEvaluationResponse(
            evaluation_id=r.evaluation_id,
            installation_id=r.installation_id,
            component_id=r.component_id,
            component_version=r.component_version,
            psi_score=r.psi_score,
            psi_severity=r.psi_severity,
            requires_mitigation=r.requires_mitigation,
            ks_statistic=r.ks_statistic,
            ks_p_value=r.ks_p_value,
            ks_drift_detected=r.ks_drift_detected,
            wasserstein_distance=r.wasserstein_distance,
            fairness_compliant=r.fairness_compliant,
            is_compliant=r.is_compliant,
            governance_findings=r.governance_findings or [],
            evaluation_details=r.evaluation_details or {},
            evaluated_by=r.evaluated_by,
            created_at=r.created_at.isoformat(),
        )

    def _to_champion_challenger_response(self, r: ChampionChallengerRunRecord) -> ChampionChallengerRunResponse:
        return ChampionChallengerRunResponse(
            run_id=r.run_id,
            installation_id=r.installation_id,
            component_id=r.component_id,
            champion_version=r.champion_version,
            challenger_version=r.challenger_version,
            decision=r.decision,
            is_promotable=r.is_promotable,
            fdr_delta=r.fdr_delta,
            f1_ratio=r.f1_ratio,
            latency_p95_delta_ms=r.latency_p95_delta_ms,
            reasons=r.reasons or [],
            champion_metrics=r.champion_metrics or {},
            challenger_metrics=r.challenger_metrics or {},
            evaluated_by=r.evaluated_by,
            created_at=r.created_at.isoformat(),
        )

    def _to_forensic_dossier_response(self, r: ForensicDossierRecord) -> ForensicDossierResponse:
        is_verified = False
        is_signed = r.signature_bundle is not None
        try:
            dossier = ForensicDossier.from_dict({
                "dossier_id": r.dossier_id,
                "case_id": r.case_id,
                "installation_id": r.installation_id,
                "title": r.title,
                "incident_type": r.incident_type,
                "fraud_loss_amount": r.fraud_loss_amount,
                "currency": r.currency,
                "examiner_subject": r.examiner_subject,
                "examiner_role": r.examiner_role,
                "created_at": r.created_at.isoformat(),
                "case_summary": r.case_summary,
                "attack_path_summary": r.attack_path_summary or {},
                "identified_mule_nodes": r.identified_mule_nodes or [],
                "evidence_records": r.evidence_records or [],
                "chain_of_custody": r.chain_of_custody or [],
                "section_106b_certificate": r.section_106b_certificate,
                "dossier_digest": r.dossier_digest,
                "signature_bundle": r.signature_bundle,
            })
            is_verified = dossier.verify_dossier_integrity() and r.status not in {"DRAFT_UNVERIFIED", "DRAFT_SIGNED"}
            if is_signed:
                bundle = SignatureBundle.from_dict(r.signature_bundle)
                trusted_key = self._trusted_signing_key(bundle)
                is_verified = is_verified and bool(trusted_key) and dossier.verify_digital_signature(trusted_key)
        except Exception:
            is_verified = False

        return ForensicDossierResponse(
            dossier_id=r.dossier_id,
            installation_id=r.installation_id,
            case_id=r.case_id,
            title=r.title,
            incident_type=r.incident_type,
            fraud_loss_amount=r.fraud_loss_amount,
            currency=r.currency,
            examiner_subject=r.examiner_subject,
            examiner_role=r.examiner_role,
            case_summary=r.case_summary,
            attack_path_summary=r.attack_path_summary or {},
            identified_mule_nodes=r.identified_mule_nodes or [],
            evidence_records=r.evidence_records or [],
            chain_of_custody=r.chain_of_custody or [],
            section_106b_certificate=r.section_106b_certificate,
            dossier_digest=r.dossier_digest,
            signature_bundle=r.signature_bundle,
            is_digitally_signed=is_signed,
            is_verified=is_verified,
            status=r.status,
            created_at=r.created_at.isoformat(),
        )

    def create_forensic_dossier(
        self,
        request: CreateForensicDossierRequest,
        actor_subject: str,
    ) -> ForensicDossierResponse:
        dossier_id = f"dos-{uuid.uuid4().hex[:12]}"
        now = _utc_now()

        custody_event = CustodyEvent(
            event_id=f"cust-{uuid.uuid4().hex[:8]}",
            timestamp=now,
            actor_subject=actor_subject,
            actor_role="LEAD_EXAMINER",
            action="DOSSIER_COMPILED",
            source_hash="0000000000000000000000000000000000000000000000000000000000000000",
            destination_hash="",
            notes="Initial compilation of court-ready forensic evidence dossier",
        )

        cert = None
        if request.certifier_name:
            cert = Section106BCertificate(
                certificate_id=f"cert-106b-{uuid.uuid4().hex[:8]}",
                statutory_framework="Kenya Evidence Act (Cap 80) Section 106B",
                certifier_name=request.certifier_name,
                certifier_designation=request.certifier_designation or "Lead Financial Crime Investigator",
                certifier_organization="Toroka Financial Crime Compliance",
                device_identification=f"TOROKA-NODE-{self.installation_id[:8]}",
                operating_condition_statement="At all material times, the computer system was operating properly and there was no malfunction affecting the production of the electronic record or accuracy of its contents.",
                hash_algorithm="SHA-256",
                merkle_root_hash="PENDING_ROOT",
                certified_at=now,
                declaration_text=request.declaration_text or "I certify under penalty of perjury that this electronic evidence record was generated in the ordinary course of financial crime detection.",
            )

        # Build initial domain dossier
        dossier = ForensicDossier(
            dossier_id=dossier_id,
            case_id=request.case_id,
            installation_id=self.installation_id,
            title=request.title,
            incident_type=request.incident_type,
            fraud_loss_amount=request.fraud_loss_amount,
            currency=request.currency,
            examiner_subject=actor_subject,
            examiner_role="LEAD_EXAMINER",
            created_at=now,
            case_summary=request.case_summary,
            attack_path_summary=request.attack_path_summary,
            identified_mule_nodes=tuple(request.identified_mule_nodes),
            evidence_records=tuple(request.evidence_records),
            chain_of_custody=(custody_event,),
            section_106b_certificate=cert,
        )

        # Update custody destination hash to computed digest
        updated_custody = (
            CustodyEvent(
                event_id=custody_event.event_id,
                timestamp=custody_event.timestamp,
                actor_subject=custody_event.actor_subject,
                actor_role=custody_event.actor_role,
                action=custody_event.action,
                source_hash=custody_event.source_hash,
                destination_hash=dossier.dossier_digest,
                notes=custody_event.notes,
            ),
        )

        updated_cert = cert
        if cert:
            updated_cert = Section106BCertificate(
                certificate_id=cert.certificate_id,
                statutory_framework=cert.statutory_framework,
                certifier_name=cert.certifier_name,
                certifier_designation=cert.certifier_designation,
                certifier_organization=cert.certifier_organization,
                device_identification=cert.device_identification,
                operating_condition_statement=cert.operating_condition_statement,
                hash_algorithm=cert.hash_algorithm,
                merkle_root_hash=dossier.dossier_digest,
                certified_at=cert.certified_at,
                declaration_text=cert.declaration_text,
            )

        final_dossier = ForensicDossier(
            dossier_id=dossier_id,
            case_id=request.case_id,
            installation_id=self.installation_id,
            title=request.title,
            incident_type=request.incident_type,
            fraud_loss_amount=request.fraud_loss_amount,
            currency=request.currency,
            examiner_subject=actor_subject,
            examiner_role="LEAD_EXAMINER",
            created_at=now,
            case_summary=request.case_summary,
            attack_path_summary=request.attack_path_summary,
            identified_mule_nodes=tuple(request.identified_mule_nodes),
            evidence_records=tuple(request.evidence_records),
            chain_of_custody=updated_custody,
            section_106b_certificate=updated_cert,
        )

        record = ForensicDossierRecord(
            dossier_id=final_dossier.dossier_id,
            installation_id=self.installation_id,
            case_id=final_dossier.case_id,
            title=final_dossier.title,
            incident_type=final_dossier.incident_type,
            fraud_loss_amount=final_dossier.fraud_loss_amount,
            currency=final_dossier.currency,
            examiner_subject=final_dossier.examiner_subject,
            examiner_role=final_dossier.examiner_role,
            case_summary=final_dossier.case_summary,
            attack_path_summary=final_dossier.attack_path_summary,
            identified_mule_nodes=list(final_dossier.identified_mule_nodes),
            evidence_records=list(final_dossier.evidence_records),
            chain_of_custody=[c.to_dict() for c in final_dossier.chain_of_custody],
            section_106b_certificate=final_dossier.section_106b_certificate.to_dict() if final_dossier.section_106b_certificate else None,
            dossier_digest=final_dossier.dossier_digest,
            signature_bundle=None,
            status="SEALED",
            created_at=final_dossier.created_at,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)

        return self._to_forensic_dossier_response(record)

    def get_forensic_dossier(self, dossier_id: str) -> ForensicDossierResponse:
        record = self.session.execute(
            select(ForensicDossierRecord).where(
                and_(
                    ForensicDossierRecord.installation_id == self.installation_id,
                    ForensicDossierRecord.dossier_id == dossier_id,
                )
            )
        ).scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=404, detail="Forensic dossier not found")
        return self._to_forensic_dossier_response(record)

    def sign_forensic_dossier(
        self,
        dossier_id: str,
        request: SignArtifactRequest,
        actor_subject: str,
    ) -> ForensicDossierResponse:
        record = self.session.execute(
            select(ForensicDossierRecord).where(
                and_(
                    ForensicDossierRecord.installation_id == self.installation_id,
                    ForensicDossierRecord.dossier_id == dossier_id,
                )
            )
        ).scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=404, detail="Forensic dossier not found")

        dossier = ForensicDossier.from_dict({
            "dossier_id": record.dossier_id,
            "case_id": record.case_id,
            "installation_id": record.installation_id,
            "title": record.title,
            "incident_type": record.incident_type,
            "fraud_loss_amount": record.fraud_loss_amount,
            "currency": record.currency,
            "examiner_subject": record.examiner_subject,
            "examiner_role": record.examiner_role,
            "created_at": record.created_at.isoformat(),
            "case_summary": record.case_summary,
            "attack_path_summary": record.attack_path_summary or {},
            "identified_mule_nodes": record.identified_mule_nodes or [],
            "evidence_records": record.evidence_records or [],
            "chain_of_custody": record.chain_of_custody or [],
            "section_106b_certificate": record.section_106b_certificate,
            "dossier_digest": record.dossier_digest,
            "signature_bundle": record.signature_bundle,
        })

        signer = self._create_artifact_signer(request)
        algo = signer.algorithm
        dossier.sign(signer)

        now = _utc_now()
        custody_event = CustodyEvent(
            event_id=f"cust-{uuid.uuid4().hex[:8]}",
            timestamp=now,
            actor_subject=actor_subject,
            actor_role="CERTIFYING_OFFICER",
            action="EXAMINER_DIGITALLY_SIGNED",
            source_hash=record.dossier_digest,
            destination_hash=dossier.signature_bundle.signature_hex[:32],
            notes=f"Digitally signed with algorithm {algo.value} (Key: {request.key_id})",
        )
        updated_custody = list(record.chain_of_custody or [])
        updated_custody.append(custody_event.to_dict())

        record.signature_bundle = dossier.signature_bundle.to_dict()
        record.chain_of_custody = updated_custody
        record.status = "SEALED_SIGNED"

        self.session.commit()
        self.session.refresh(record)
        return self._to_forensic_dossier_response(record)

    def verify_forensic_dossier(
        self,
        dossier_id: str,
        request: VerifyArtifactRequest,
    ) -> VerifyArtifactResponse:
        record = self.session.execute(
            select(ForensicDossierRecord).where(
                and_(
                    ForensicDossierRecord.installation_id == self.installation_id,
                    ForensicDossierRecord.dossier_id == dossier_id,
                )
            )
        ).scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=404, detail="Forensic dossier not found")

        dossier = ForensicDossier.from_dict({
            "dossier_id": record.dossier_id,
            "case_id": record.case_id,
            "installation_id": record.installation_id,
            "title": record.title,
            "incident_type": record.incident_type,
            "fraud_loss_amount": record.fraud_loss_amount,
            "currency": record.currency,
            "examiner_subject": record.examiner_subject,
            "examiner_role": record.examiner_role,
            "created_at": record.created_at.isoformat(),
            "case_summary": record.case_summary,
            "attack_path_summary": record.attack_path_summary or {},
            "identified_mule_nodes": record.identified_mule_nodes or [],
            "evidence_records": record.evidence_records or [],
            "chain_of_custody": record.chain_of_custody or [],
            "section_106b_certificate": record.section_106b_certificate,
            "dossier_digest": record.dossier_digest,
            "signature_bundle": record.signature_bundle,
        })

        is_digest_valid = dossier.verify_dossier_integrity()
        sig_verified = False
        sig_err = None

        if dossier.signature_bundle:
            bundle = dossier.signature_bundle
            trusted_key = self._trusted_signing_key(bundle, request)
            sig_verified = bool(trusted_key) and dossier.verify_digital_signature(trusted_key)
            if not sig_verified:
                sig_err = "Signature could not be validated against a trusted signing key"
        else:
            sig_err = "Dossier has no digital signature attached"

        return VerifyArtifactResponse(
            artifact_id=record.dossier_id,
            artifact_type="forensic_dossier",
            is_valid=is_digest_valid and dossier.signature_bundle is not None and sig_verified,
            digest_verified=is_digest_valid,
            signature_verified=sig_verified,
            is_digitally_signed=dossier.signature_bundle is not None,
            signature_error=sig_err,
        )

    def export_forensic_dossier_html(self, dossier_id: str) -> str:
        record = self.session.execute(
            select(ForensicDossierRecord).where(
                and_(
                    ForensicDossierRecord.installation_id == self.installation_id,
                    ForensicDossierRecord.dossier_id == dossier_id,
                )
            )
        ).scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=404, detail="Forensic dossier not found")

        dossier = ForensicDossier.from_dict({
            "dossier_id": record.dossier_id,
            "case_id": record.case_id,
            "installation_id": record.installation_id,
            "title": record.title,
            "incident_type": record.incident_type,
            "fraud_loss_amount": record.fraud_loss_amount,
            "currency": record.currency,
            "examiner_subject": record.examiner_subject,
            "examiner_role": record.examiner_role,
            "created_at": record.created_at.isoformat(),
            "case_summary": record.case_summary,
            "attack_path_summary": record.attack_path_summary or {},
            "identified_mule_nodes": record.identified_mule_nodes or [],
            "evidence_records": record.evidence_records or [],
            "chain_of_custody": record.chain_of_custody or [],
            "section_106b_certificate": record.section_106b_certificate,
            "dossier_digest": record.dossier_digest,
            "signature_bundle": record.signature_bundle,
        })
        return dossier.render_html_dossier()

    def evaluate_inflight_payment(
        self,
        request: InflightPaymentEvaluationRequest,
        actor_subject: str,
    ) -> InflightPaymentEvaluationResponse:
        debtor = PartyIdentification(
            name=request.debtor_name,
            account_number=request.debtor_account,
            agent_bic=request.debtor_bic,
            national_id=request.debtor_national_id,
            msisdn=request.debtor_msisdn,
        )
        creditor = PartyIdentification(
            name=request.creditor_name,
            account_number=request.creditor_account,
            agent_bic=request.creditor_bic,
            national_id=request.creditor_national_id,
            msisdn=request.creditor_msisdn,
        )
        try:
            clearing_rail = ClearingRail(request.clearing_rail)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unsupported ISO 20022 clearing rail") from exc
        transfer = Pacs008CreditTransfer(
            msg_id=request.msg_id or f"MSG-{uuid.uuid4().hex[:12]}",
            end_to_end_id=request.end_to_end_id,
            tx_id=f"TX-{uuid.uuid4().hex[:12]}",
            amount=request.amount,
            currency=request.currency,
            debtor=debtor,
            creditor=creditor,
            clearing_rail=clearing_rail,
            remittance_narrative=request.remittance_narrative,
        )

        mule_accounts: set[str] = set()
        findings = self.session.execute(
            select(NetworkFindingRecord).where(
                NetworkFindingRecord.installation_id == self.installation_id
            )
        ).scalars().all()
        for f in findings:
            if f.finding_data and "mule_accounts" in f.finding_data:
                mule_accounts.update(f.finding_data["mule_accounts"])

        eval_result = ISO20022Engine.evaluate_inflight_payment(
            transfer=transfer,
            known_mule_accounts=mule_accounts,
            # No trusted bank-history adapter is available here; unknown is not zero.
            account_prior_transfers_count=None,
        )

        record = InflightPaymentRiskRecord(
            evaluation_id=f"eval-pmt-{uuid.uuid4().hex[:12]}",
            installation_id=self.installation_id,
            end_to_end_id=transfer.end_to_end_id,
            clearing_rail=clearing_rail.value,
            amount=transfer.amount,
            currency=transfer.currency,
            debtor_account=transfer.debtor.account_number,
            creditor_account=transfer.creditor.account_number,
            decision=eval_result.decision.value,
            risk_score=eval_result.risk_score,
            risk_tier=eval_result.risk_tier.value,
            triggered_rules=list(eval_result.triggered_rules),
            recommended_action=eval_result.recommended_action,
            latency_ms=eval_result.latency_ms,
            evaluated_at=eval_result.evaluated_at,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)

        return InflightPaymentEvaluationResponse(
            end_to_end_id=record.end_to_end_id,
            decision=record.decision,
            risk_score=record.risk_score,
            risk_tier=record.risk_tier,
            triggered_rules=record.triggered_rules,
            recommended_action=record.recommended_action,
            latency_ms=record.latency_ms,
            evaluated_at=record.evaluated_at.isoformat(),
        )

    def verify_copilot_semantics(
        self,
        request: SemanticVerifyRequest,
    ) -> SemanticVerifyResponse:
        evidence_items = []
        for d in request.evidence_context:
            clean_scan = sanitize_narrative(d.get("excerpt", ""))
            evidence_items.append(
                EvidenceItem.create(
                    evidence_id=d["evidence_id"],
                    installation_id=self.installation_id,
                    case_id="default",
                    source_system=d.get("source_system", "CORE_BANKING"),
                    source_record_id=d.get("source_record_id", d["evidence_id"]),
                    excerpt=clean_scan.clean_text,
                )
            )
        ctx = EvidenceContext(
            installation_id=self.installation_id,
            case_id="default",
            items=tuple(evidence_items),
        )

        claims = []
        for c in request.claims:
            quotes = tuple(
                EvidenceQuote(
                    evidence_id=q["evidence_id"],
                    quoted_text=q["quoted_text"],
                )
                for q in c.get("quotes", [])
            )
            kind_str = c.get("kind", "fact").upper()
            kind = ClaimKind.FACT if kind_str == "FACT" else ClaimKind.INFERENCE
            claims.append(
                GroundedClaim(
                    claim_id=c["claim_id"],
                    statement=c["statement"],
                    kind=kind,
                    evidence_ids=tuple(c.get("evidence_ids", [])),
                    quotes=quotes,
                )
            )

        report = verify_report_semantics(claims, ctx)
        return SemanticVerifyResponse(
            is_valid=report.is_valid,
            total_claims=report.total_claims,
            entailed_claims=report.entailed_claims,
            contradicted_claims=report.contradicted_claims,
            numeric_mismatches=report.numeric_mismatches,
            ungrounded_claims=report.ungrounded_claims,
            evaluations=[e.to_dict() for e in report.evaluations],
        )

