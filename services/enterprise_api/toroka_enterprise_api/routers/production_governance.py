from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from ..auth import EnterprisePrincipal, get_current_principal, require_roles
from ..dependencies import get_db, get_installation_id
from ..governance_schemas import (
    ApproveComponentRequest,
    ChampionChallengerRunResponse,
    CreateComponentRequest,
    CreateIncidentRequest,
    CreateReleaseRequest,
    CreateValidationRunRequest,
    DriftRecordResponse,
    EvaluateChampionChallengerRequest,
    EvaluateQuantitativeDriftRequest,
    EvaluateReadinessGatesRequest,
    EvidencePassportResponse,
    GenerateEvidencePassportRequest,
    GovernanceIncidentResponse,
    GovernedAIProviderResponse,
    GovernedComponentResponse,
    ProductionReleaseResponse,
    PromoteReleaseRequest,
    QuantitativeDriftEvaluationResponse,
    ReadinessAssessmentResponse,
    ReadinessAttestationResponse,
    RecordDriftRequest,
    RecordReadinessAttestationRequest,
    RegisterAIProviderRequest,
    ResumeComponentRequest,
    RollbackReleaseRequest,
    SignArtifactRequest,
    SuspendComponentRequest,
    SuspensionRecordResponse,
    SystemHealthOverviewResponse,
    UpdateIncidentStatusRequest,
    ValidationPackageResponse,
    ValidationRunResponse,
    VerifyArtifactRequest,
    VerifyArtifactResponse,
)
from ..permissions import (
    ROLE_AUDITOR,
    ROLE_AUTHORISER,
    ROLE_INVESTIGATOR,
    ROLE_SYSTEM_ADMINISTRATOR,
)
from ..services.production_governance import ProductionGovernanceService

router = APIRouter(
    prefix="/api/enterprise/v1/governance",
    tags=["Production Governance & Model Risk"],
)


def _primary_role(principal: EnterprisePrincipal) -> str:
    return sorted(principal.roles)[0] if principal.roles else "investigator"


# =============================================================================
# 1. Model & Component Registry
# =============================================================================

@router.post(
    "/components",
    response_model=GovernedComponentResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def register_component(
    request: CreateComponentRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> GovernedComponentResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.register_component(
        request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/components",
    response_model=list[GovernedComponentResponse],
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def list_components(
    component_type: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[GovernedComponentResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_components(component_type=component_type, status_filter=status_filter)


@router.get(
    "/components/{component_id}/{version}",
    response_model=GovernedComponentResponse,
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def get_component(
    component_id: str,
    version: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> GovernedComponentResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.get_component(component_id=component_id, version=version)


@router.post(
    "/components/{component_id}/{version}/approve",
    response_model=GovernedComponentResponse,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def approve_component(
    component_id: str,
    version: str,
    request: ApproveComponentRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> GovernedComponentResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.approve_component(
        component_id=component_id,
        version=version,
        request=request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


# =============================================================================
# 2. Model & Detector Validation Framework
# =============================================================================

@router.post(
    "/validation-runs",
    response_model=ValidationRunResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def record_validation_run(
    request: CreateValidationRunRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> ValidationRunResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.record_validation_run(
        request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/validation-runs",
    response_model=list[ValidationRunResponse],
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def list_validation_runs(
    component_id: str | None = Query(default=None),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[ValidationRunResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_validation_runs(component_id=component_id)


# =============================================================================
# 3. Production Release Manager & Deployment
# =============================================================================

@router.post(
    "/releases",
    response_model=ProductionReleaseResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def create_release(
    request: CreateReleaseRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> ProductionReleaseResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.create_release(
        request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/releases",
    response_model=list[ProductionReleaseResponse],
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def list_releases(
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[ProductionReleaseResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_releases()


@router.post(
    "/releases/{release_id}/promote",
    response_model=ProductionReleaseResponse,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def promote_release(
    release_id: str,
    request: PromoteReleaseRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> ProductionReleaseResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.promote_release(
        release_id=release_id,
        target_environment=request.target_environment,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.post(
    "/releases/{release_id}/rollback",
    response_model=ProductionReleaseResponse,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def rollback_release(
    release_id: str,
    request: RollbackReleaseRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> ProductionReleaseResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.rollback_release(
        release_id=release_id,
        target_release_id=request.target_release_id,
        reason=request.reason,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


# =============================================================================
# 4. Kill-Switch System & Granular Component Suspension
# =============================================================================

@router.post(
    "/kill-switch/suspend",
    response_model=SuspensionRecordResponse,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def suspend_component(
    request: SuspendComponentRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> SuspensionRecordResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.suspend_component(
        request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.post(
    "/kill-switch/resume",
    response_model=SuspensionRecordResponse,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def resume_component(
    request: ResumeComponentRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> SuspensionRecordResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.resume_component(
        request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/kill-switch/suspensions",
    response_model=list[SuspensionRecordResponse],
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def list_suspensions(
    active_only: bool = Query(default=False),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[SuspensionRecordResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_suspensions(active_only=active_only)


# =============================================================================
# 5. Incident Management & Investigation Impact
# =============================================================================

@router.post(
    "/incidents",
    response_model=GovernanceIncidentResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def create_incident(
    request: CreateIncidentRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> GovernanceIncidentResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.create_incident(
        request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.patch(
    "/incidents/{incident_id}/status",
    response_model=GovernanceIncidentResponse,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def update_incident_status(
    incident_id: str,
    request: UpdateIncidentStatusRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> GovernanceIncidentResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.update_incident_status(
        incident_id=incident_id,
        request=request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/incidents",
    response_model=list[GovernanceIncidentResponse],
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def list_incidents(
    status_filter: str | None = Query(default=None, alias="status"),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[GovernanceIncidentResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_incidents(status_filter=status_filter)


# =============================================================================
# 6. Drift Monitoring & System Health
# =============================================================================

@router.post(
    "/drift",
    response_model=DriftRecordResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_SYSTEM_ADMINISTRATOR, ROLE_AUTHORISER))],
)
def record_drift(
    request: RecordDriftRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> DriftRecordResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.record_drift(
        request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/drift",
    response_model=list[DriftRecordResponse],
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def list_drift_records(
    drift_type: str | None = Query(default=None),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[DriftRecordResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_drift_records(drift_type=drift_type)


@router.get(
    "/health",
    response_model=SystemHealthOverviewResponse,
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def get_system_health(
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> SystemHealthOverviewResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.get_system_health()


# =============================================================================
# 7. Toroka Evidence Passport: Cryptographically Bound Finding Provenance
# =============================================================================

@router.post(
    "/passports",
    response_model=EvidencePassportResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def generate_evidence_passport(
    request: GenerateEvidencePassportRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> EvidencePassportResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.generate_evidence_passport(
        finding_id=request.finding_id,
        case_id=request.case_id,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/passports/{passport_id}",
    response_model=EvidencePassportResponse,
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def get_evidence_passport(
    passport_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> EvidencePassportResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.get_evidence_passport(passport_id=passport_id)


@router.get(
    "/passports",
    response_model=list[EvidencePassportResponse],
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def list_evidence_passports(
    case_id: str | None = Query(default=None),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[EvidencePassportResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_evidence_passports(case_id=case_id)


# =============================================================================
# 8. Governed AI Providers
# =============================================================================

@router.post(
    "/ai-providers",
    response_model=GovernedAIProviderResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def register_ai_provider(
    request: RegisterAIProviderRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> GovernedAIProviderResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.register_ai_provider(
        request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/ai-providers",
    response_model=list[GovernedAIProviderResponse],
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def list_ai_providers(
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[GovernedAIProviderResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_ai_providers()


# =============================================================================
# 9. Production Readiness Assessment & Bank Validation Package
# =============================================================================

@router.post(
    "/readiness/evaluate",
    response_model=ReadinessAssessmentResponse,
    dependencies=[Depends(require_roles(ROLE_AUDITOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def evaluate_readiness(
    request: EvaluateReadinessGatesRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> ReadinessAssessmentResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.evaluate_readiness(
        request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/readiness/validation-package/{release_version}",
    response_model=ValidationPackageResponse,
    dependencies=[
        Depends(require_roles(ROLE_AUDITOR, ROLE_AUTHORISER, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def get_validation_package(
    release_version: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> ValidationPackageResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.generate_validation_package(release_version=release_version)


@router.post(
    "/readiness/attestations",
    response_model=ReadinessAttestationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def record_readiness_attestation(
    request: RecordReadinessAttestationRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> ReadinessAttestationResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.record_readiness_attestation(
        request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/readiness/attestations",
    response_model=list[ReadinessAttestationResponse],
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def list_readiness_attestations(
    release_version: str | None = Query(default=None),
    gate_name: str | None = Query(default=None),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[ReadinessAttestationResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_readiness_attestations(release_version=release_version, gate_name=gate_name)


# =============================================================================
# Phase 13.0: PKI Digital Signatures, Quantitative Risk & Shadow Governance
# =============================================================================

@router.post(
    "/passports/{passport_id}/sign",
    response_model=EvidencePassportResponse,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def sign_evidence_passport(
    passport_id: str,
    request: SignArtifactRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> EvidencePassportResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.sign_evidence_passport(
        passport_id=passport_id,
        request=request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.post(
    "/passports/{passport_id}/verify",
    response_model=VerifyArtifactResponse,
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def verify_evidence_passport(
    passport_id: str,
    request: VerifyArtifactRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> VerifyArtifactResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.verify_evidence_passport(passport_id=passport_id, request=request)


@router.post(
    "/releases/{release_id}/sign",
    response_model=ProductionReleaseResponse,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def sign_release(
    release_id: str,
    request: SignArtifactRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> ProductionReleaseResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.sign_release(
        release_id=release_id,
        request=request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.post(
    "/releases/{release_id}/verify",
    response_model=VerifyArtifactResponse,
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def verify_release(
    release_id: str,
    request: VerifyArtifactRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> VerifyArtifactResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.verify_release_manifest(release_id=release_id, request=request)


@router.post(
    "/model-risk/drift-evaluations",
    response_model=QuantitativeDriftEvaluationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def evaluate_quantitative_drift(
    request: EvaluateQuantitativeDriftRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> QuantitativeDriftEvaluationResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.evaluate_quantitative_drift(
        request=request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/model-risk/drift-evaluations",
    response_model=list[QuantitativeDriftEvaluationResponse],
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def list_quantitative_drift_evaluations(
    component_id: str | None = Query(default=None),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[QuantitativeDriftEvaluationResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_quantitative_drift_evaluations(component_id=component_id)


@router.post(
    "/model-risk/champion-challenger",
    response_model=ChampionChallengerRunResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def evaluate_champion_challenger(
    request: EvaluateChampionChallengerRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> ChampionChallengerRunResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.evaluate_champion_challenger(
        request=request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/model-risk/champion-challenger",
    response_model=list[ChampionChallengerRunResponse],
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def list_champion_challenger_runs(
    component_id: str | None = Query(default=None),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[ChampionChallengerRunResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_champion_challenger_runs(component_id=component_id)

