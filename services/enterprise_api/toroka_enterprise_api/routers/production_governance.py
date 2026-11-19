from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ..auth import EnterprisePrincipal, get_current_principal, require_roles
from ..dependencies import get_db, get_installation_id
from ..governance_schemas import (
    ApproveAIProviderRequest,
    ApproveComponentRequest,
    ChampionChallengerRunResponse,
    CopVerifyRequest,
    CopVerifyResponse,
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
    ExecuteCascadeDirectiveRequest,
    ExecuteCascadeDirectiveResponse,
    ExecuteTrustedValidationRequest,
    FederatedMuleEntryResponse,
    ForensicDossierResponse,
    GenerateEvidencePassportRequest,
    GovernanceIncidentResponse,
    GovernedAIProviderResponse,
    GovernedComponentResponse,
    InflightPaymentEvaluationRequest,
    InflightPaymentEvaluationResponse,
    MoneyLockAccountResponse,
    MoneyLockBranchUnlockRequest,
    MoneyLockLockRequest,
    MuleCascadeTraceResponse,
    PrecautionaryHoldCreateRequest,
    PrecautionaryHoldEscalateRequest,
    PrecautionaryHoldRecallRequest,
    PrecautionaryHoldReleaseRequest,
    PrecautionaryHoldResponse,
    ProductionReleaseResponse,
    PromoteReleaseRequest,
    QuantitativeDriftEvaluationResponse,
    QueryFederatedMuleRequest,
    QueryFederatedMuleResponse,
    ReadinessAssessmentResponse,
    ReadinessAttestationResponse,
    RecordDriftRequest,
    RecordReadinessAttestationRequest,
    RegisterAIProviderRequest,
    RegisterFederatedMuleRequest,
    RegisterTrustedSignerRequest,
    ResumeComponentRequest,
    RollbackReleaseRequest,
    SemanticVerifyRequest,
    SemanticVerifyResponse,
    SignArtifactRequest,
    SimBindingEnrollRequest,
    SimBindingEnrollResponse,
    SuspendComponentRequest,
    SuspensionRecordResponse,
    SystemHealthOverviewResponse,
    TelecomSignalRequest,
    TelecomSignalResponse,
    TriggerMuleCascadeTraceRequest,
    TrustedSignerResponse,
    UpdateFederatedMuleStatusRequest,
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


@router.post(
    "/validation-runs/execute-trusted",
    response_model=ValidationRunResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def execute_trusted_validation(
    request: ExecuteTrustedValidationRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> ValidationRunResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.execute_trusted_validation(
        request=request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


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
        signature_bundle=request.signature_bundle,
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


@router.post(
    "/ai-providers/{provider_id}/approve",
    response_model=GovernedAIProviderResponse,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def approve_ai_provider(
    provider_id: str,
    request: ApproveAIProviderRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> GovernedAIProviderResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.approve_ai_provider(
        provider_id=provider_id,
        request=request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


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


# =============================================================================
# 12. Court-Ready Forensic Evidence Dossiers (Sec 106B & Chain of Custody)
# =============================================================================

@router.post(
    "/forensic-dossiers",
    response_model=ForensicDossierResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def create_forensic_dossier(
    request: CreateForensicDossierRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> ForensicDossierResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.create_forensic_dossier(
        request=request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/forensic-dossiers/{dossier_id}",
    response_model=ForensicDossierResponse,
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUDITOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def get_forensic_dossier(
    dossier_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> ForensicDossierResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.get_forensic_dossier(dossier_id=dossier_id)


@router.post(
    "/forensic-dossiers/{dossier_id}/sign",
    response_model=ForensicDossierResponse,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def sign_forensic_dossier(
    dossier_id: str,
    request: SignArtifactRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> ForensicDossierResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.sign_forensic_dossier(
        dossier_id=dossier_id,
        request=request,
        actor_subject=principal.subject,
    )


@router.post(
    "/forensic-dossiers/{dossier_id}/verify",
    response_model=VerifyArtifactResponse,
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUDITOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def verify_forensic_dossier(
    dossier_id: str,
    request: VerifyArtifactRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> VerifyArtifactResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.verify_forensic_dossier(dossier_id=dossier_id, request=request)


@router.get(
    "/forensic-dossiers/{dossier_id}/export-html",
    response_class=HTMLResponse,
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUDITOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def export_forensic_dossier_html(
    dossier_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    html_content = service.export_forensic_dossier_html(dossier_id=dossier_id)
    return HTMLResponse(content=html_content)


# =============================================================================
# 13. ISO 20022 Financial Messaging & In-Flight Risk Scoring
# =============================================================================

@router.post(
    "/integrations/iso20022/evaluate-inflight",
    response_model=InflightPaymentEvaluationResponse,
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def evaluate_inflight_payment(
    request: InflightPaymentEvaluationRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> InflightPaymentEvaluationResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.evaluate_inflight_payment(request=request, actor_subject=principal.subject)


# =============================================================================
# 14. Semantic Grounding & Copilot Anti-Evasion Verification
# =============================================================================

@router.post(
    "/copilot/semantic-verify",
    response_model=SemanticVerifyResponse,
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUDITOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def verify_copilot_semantics(
    request: SemanticVerifyRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> SemanticVerifyResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.verify_copilot_semantics(request=request)


# =============================================================================
# 15. Signer Trust Registry
# =============================================================================

@router.post(
    "/trust-registry/signers",
    response_model=TrustedSignerResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def register_trusted_signer(
    request: RegisterTrustedSignerRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> TrustedSignerResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.register_trusted_signer(
        request=request,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/trust-registry/signers",
    response_model=list[TrustedSignerResponse],
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_INVESTIGATOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def list_trusted_signers(
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[TrustedSignerResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_trusted_signers()


@router.post(
    "/trust-registry/signers/{key_id}/revoke",
    response_model=TrustedSignerResponse,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def revoke_trusted_signer(
    key_id: str,
    reason: str = Query(..., description="Reason for key revocation"),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> TrustedSignerResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.revoke_trusted_signer(
        key_id=key_id,
        reason=reason,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


# =============================================================================
# 16. Confirmation of Payee (CoP) Pre-Flight Name Verification
# =============================================================================

@router.post(
    "/integrations/cop/verify",
    response_model=CopVerifyResponse,
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def verify_confirmation_of_payee(
    request: CopVerifyRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> CopVerifyResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.verify_confirmation_of_payee(request=request, actor_subject=principal.subject)


# =============================================================================
# 17. Telecom Scam Signal Live Carrier Telemetry
# =============================================================================

@router.post(
    "/integrations/telecom/scam-signal",
    response_model=TelecomSignalResponse,
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def evaluate_telecom_scam_signal(
    request: TelecomSignalRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> TelecomSignalResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.evaluate_telecom_signal(request=request, actor_subject=principal.subject)


# =============================================================================
# 18. Federated Mule Directory & Hash-Linked Interbank Blacklist
# =============================================================================

@router.post(
    "/integrations/federated-mules/register",
    response_model=FederatedMuleEntryResponse,
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def register_federated_mule(
    request: RegisterFederatedMuleRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> FederatedMuleEntryResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.register_federated_mule(request=request, actor_subject=principal.subject)


@router.post(
    "/integrations/federated-mules/query",
    response_model=QueryFederatedMuleResponse,
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def query_federated_mule(
    request: QueryFederatedMuleRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> QueryFederatedMuleResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.query_federated_mule(request=request)


@router.get(
    "/integrations/federated-mules/entries",
    response_model=list[FederatedMuleEntryResponse],
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def list_federated_mules(
    entity_type: str | None = Query(None),
    status: str | None = Query(None),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[FederatedMuleEntryResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_federated_mules(entity_type=entity_type, status=status)


@router.patch(
    "/integrations/federated-mules/entries/{entry_id}/status",
    response_model=FederatedMuleEntryResponse,
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def update_federated_mule_status(
    entry_id: str,
    request: UpdateFederatedMuleStatusRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> FederatedMuleEntryResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.update_federated_mule_status(entry_id=entry_id, request=request, actor_subject=principal.subject)


# =============================================================================
# Phase 14.3: Multi-Tiered Mule Tracing & Graph Cascade Endpoints (PBOC / UK PSR)
# =============================================================================

@router.post(
    "/intelligence/mule-cascade/trace",
    response_model=MuleCascadeTraceResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def trigger_mule_cascade_trace(
    request: TriggerMuleCascadeTraceRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> MuleCascadeTraceResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.trigger_mule_cascade_trace(request=request, actor_subject=principal.subject)


@router.get(
    "/intelligence/mule-cascade/traces",
    response_model=list[MuleCascadeTraceResponse],
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def list_mule_cascade_traces(
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[MuleCascadeTraceResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_mule_cascade_traces()


@router.get(
    "/intelligence/mule-cascade/traces/{trace_id}",
    response_model=MuleCascadeTraceResponse,
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def get_mule_cascade_trace(
    trace_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> MuleCascadeTraceResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.get_mule_cascade_trace(trace_id=trace_id)


@router.post(
    "/intelligence/mule-cascade/traces/{trace_id}/directives/{directive_id}/execute",
    response_model=ExecuteCascadeDirectiveResponse,
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def execute_cascade_directive(
    trace_id: str,
    directive_id: str,
    request: ExecuteCascadeDirectiveRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> ExecuteCascadeDirectiveResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.execute_cascade_directive(
        trace_id=trace_id,
        request=request,
        actor_subject=principal.subject,
    )


# ==============================================================================
# Phase 15.0: Singapore MAS Money Lock Vault Partitioning Endpoints
# ==============================================================================

@router.post(
    "/money-lock/accounts/{account_id}/lock",
    response_model=MoneyLockAccountResponse,
)
def lock_money_vault(
    account_id: str,
    request: MoneyLockLockRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> MoneyLockAccountResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.lock_money_vault(
        account_id=account_id,
        amount=request.amount,
        actor=request.actor or principal.subject,
    )


@router.post(
    "/money-lock/accounts/{account_id}/attempt-digital-unlock",
    status_code=status.HTTP_403_FORBIDDEN,
)
def attempt_digital_unlock(
    account_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> None:
    """Attempts digital unlocking; strictly rejected under Singapore MAS Money Lock policy."""
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    service.attempt_digital_unlock(
        account_id=account_id,
        actor=principal.subject,
    )


@router.post(
    "/money-lock/accounts/{account_id}/branch-unlock",
    response_model=MoneyLockAccountResponse,
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def branch_unlock_money_vault(
    account_id: str,
    request: MoneyLockBranchUnlockRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> MoneyLockAccountResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.branch_unlock_money_vault(
        account_id=account_id,
        amount=request.amount,
        officer_id=request.officer_id,
        station_id=request.station_id,
        dual_authorizer_id=request.dual_authorizer_id,
        channel=request.channel,
    )


@router.get(
    "/money-lock/accounts/{account_id}",
    response_model=MoneyLockAccountResponse,
)
def get_money_lock_account(
    account_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> MoneyLockAccountResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.get_money_lock_account(account_id=account_id)


@router.get(
    "/money-lock/accounts",
    response_model=list[MoneyLockAccountResponse],
)
def list_money_lock_accounts(
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[MoneyLockAccountResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_money_lock_accounts()


# ==============================================================================
# Phase 15.1: Brazil BCB Bloqueio Cautelar 72h Precautionary Hold Endpoints
# ==============================================================================

@router.post(
    "/precautionary-holds",
    response_model=PrecautionaryHoldResponse,
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def create_precautionary_hold(
    request: PrecautionaryHoldCreateRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> PrecautionaryHoldResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.create_precautionary_hold(request=request)


@router.post(
    "/precautionary-holds/{hold_id}/release",
    response_model=PrecautionaryHoldResponse,
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def release_precautionary_hold(
    hold_id: str,
    request: PrecautionaryHoldReleaseRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> PrecautionaryHoldResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.release_precautionary_hold(hold_id=hold_id, request=request)


@router.post(
    "/precautionary-holds/{hold_id}/escalate",
    response_model=PrecautionaryHoldResponse,
    dependencies=[
        Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def escalate_precautionary_hold_to_camt056(
    hold_id: str,
    request: PrecautionaryHoldEscalateRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> PrecautionaryHoldResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.escalate_precautionary_hold_to_camt056(hold_id=hold_id, request=request)


@router.post(
    "/precautionary-holds/{hold_id}/recall",
    response_model=PrecautionaryHoldResponse,
)
def recall_precautionary_hold(
    hold_id: str,
    request: PrecautionaryHoldRecallRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> PrecautionaryHoldResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.recall_precautionary_hold(hold_id=hold_id, request=request)


@router.get(
    "/precautionary-holds",
    response_model=list[PrecautionaryHoldResponse],
)
def list_precautionary_holds(
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[PrecautionaryHoldResponse]:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.list_precautionary_holds()


# ==============================================================================
# Phase 15.2: India NPCI Cryptographic SIM & Hardware Binding Endpoints
# ==============================================================================

@router.post(
    "/sim-binding/enroll",
    response_model=SimBindingEnrollResponse,
    dependencies=[
        Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))
    ],
)
def enroll_sim_binding(
    request: SimBindingEnrollRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> SimBindingEnrollResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.enroll_sim_binding(request=request)


@router.get(
    "/sim-binding/accounts/{account_id}",
    response_model=SimBindingEnrollResponse,
)
def get_sim_binding(
    account_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> SimBindingEnrollResponse:
    effective_inst = principal.installation_id or installation_id
    service = ProductionGovernanceService(db, effective_inst)
    return service.get_sim_binding(account_id=account_id)







