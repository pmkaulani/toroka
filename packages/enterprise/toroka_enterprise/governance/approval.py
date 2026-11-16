from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from .models import (
    GovernanceStatus,
    GovernedComponent,
    RiskTier,
)


class ApprovalError(Exception):
    pass


@dataclass(frozen=True)
class ApprovalDecision:
    component_id: str
    component_version: str
    approved_by: str
    approved_at: datetime
    validation_run_id: str
    validation_digest: str
    rationale: str


def approve_component(
    component: GovernedComponent,
    *,
    reviewer_subject: str,
    validation_run_id: str,
    validation_digest: str,
    rationale: str,
    now: datetime,
) -> GovernedComponent:
    if component.status != GovernanceStatus.VALIDATION:
        raise ApprovalError("Only components in validation may be approved")
    if not reviewer_subject or not reviewer_subject.strip():
        raise ApprovalError("An authenticated reviewer is required")
    if not validation_run_id or not validation_run_id.strip():
        raise ApprovalError("Validation evidence is required")
    if not validation_digest or not validation_digest.strip():
        raise ApprovalError("Validation digest is required")
    if not rationale or not rationale.strip():
        raise ApprovalError("Approval rationale is required")

    # Enforce Maker-Checker Separation for Moderate, High, and Critical risk tiers
    if component.risk_tier in (RiskTier.MODERATE, RiskTier.HIGH, RiskTier.CRITICAL):
        if reviewer_subject == component.created_by:
            raise ApprovalError(
                f"Maker-checker violation: Component author '{reviewer_subject}' "
                f"cannot approve {component.risk_tier.value}-tier component"
            )

    return GovernedComponent(
        component_id=component.component_id,
        version=component.version,
        component_type=component.component_type,
        name=component.name,
        status=GovernanceStatus.APPROVED,
        risk_tier=component.risk_tier,
        owner_team=component.owner_team,
        source_digest=component.source_digest,
        configuration_digest=component.configuration_digest,
        created_at=component.created_at,
        created_by=component.created_by,
        approved_at=now,
        approved_by=reviewer_subject,
        description=component.description,
        parameters=dict(component.parameters),
    )
