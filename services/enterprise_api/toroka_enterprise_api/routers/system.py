"""System health, identity, and capability routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..auth import (
    EnterprisePrincipal,
    get_current_principal,
    require_roles,
)
from ..permissions import BANK_ROLES

router = APIRouter(tags=["Enterprise System"])


@router.get("/health/live")
def health_live():
    """Basic service liveness check. Does not disclose internal config or secrets."""
    return {
        "status": "alive",
        "service": "toroka-enterprise-api",
    }


@router.get("/api/enterprise/v1/me")
def current_identity(
    principal: EnterprisePrincipal = Depends(get_current_principal),
):
    """Return the authenticated subject and resolved Toroka roles."""
    return {
        "subject": principal.subject,
        "roles": sorted(principal.roles),
    }


@router.get(
    "/api/enterprise/v1/capabilities",
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
def capabilities():
    """Advertise actual implemented operational capabilities."""
    return {
        "service": "toroka-enterprise",
        "casework_api": False,
        "production_persistence": False,
        "authentication": "enterprise-identity",
        "investigation_engine": "existing-enterprise-engine",
    }
