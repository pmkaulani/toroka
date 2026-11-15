"""System health, identity, and capability routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

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


@router.get("/health/ready")
def health_ready(
    request: Request,
):
    """Database and vault readiness probe. Fails safely if persistence cannot be reached."""
    from sqlalchemy import text

    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "reason": "Operational database not configured"},
        )

    try:
        with session_factory() as db:
            db.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "reason": "Operational database connection failed"},
        )

    vault_factory = getattr(request.app.state, "vault_session_factory", None)
    if vault_factory is not None:
        try:
            with vault_factory() as vdb:
                vdb.execute(text("SELECT 1"))
        except Exception:
            return JSONResponse(
                status_code=503,
                content={"status": "not_ready", "reason": "Identity vault database connection failed"},
            )

    return {
        "status": "ready",
        "service": "toroka-enterprise-api",
        "persistence": "connected",
        "vault": "connected",
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
        "casework_api": True,
        "production_persistence": True,
        "authentication": "enterprise-identity",
        "investigation_engine": "existing-enterprise-engine",
    }
