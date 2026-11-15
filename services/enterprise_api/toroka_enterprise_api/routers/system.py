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
    """Deep readiness probe verifying database connectivity, schema revision, vault service, and audit subsystem."""
    from sqlalchemy import text

    settings = getattr(request.app.state, "settings", None)
    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "detail": "Operational database not configured"},
        )

    try:
        with session_factory() as db:
            db.execute(text("SELECT 1"))
            if settings and getattr(settings, "expected_schema_revision", ""):
                try:
                    revisions = db.execute(
                        text("SELECT version_num FROM alembic_version")
                    ).scalars().all()
                    if settings.expected_schema_revision not in revisions:
                        raise RuntimeError("Operational schema revision mismatch")
                except Exception as exc:
                    if "Operational schema revision mismatch" in str(exc):
                        raise
                    raise RuntimeError("Unable to verify alembic migration version") from exc

        # Check vault client readiness
        vault_client = getattr(request.app.state, "vault_client", None)
        if vault_client is not None:
            if not vault_client.health_ready():
                raise RuntimeError("Vault is not ready")

        # Check audit healthcheck
        audit_check = getattr(request.app.state, "audit_healthcheck", None)
        if audit_check is not None:
            if not audit_check():
                raise RuntimeError("Audit subsystem is not ready")

    except Exception:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "detail": "Service dependencies are unavailable"},
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
