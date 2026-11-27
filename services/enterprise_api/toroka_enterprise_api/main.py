"""Toroka Enterprise API application assembly."""
from __future__ import annotations

import logging
import re
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from jwt import PyJWKClient

from .config import EnterpriseSettings
from .persistence.database import build_engine, build_session_factory
from .persistence.vault import FernetVaultCipher
from .routers.cases import router as cases_router
from .routers.contract import router as contract_router
from .routers.governance import router as governance_router
from .routers.integration_events import router as integration_events_router
from .routers.integrations import router as integrations_router
from .routers.intelligence import router as intelligence_router
from .routers.baselines import router as baselines_router
from .routers.reconstruction import router as reconstruction_router
from .routers.simulations import router as simulations_router
from .routers.memory import router as memory_router
from .routers.network import router as network_router
from .routers.copilot import router as copilot_router
from .routers.investigations import router as investigations_router
from .routers.production_governance import router as production_governance_router
from .routers.reveals import router as reveals_router
from .routers.runs import router as runs_router
from .routers.system import router as system_router
from .vault_client import LocalVaultClient, RemoteVaultClient

logger = logging.getLogger(__name__)

SAFE_CORRELATION_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

# In-memory tracking for sensitive endpoint rate limits
_SENSITIVE_CALL_TIMESTAMPS: dict[str, list[float]] = defaultdict(list)
_MAX_SENSITIVE_CALLS_PER_MINUTE = 20


def create_app(
    settings: EnterpriseSettings | None = None,
) -> FastAPI:
    settings = settings or EnterpriseSettings.from_env()
    settings.validate()

    production = settings.environment == "production"
    hide_docs = settings.environment in ("production", "staging")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        if hasattr(app.state, "engine") and app.state.engine is not None:
            app.state.engine.dispose()
        if hasattr(app.state, "vault_engine") and app.state.vault_engine is not None:
            app.state.vault_engine.dispose()

    app = FastAPI(
        title="Toroka Enterprise API",
        version="0.3.0",
        description="Authenticated financial-crime investigation operations API.",
        docs_url=None if hide_docs else "/docs",
        redoc_url=None if hide_docs else "/redoc",
        openapi_url=None if hide_docs else "/openapi.json",
        lifespan=lifespan,
    )

    app.state.settings = settings
    if settings.audit_checkpoint_dir and settings.audit_checkpoint_hmac_key:
        from .persistence.checkpoints import (
            DirectoryImmutableCheckpointStore,
            HMACCheckpointSigner,
            HMACCheckpointVerifier,
        )
        key_bytes = settings.audit_checkpoint_hmac_key.encode("utf-8")
        app.state.checkpoint_store = DirectoryImmutableCheckpointStore(settings.audit_checkpoint_dir)
        app.state.checkpoint_signer = HMACCheckpointSigner(key_bytes, key_id="ent-hmac-v1")
        app.state.checkpoint_verifier = HMACCheckpointVerifier(key_bytes, key_id="ent-hmac-v1")
    else:
        app.state.checkpoint_store = None
        app.state.checkpoint_signer = None
        app.state.checkpoint_verifier = None

    # Operational database engine and session factory
    app.state.engine = build_engine(settings.database_url, production=production)
    app.state.session_factory = build_session_factory(app.state.engine)

    # In development/testing with SQLite, ensure integration and intelligence tables exist
    if "sqlite" in settings.database_url:
        from toroka_enterprise.integrations.models import IntegrationBase
        IntegrationBase.metadata.create_all(app.state.engine)
        from toroka_enterprise.intelligence.models import IntelligenceBase
        IntelligenceBase.metadata.create_all(app.state.engine)

    # Identity vault client setup
    if settings.vault_service_url:
        app.state.vault_client = RemoteVaultClient(
            settings.vault_service_url,
            service_token=settings.vault_service_token,
        )
    else:
        # Local development / test vault setup
        app.state.vault_engine = build_engine(settings.vault_database_url, production=production)
        app.state.vault_session_factory = build_session_factory(app.state.vault_engine)
        if settings.vault_key:
            vault_keys = {settings.vault_key_version: settings.vault_key}
            app.state.vault_cipher = FernetVaultCipher(
                vault_keys, current_version=settings.vault_key_version
            )
        else:
            dev_key = Fernet.generate_key().decode("utf-8")
            app.state.vault_cipher = FernetVaultCipher(
                {"v1": dev_key}, current_version="v1"
            )
        app.state.vault_client = LocalVaultClient(
            app.state.vault_session_factory,
            app.state.vault_cipher,
        )

    # Audit subsystem healthcheck
    def audit_healthcheck() -> bool:
        try:
            with app.state.session_factory() as db:
                from sqlalchemy import text
                db.execute(text("SELECT 1 FROM enterprise_audit_heads LIMIT 1"))
            return True
        except Exception:
            try:
                with app.state.session_factory() as db:
                    from sqlalchemy import text
                    db.execute(text("SELECT 1"))
                return True
            except Exception:
                return False

    app.state.audit_healthcheck = audit_healthcheck

    # OIDC JWKS Client
    app.state.jwks_client = (
        PyJWKClient(
            settings.oidc_jwks_url,
            cache_jwk_set=True,
            lifespan=300,
            timeout=5,
        )
        if settings.auth_mode == "oidc" and settings.oidc_jwks_url
        else None
    )

    # Only enable CORS when an explicit origin allowlist exists.
    # Same-origin production workbench does not require CORS.
    if settings.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_allowed_origins),
            allow_credentials=False,
            allow_methods=[
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
            ],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "X-Correlation-ID",
            ],
            max_age=600,
        )

    # Include API Routers
    app.include_router(system_router)
    app.include_router(contract_router)
    app.include_router(cases_router)
    app.include_router(reveals_router)
    app.include_router(runs_router)
    app.include_router(governance_router)
    app.include_router(integrations_router)
    app.include_router(integration_events_router)
    app.include_router(intelligence_router)
    app.include_router(baselines_router)
    app.include_router(reconstruction_router)
    app.include_router(simulations_router)
    app.include_router(memory_router)
    app.include_router(network_router)
    app.include_router(copilot_router)
    app.include_router(investigations_router)
    app.include_router(production_governance_router)

    # Mount static Enterprise Workbench if dist exists
    workbench_dist = Path(__file__).resolve().parents[3] / "apps" / "enterprise-workbench" / "dist"
    if workbench_dist.is_dir():
        app.mount("/workbench", StaticFiles(directory=str(workbench_dist), html=True), name="workbench")

    @app.middleware("http")
    async def security_and_correlation_headers(request: Request, call_next):
        supplied_id = request.headers.get("X-Correlation-ID", "")
        if SAFE_CORRELATION_ID.fullmatch(supplied_id):
            correlation_id = supplied_id
        else:
            correlation_id = uuid.uuid4().hex

        # Request body size protection (e.g. 10MB limit)
        content_length = request.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > 10 * 1024 * 1024:
                    return JSONResponse(
                        {"error": "payload_too_large", "detail": "Request body exceeds maximum size of 10MB"},
                        status_code=413,
                    )
            except ValueError:
                pass

        # Ingress abuse protection: rate limit sensitive reveal-consumption endpoints
        path = request.url.path
        if "/reveal-requests/" in path and path.endswith("/consume"):
            client_ip = request.client.host if request.client else "unknown"
            now = time.time()
            recent_times = [t for t in _SENSITIVE_CALL_TIMESTAMPS[client_ip] if now - t < 60.0]
            _SENSITIVE_CALL_TIMESTAMPS[client_ip] = recent_times
            if len(recent_times) >= _MAX_SENSITIVE_CALLS_PER_MINUTE:
                logger.warning("Rate limit exceeded for reveal consume on IP %s", client_ip)
                return JSONResponse(
                    {"error": "rate_limit_exceeded", "detail": "Rate limit exceeded for sensitive operation"},
                    status_code=429,
                )
            _SENSITIVE_CALL_TIMESTAMPS[client_ip].append(now)

        try:
            response = await call_next(request)
        except Exception:
            logger.exception(
                "Unhandled Enterprise API exception",
                extra={"correlation_id": correlation_id},
            )
            response = JSONResponse(
                {
                    "error": "internal_error",
                    "detail": "The operation could not be completed.",
                },
                status_code=500,
            )

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        return response

    return app


def create_app_from_env() -> FastAPI:
    return create_app(EnterpriseSettings.from_env())
