"""Toroka Enterprise API application assembly."""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from jwt import PyJWKClient

from .config import EnterpriseSettings
from .persistence.database import build_engine, build_session_factory
from .persistence.vault import FernetVaultCipher
from .routers.cases import router as cases_router
from .routers.contract import router as contract_router
from .routers.reveals import router as reveals_router
from .routers.runs import router as runs_router
from .routers.system import router as system_router


def create_app(
    settings: EnterpriseSettings | None = None,
) -> FastAPI:
    settings = settings or EnterpriseSettings.from_env()
    settings.validate()

    production = settings.environment == "production"

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
        docs_url=None if production else "/docs",
        redoc_url=None if production else "/redoc",
        openapi_url=None if production else "/openapi.json",
        lifespan=lifespan,
    )

    app.state.settings = settings

    # Operational database engine and session factory
    app.state.engine = build_engine(settings.database_url, production=production)
    app.state.session_factory = build_session_factory(app.state.engine)

    # Identity vault engine and session factory
    app.state.vault_engine = build_engine(settings.vault_database_url, production=production)
    app.state.vault_session_factory = build_session_factory(app.state.vault_engine)

    # Identity vault cipher
    if settings.vault_key:
        vault_keys = {settings.vault_key_version: settings.vault_key}
        app.state.vault_cipher = FernetVaultCipher(
            vault_keys, current_version=settings.vault_key_version
        )
    else:
        # Development fallback: generate ephemeral key
        dev_key = Fernet.generate_key().decode("utf-8")
        app.state.vault_cipher = FernetVaultCipher(
            {"v1": dev_key}, current_version="v1"
        )

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

    # Include API Routers
    app.include_router(system_router)
    app.include_router(contract_router)
    app.include_router(cases_router)
    app.include_router(reveals_router)
    app.include_router(runs_router)

    @app.middleware("http")
    async def security_and_correlation_headers(request: Request, call_next):
        correlation_id = request.headers.get("X-Correlation-ID") or uuid.uuid4().hex
        try:
            response = await call_next(request)
        except Exception:
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
        return response

    return app


def create_app_from_env() -> FastAPI:
    return create_app(EnterpriseSettings.from_env())
