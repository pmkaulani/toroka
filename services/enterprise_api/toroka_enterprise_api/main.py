"""Toroka Enterprise API application assembly."""
from __future__ import annotations

import uuid

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from jwt import PyJWKClient

from .config import EnterpriseSettings
from .routers.contract import router as contract_router
from .routers.system import router as system_router


def create_app(
    settings: EnterpriseSettings | None = None,
) -> FastAPI:
    settings = settings or EnterpriseSettings.from_env()
    settings.validate()

    production = settings.environment == "production"

    app = FastAPI(
        title="Toroka Enterprise API",
        version="0.3.0",
        description="Authenticated financial-crime investigation operations API.",
        docs_url=None if production else "/docs",
        redoc_url=None if production else "/redoc",
        openapi_url=None if production else "/openapi.json",
    )

    app.state.settings = settings
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

    app.include_router(system_router)
    app.include_router(contract_router)

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
