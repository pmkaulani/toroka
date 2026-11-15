"""Identity Vault FastAPI service application assembly."""
from __future__ import annotations

from contextlib import asynccontextmanager
from cryptography.fernet import Fernet
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from .config import VaultSettings
from .crypto import (
    EnvelopeVaultCipher,
    FernetVaultCipher,
    LocalKMSKeyProvider,
)
from .models import VaultBase
from .routers.internal_reveal import health_router, router as internal_router


def create_app(settings: VaultSettings | None = None) -> FastAPI:
    settings = settings or VaultSettings.from_env()
    settings.validate()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        yield
        if hasattr(app.state, "engine") and app.state.engine is not None:
            app.state.engine.dispose()

    app = FastAPI(
        title="Toroka Identity Vault Service",
        version="0.1.0",
        description="Isolated, purpose-specific encrypted identity vault service.",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )

    app.state.settings = settings

    # Configure database engine
    is_sqlite = settings.database_url.startswith("sqlite")
    engine_kwargs = {}
    if is_sqlite:
        from sqlalchemy.pool import StaticPool
        if ":memory:" in settings.database_url:
            engine_kwargs["poolclass"] = StaticPool
            engine_kwargs["connect_args"] = {"check_same_thread": False}
    else:
        engine_kwargs["pool_pre_ping"] = True
        engine_kwargs["pool_size"] = 10
        engine_kwargs["max_overflow"] = 5

    engine = create_engine(settings.database_url, **engine_kwargs)
    VaultBase.metadata.create_all(engine)
    app.state.engine = engine
    app.state.session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    # Configure encryption cipher
    if settings.encryption_mode == "envelope":
        kms_provider = LocalKMSKeyProvider()
        key_id_map = {settings.vault_key_version: settings.kms_key_id}
        app.state.cipher = EnvelopeVaultCipher(
            key_provider=kms_provider,
            key_id_map=key_id_map,
            current_version=settings.vault_key_version,
        )
    else:
        # Development Fernet
        key = settings.vault_key or Fernet.generate_key().decode("utf-8")
        app.state.cipher = FernetVaultCipher(
            {settings.vault_key_version: key},
            current_version=settings.vault_key_version,
        )

    # Include routers
    app.include_router(health_router)
    app.include_router(internal_router)

    return app


def create_app_from_env() -> FastAPI:
    return create_app(VaultSettings.from_env())
