"""FastAPI dependency providers for persistence and services."""
from __future__ import annotations

from collections.abc import Generator

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from .persistence.vault import FernetVaultCipher, IdentityVaultRepository, VaultCipher
from .services.cases import CaseService
from .services.reveals import RevealService
from .services.runs import RunService


def get_db(request: Request) -> Generator[Session, None, None]:
    """Provide an isolated operational database session per request."""
    factory = request.app.state.session_factory
    db = factory()
    try:
        yield db
    finally:
        db.close()


def get_vault_db(request: Request) -> Generator[Session, None, None]:
    """Provide an isolated identity vault database session per request."""
    factory = getattr(request.app.state, "vault_session_factory", None)
    if factory is None:
        raise RuntimeError("Identity vault session factory is not configured")
    db = factory()
    try:
        yield db
    finally:
        db.close()


def get_vault_cipher(request: Request) -> VaultCipher:
    cipher = getattr(request.app.state, "vault_cipher", None)
    if cipher is None:
        raise RuntimeError("Vault encryption cipher is not configured")
    return cipher


def get_vault_repo(
    vault_db: Session = Depends(get_vault_db),
    cipher: VaultCipher = Depends(get_vault_cipher),
) -> IdentityVaultRepository:
    return IdentityVaultRepository(vault_db, cipher)


def get_vault_client(request: Request):
    from .vault_client import LocalVaultClient, RemoteVaultClient
    client = getattr(request.app.state, "vault_client", None)
    if isinstance(client, RemoteVaultClient):
        return client
    factory = getattr(request.app.state, "vault_session_factory", None)
    cipher = getattr(request.app.state, "vault_cipher", None)
    return LocalVaultClient(factory, cipher)


def get_case_service(
    db: Session = Depends(get_db),
) -> CaseService:
    return CaseService(db)


def get_reveal_service(
    db: Session = Depends(get_db),
    vault_client = Depends(get_vault_client),
) -> RevealService:
    return RevealService(db, vault_client)


def get_run_service(
    db: Session = Depends(get_db),
) -> RunService:
    return RunService(db)


def get_settings(request: Request):
    return getattr(request.app.state, "settings", None)


def get_installation_id(request: Request) -> str:
    settings = getattr(request.app.state, "settings", None)
    if settings is not None and hasattr(settings, "installation_id"):
        return settings.installation_id
    return "toroka-default-installation"
