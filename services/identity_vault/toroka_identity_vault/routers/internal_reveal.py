"""Internal endpoints for identity storage and reveal operations."""
from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..auth import require_internal_service_auth
from ..repository import IdentityVaultRepository

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/internal/v1",
    tags=["Internal Vault Operations"],
    dependencies=[Depends(require_internal_service_auth)],
)


class RevealConsumeRequest(BaseModel):
    installation_id: str = Field(..., min_length=1)
    pseudonym: str = Field(..., min_length=1)
    request_id: str = Field(..., min_length=1)
    requester_subject: str = Field(..., min_length=1)
    reveal_token: str | None = None


class RevealConsumeResponse(BaseModel):
    pseudonym: str
    plaintext_identity: str


class IdentityStoreRequest(BaseModel):
    installation_id: str = Field(..., min_length=1)
    pseudonym: str = Field(..., min_length=1)
    plaintext_identity: str = Field(..., min_length=1)
    key_version: str | None = None


class IdentityStoreResponse(BaseModel):
    status: str
    pseudonym: str
    key_version: str


def get_vault_repo(request: Request) -> IdentityVaultRepository:
    session_factory = request.app.state.session_factory
    cipher = request.app.state.cipher
    db: Session = session_factory()
    try:
        return IdentityVaultRepository(db, cipher)
    finally:
        pass


@router.post(
    "/reveals/consume",
    response_model=RevealConsumeResponse,
)
def consume_reveal(
    body: RevealConsumeRequest,
    request: Request,
):
    """Internal identity retrieval for approved, single-use reveal requests.
    
    Independently validates installation boundary. Never outputs plaintext identities into logs.
    """
    session_factory = request.app.state.session_factory
    cipher = request.app.state.cipher

    with session_factory() as db:
        repo = IdentityVaultRepository(db, cipher)
        plaintext = repo.retrieve_and_decrypt(body.installation_id, body.pseudonym)
        if plaintext is None:
            logger.warning(
                "Internal reveal failed: pseudonym not found or decryption failed",
                extra={
                    "installation_id": body.installation_id,
                    "request_id": body.request_id,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Pseudonym '{body.pseudonym}' could not be resolved in the vault",
            )

        logger.info(
            "Internal reveal consumed successfully",
            extra={
                "installation_id": body.installation_id,
                "request_id": body.request_id,
                "requester_subject": body.requester_subject,
            },
        )
        return RevealConsumeResponse(
            pseudonym=body.pseudonym,
            plaintext_identity=plaintext,
        )


@router.post(
    "/identities",
    response_model=IdentityStoreResponse,
    status_code=status.HTTP_201_CREATED,
)
def store_identity(
    body: IdentityStoreRequest,
    request: Request,
):
    """Store an encrypted pseudonym-to-identity mapping in the vault."""
    session_factory = request.app.state.session_factory
    cipher = request.app.state.cipher

    with session_factory() as db:
        repo = IdentityVaultRepository(db, cipher)
        record = repo.store(
            installation_id=body.installation_id,
            pseudonym=body.pseudonym,
            plaintext_identity=body.plaintext_identity,
            key_version=body.key_version,
        )
        db.commit()
        return IdentityStoreResponse(
            status="stored",
            pseudonym=record.pseudonym,
            key_version=record.key_version,
        )


# Health checks do not require internal service auth so container orchestrators can probe them
health_router = APIRouter(prefix="/internal/v1/health", tags=["Vault Health"])


@health_router.get("/live")
def health_live():
    return {"status": "alive", "service": "toroka-identity-vault"}


@health_router.get("/ready")
def health_ready(request: Request):
    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database session factory not configured",
        )
    try:
        with session_factory() as db:
            db.execute(text("SELECT 1"))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Vault database unreachable",
        ) from exc
    return {"status": "ready", "service": "toroka-identity-vault", "database": "connected"}
