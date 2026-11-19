"""Internal endpoints for identity storage and reveal operations."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from ..auth import require_internal_service_auth
from ..grants import verify_signed_reveal_grant
from ..models import VaultConsumedGrant
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
    
    Independently validates cryptographic approval grant, scope, and single-use consumption.
    Never outputs plaintext identities into logs.
    """
    if not body.reveal_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Reveal token with signed approval grant is required to consume identity",
        )

    try:
        grant_payload = verify_signed_reveal_grant(
            body.reveal_token,
            expected_installation_id=body.installation_id,
            expected_requester_subject=body.requester_subject,
            expected_pseudonym=body.pseudonym,
            expected_grant_id=body.request_id,
        )
    except ValueError as exc:
        logger.warning(
            "Internal reveal approval grant validation failed: %s",
            exc,
            extra={
                "installation_id": body.installation_id,
                "request_id": body.request_id,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Reveal approval grant invalid or expired: {exc}",
        )

    session_factory = request.app.state.session_factory
    cipher = request.app.state.cipher

    with session_factory() as db:
        # Atomic single-use consumption check
        stmt = (
            select(VaultConsumedGrant)
            .where(
                VaultConsumedGrant.installation_id == body.installation_id,
                VaultConsumedGrant.grant_id == body.request_id,
            )
            .with_for_update()
        )
        consumed = db.execute(stmt).scalar_one_or_none()
        if consumed is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Reveal approval grant has already been consumed (single-use only)",
            )

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

        # Mark grant consumed atomically alongside retrieval
        now = datetime.now(timezone.utc)
        record = VaultConsumedGrant(
            installation_id=body.installation_id,
            grant_id=body.request_id,
            case_id=grant_payload.get("case_id", ""),
            requester_subject=body.requester_subject,
            consumed_at=now,
        )
        db.add(record)
        db.commit()

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
