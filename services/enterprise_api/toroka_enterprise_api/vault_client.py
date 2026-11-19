"""Client abstraction for communicating with the Identity Vault service."""
from __future__ import annotations

import logging
from typing import Protocol
import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session, sessionmaker

from .persistence.vault import IdentityVaultRepository, VaultCipher

logger = logging.getLogger(__name__)


class VaultClientProtocol(Protocol):
    """Protocol for Identity Vault operations from the Enterprise API."""

    def consume_reveal(
        self,
        installation_id: str,
        pseudonym: str,
        request_id: str,
        requester_subject: str,
        reveal_token: str | None = None,
    ) -> str:
        """Retrieve and decrypt an identity for an approved reveal request."""
        ...

    def health_ready(self) -> bool:
        """Check if the identity vault service is available and ready."""
        ...

    def store_identity(
        self,
        installation_id: str,
        pseudonym: str,
        plaintext_identity: str,
    ) -> None:
        """Store an identity mapping in the vault."""
        ...


class RemoteVaultClient:
    """HTTP client communicating with the isolated Identity Vault service."""

    def __init__(
        self,
        vault_service_url: str,
        service_token: str = "",
        timeout: float = 5.0,
    ):
        self.vault_service_url = vault_service_url.rstrip("/")
        self.service_token = service_token
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.service_token:
            headers["X-Internal-Service-Token"] = self.service_token
        return headers

    def consume_reveal(
        self,
        installation_id: str,
        pseudonym: str,
        request_id: str,
        requester_subject: str,
        reveal_token: str | None = None,
    ) -> str:
        url = f"{self.vault_service_url}/internal/v1/reveals/consume"
        payload = {
            "installation_id": installation_id,
            "pseudonym": pseudonym,
            "request_id": request_id,
            "requester_subject": requester_subject,
            "reveal_token": reveal_token,
        }
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload, headers=self._headers())
        except Exception as exc:
            logger.error("Failed to connect to identity vault service: %s", exc)
            raise RuntimeError(f"Identity vault service connection failure: {exc}") from exc

        if resp.status_code == 404:
            raise LookupError(f"Pseudonym '{pseudonym}' could not be resolved in the identity vault")
        if resp.status_code != 200:
            raise RuntimeError(f"Identity vault service returned HTTP {resp.status_code}: {resp.text}")

        data = resp.json()
        return data["plaintext_identity"]

    def health_ready(self) -> bool:
        url = f"{self.vault_service_url}/internal/v1/health/ready"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.get(url)
                return resp.status_code == 200
        except Exception:
            return False

    def store_identity(
        self,
        installation_id: str,
        pseudonym: str,
        plaintext_identity: str,
    ) -> None:
        url = f"{self.vault_service_url}/internal/v1/identities"
        payload = {
            "installation_id": installation_id,
            "pseudonym": pseudonym,
            "plaintext_identity": plaintext_identity,
        }
        with httpx.Client(timeout=self.timeout) as client:
            resp = client.post(url, json=payload, headers=self._headers())
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"Failed to store identity in vault service: {resp.text}")


class LocalVaultClient:
    """In-process identity vault client adapter for local development and testing."""

    def __init__(
        self,
        session_factory: sessionmaker[Session] | None,
        cipher: VaultCipher,
    ):
        self.session_factory = session_factory
        self.cipher = cipher

    def consume_reveal(
        self,
        installation_id: str,
        pseudonym: str,
        request_id: str,
        requester_subject: str,
        reveal_token: str | None = None,
    ) -> str:
        if self.session_factory is None:
            raise RuntimeError("Vault session factory is not configured")
        if reveal_token:
            from .grants import verify_signed_reveal_grant
            verify_signed_reveal_grant(
                reveal_token,
                expected_installation_id=installation_id,
                expected_requester_subject=requester_subject,
                expected_pseudonym=pseudonym,
                expected_grant_id=request_id,
            )
        with self.session_factory() as db:
            repo = IdentityVaultRepository(db, self.cipher)
            plaintext = repo.retrieve_and_decrypt(pseudonym, installation_id=installation_id)
            if plaintext is None:
                raise LookupError(f"Pseudonym '{pseudonym}' could not be resolved in the identity vault")
            return plaintext

    def health_ready(self) -> bool:
        if self.session_factory is None:
            return False
        try:
            with self.session_factory() as db:
                db.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    def store_identity(
        self,
        installation_id: str,
        pseudonym: str,
        plaintext_identity: str,
    ) -> None:
        if self.session_factory is None:
            raise RuntimeError("Vault session factory is not configured")
        with self.session_factory() as db:
            repo = IdentityVaultRepository(db, self.cipher)
            repo.store(pseudonym, plaintext_identity, installation_id=installation_id)
            db.commit()
