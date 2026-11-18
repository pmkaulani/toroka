"""Toroka Enterprise — Bank Evidence Reference Resolver.

Resolves evidence references to bank-controlled persisted artifacts, recomputes
cryptographic content digests, enforces tenant isolation and access control,
and eliminates caller-supplied arbitrary URLs or fake digests.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Protocol


class EvidenceArtifactScope(StrEnum):
    RELEASE = "RELEASE"
    GATE = "GATE"
    MODEL = "MODEL"
    SECURITY_AUDIT = "SECURITY_AUDIT"
    COMPLIANCE_CERTIFICATE = "COMPLIANCE_CERTIFICATE"


@dataclass(frozen=True)
class BankEvidenceArtifact:
    """An immutable, bank-controlled evidence artifact."""
    artifact_id: str
    installation_id: str
    source_system: str
    scope: str
    target_version: str
    target_gate: str
    content_bytes: bytes
    content_sha256: str
    capture_time: datetime
    authorized_roles: tuple[str, ...]
    expires_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_expired(self, at: datetime | None = None) -> bool:
        check_time = at or datetime.now(timezone.utc)
        if self.expires_at is None:
            return False
        return check_time > self.expires_at


class EvidenceReferenceResolver(Protocol):
    """Protocol for resolving bank evidence references."""
    def resolve_artifact(
        self,
        evidence_reference: str,
        installation_id: str,
        actor_role: str,
    ) -> BankEvidenceArtifact | None: ...

    def verify_readiness_evidence(
        self,
        *,
        evidence_reference: str,
        expected_digest: str,
        installation_id: str,
        release_version: str,
        gate_name: str,
        actor_role: str,
    ) -> tuple[bool, str]: ...


class BankEvidenceAdapter:
    """In-memory and repository-backed bank evidence resolver verifying real artifacts."""

    def __init__(self, is_configured: bool = True) -> None:
        self.is_configured = is_configured
        self._artifacts: dict[str, BankEvidenceArtifact] = {}

    def register_artifact(self, artifact: BankEvidenceArtifact) -> None:
        # Recompute digest on registration to enforce integrity
        actual_digest = hashlib.sha256(artifact.content_bytes).hexdigest()
        if not hmac.compare_digest(artifact.content_sha256, actual_digest):
            raise ValueError(f"Artifact {artifact.artifact_id} digest mismatch on registration")
        self._artifacts[artifact.artifact_id] = artifact

    def resolve_artifact(
        self,
        evidence_reference: str,
        installation_id: str,
        actor_role: str,
    ) -> BankEvidenceArtifact | None:
        if not self.is_configured:
            return None

        # Reject arbitrary caller-supplied HTTP/HTTPS/FTP URLs
        if re.match(r"^(https?|ftp|file)://", evidence_reference, re.IGNORECASE):
            return None

        artifact = self._artifacts.get(evidence_reference)
        if artifact is None:
            return None

        # Tenant isolation
        if artifact.installation_id != installation_id:
            return None

        # Role-based authorization
        if actor_role not in artifact.authorized_roles and "admin" not in artifact.authorized_roles:
            return None

        return artifact

    def verify_readiness_evidence(
        self,
        *,
        evidence_reference: str,
        expected_digest: str,
        installation_id: str,
        release_version: str,
        gate_name: str,
        actor_role: str,
    ) -> tuple[bool, str]:
        if not self.is_configured:
            return False, "No bank evidence adapter is configured; evidence cannot be verified"

        # Reject raw external URLs
        if re.match(r"^(https?|ftp|file)://", evidence_reference, re.IGNORECASE):
            return False, f"Raw URL '{evidence_reference}' is not an authorized bank evidence reference"

        artifact = self.resolve_artifact(evidence_reference, installation_id, actor_role)
        if artifact is None:
            return False, f"Evidence artifact '{evidence_reference}' could not be resolved or is not accessible in installation '{installation_id}'"

        # Check expiration
        now = datetime.now(timezone.utc)
        if artifact.is_expired(now):
            return False, f"Evidence artifact '{evidence_reference}' expired at {artifact.expires_at}"

        # Recompute cryptographic digest
        actual_digest = hashlib.sha256(artifact.content_bytes).hexdigest()
        if not hmac.compare_digest(expected_digest, actual_digest):
            return False, f"Cryptographic digest mismatch: expected '{expected_digest}', computed '{actual_digest}'"

        # Scope validation: gate and release version
        if artifact.target_gate and artifact.target_gate != gate_name:
            return False, f"Evidence artifact gate '{artifact.target_gate}' does not match requested gate '{gate_name}'"

        if artifact.target_version and artifact.target_version != release_version:
            return False, f"Evidence artifact version '{artifact.target_version}' does not match release version '{release_version}'"

        return True, "Evidence artifact verified against bank-controlled store"
