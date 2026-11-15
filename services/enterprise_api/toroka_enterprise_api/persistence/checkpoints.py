"""Independent signed audit checkpoints and immutable anchoring."""
from __future__ import annotations

import base64
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol
from sqlalchemy.orm import Session

from .audit import verify_audit_chain
from .models import AuditHead, AuditRecord


class CheckpointSigner(Protocol):
    """Protocol for signing audit checkpoints using a separately managed key or KMS."""

    def sign(self, payload: bytes) -> tuple[str, bytes]:
        """Return (key_id, signature)."""
        ...


class CheckpointVerifier(Protocol):
    """Protocol for verifying audit checkpoint signatures."""

    def verify(self, payload: bytes, key_id: str, signature: bytes) -> bool:
        """Verify signature validity for the given payload."""
        ...


class HMACCheckpointSigner:
    """HMAC-SHA256 checkpoint signer for development, testing, and standard key references."""

    def __init__(self, key: bytes, key_id: str = "k1"):
        self.key = key
        self.key_id = key_id

    def sign(self, payload: bytes) -> tuple[str, bytes]:
        signature = hmac.new(self.key, payload, "sha256").digest()
        return self.key_id, signature


class HMACCheckpointVerifier:
    """HMAC-SHA256 checkpoint verifier matching HMACCheckpointSigner."""

    def __init__(self, key: bytes, key_id: str = "k1"):
        self.key = key
        self.key_id = key_id

    def verify(self, payload: bytes, key_id: str, signature: bytes) -> bool:
        if key_id != self.key_id:
            return False
        expected = hmac.new(self.key, payload, "sha256").digest()
        return hmac.compare_digest(expected, signature)


class ImmutableCheckpointStore(Protocol):
    """Protocol for bank-controlled immutable object storage."""

    def put_if_absent(self, object_key: str, content: bytes) -> None:
        """Write an immutable object. Overwriting must raise FileExistsError."""
        ...

    def get(self, object_key: str) -> bytes | None:
        """Retrieve stored checkpoint object."""
        ...

    def list_keys(self, prefix: str = "") -> list[str]:
        """List object keys starting with prefix."""
        ...


class MemoryImmutableCheckpointStore:
    """In-memory immutable checkpoint store for testing and verification."""

    def __init__(self):
        self._store: dict[str, bytes] = {}

    def put_if_absent(self, object_key: str, content: bytes) -> None:
        if object_key in self._store:
            raise FileExistsError(f"Immutable checkpoint '{object_key}' cannot be overwritten")
        self._store[object_key] = content

    def get(self, object_key: str) -> bytes | None:
        return self._store.get(object_key)

    def list_keys(self, prefix: str = "") -> list[str]:
        return [k for k in sorted(self._store.keys()) if k.startswith(prefix)]


class DirectoryImmutableCheckpointStore:
    """Filesystem-backed immutable checkpoint store respecting write-once policy."""

    def __init__(self, base_dir: Path | str):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def put_if_absent(self, object_key: str, content: bytes) -> None:
        file_path = self.base_dir / object_key
        if file_path.exists():
            raise FileExistsError(f"Immutable checkpoint '{object_key}' already exists on disk")
        file_path.parent.mkdir(parents=True, exist_ok=True)
        # Write to temporary file and move without overwriting
        tmp_file = file_path.with_suffix(".tmp")
        tmp_file.write_bytes(content)
        # Exclusive rename
        tmp_file.rename(file_path)

    def get(self, object_key: str) -> bytes | None:
        file_path = self.base_dir / object_key
        if not file_path.is_file():
            return None
        return file_path.read_bytes()

    def list_keys(self, prefix: str = "") -> list[str]:
        keys = []
        for p in self.base_dir.rglob("*.json"):
            rel = p.relative_to(self.base_dir).as_posix()
            if rel.startswith(prefix):
                keys.append(rel)
        return sorted(keys)


class AuditCheckpointManager:
    """Creates, signs, stores, and independently verifies audit checkpoints."""

    @staticmethod
    def create_checkpoint(
        installation_id: str,
        db: Session,
        signer: CheckpointSigner,
        store: ImmutableCheckpointStore,
    ) -> dict:
        """Capture the current audit sequence and chain head hash, sign, and store immutably."""
        # 1. Verify existing chain integrity before checkpointing
        is_valid, current_head_hash, total_records = verify_audit_chain(db, installation_id)
        if not is_valid:
            raise ValueError(f"Cannot create checkpoint: audit chain integrity check failed for installation '{installation_id}'")

        # 2. Retrieve current head
        head = db.get(AuditHead, installation_id)
        if head is None:
            raise LookupError(f"No audit records or audit head found for installation '{installation_id}'")

        checkpoint_data = {
            "version": "1.0",
            "installation_id": installation_id,
            "head_sequence": head.last_sequence,
            "head_hash": head.last_hash,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        canonical_payload = json.dumps(checkpoint_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        key_id, signature = signer.sign(canonical_payload)

        envelope = {
            "data": checkpoint_data,
            "key_id": key_id,
            "signature": base64.b64encode(signature).decode("ascii"),
        }

        object_key = f"checkpoints/{installation_id}/checkpoint_seq_{head.last_sequence:012d}.json"
        store.put_if_absent(object_key, json.dumps(envelope, indent=2).encode("utf-8"))
        return envelope

    @staticmethod
    def verify_checkpoint(
        envelope: dict,
        verifier: CheckpointVerifier,
        db: Session,
    ) -> tuple[bool, str]:
        """Verify checkpoint signature and validate against internal database records."""
        data = envelope.get("data")
        key_id = envelope.get("key_id")
        sig_str = envelope.get("signature")

        if not data or not key_id or not sig_str:
            return False, "Malformed checkpoint envelope: missing data, key_id, or signature"

        try:
            signature = base64.b64decode(sig_str.encode("ascii"))
        except Exception:
            return False, "Invalid base64 signature encoding"

        canonical_payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if not verifier.verify(canonical_payload, key_id, signature):
            return False, "Cryptographic signature verification failed"

        installation_id = data["installation_id"]
        expected_seq = data["head_sequence"]
        expected_hash = data["head_hash"]

        # Check database record at expected_seq
        record = db.query(AuditRecord).filter_by(
            installation_id=installation_id,
            sequence=expected_seq,
        ).first()

        if record is None:
            return False, f"Audit record sequence {expected_seq} not found in database (possible truncation or restoration rollback)"

        if record.event_hash != expected_hash:
            return False, f"Hash mismatch at sequence {expected_seq}: recorded '{record.event_hash}' != checkpoint '{expected_hash}' (database tampering detected)"

        return True, "Checkpoint signature and database records successfully verified"
