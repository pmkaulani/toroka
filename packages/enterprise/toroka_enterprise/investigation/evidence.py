"""Evidence integrity and chain-of-custody verification utilities."""
from __future__ import annotations

import hashlib
import hmac
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    """Computes SHA-256 hex digest of raw byte content."""
    return hashlib.sha256(data).hexdigest().lower()


def sha256_file(path: str | Path) -> str:
    """Computes SHA-256 hex digest of an on-disk artefact."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().lower()


def verify_evidence_bytes(
    *,
    data: bytes | None = None,
    path: str | Path | None = None,
    expected_sha256: str,
) -> bool:
    """Verifies that actual artefact bytes match expected SHA-256 in constant time."""
    if data is not None:
        actual = sha256_bytes(data)
    elif path is not None:
        actual = sha256_file(path)
    else:
        raise ValueError("Must provide either data bytes or a file path to verify")

    return hmac.compare_digest(actual.lower(), expected_sha256.lower().strip())
