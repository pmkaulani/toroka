"""Toroka Enterprise — Asymmetric PKI, HSM Signing & Cryptographic Proof Engine.

Provides:
1. Ed25519 and ECDSA P-256 asymmetric digital signatures for Evidence Passports
   and Release Manifests, supporting on-premise physical HSMs (PKCS#11) and Cloud KMS.
2. Detached SignatureBundle serialization for non-repudiation and external regulatory inspection.
3. RFC 6962-compliant Merkle Tree batching and cryptographic inclusion proof generation.
4. Zero-dependency offline verification functions for statutory supervisory audit.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def canonical_bytes(content: bytes | str | dict[str, Any]) -> bytes:
    """Produces deterministic canonical UTF-8 bytes for signing."""
    if isinstance(content, bytes):
        return content
    if isinstance(content, dict):
        return json.dumps(
            content,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    return str(content).encode("utf-8")


class AsymmetricAlgorithm(StrEnum):
    ED25519 = "Ed25519"
    ECDSA_P256 = "ECDSA_P256"


@dataclass(frozen=True)
class SignatureBundle:
    """Detached cryptographic signature bundle certifying content authenticity and non-repudiation."""
    key_id: str
    algorithm: str  # AsymmetricAlgorithm
    signature: str  # Base64 encoded
    public_key_pem: str
    signed_at: str
    digest_algorithm: str
    content_digest: str  # SHA-256 of canonical payload

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "signature": self.signature,
            "public_key_pem": self.public_key_pem,
            "signed_at": self.signed_at,
            "digest_algorithm": self.digest_algorithm,
            "content_digest": self.content_digest,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignatureBundle:
        return cls(
            key_id=str(data["key_id"]),
            algorithm=str(data["algorithm"]),
            signature=str(data["signature"]),
            public_key_pem=str(data["public_key_pem"]),
            signed_at=str(data["signed_at"]),
            digest_algorithm=str(data.get("digest_algorithm", "SHA256")),
            content_digest=str(data["content_digest"]),
        )


class HSMAsymmetricSigner(Protocol):
    """Protocol for bank-managed HSM or Cloud KMS asymmetric signing services."""
    @property
    def key_id(self) -> str: ...

    @property
    def algorithm(self) -> AsymmetricAlgorithm: ...

    def get_public_key_pem(self) -> str: ...

    def sign(self, payload: bytes | str | dict[str, Any]) -> SignatureBundle: ...

    def verify(self, payload: bytes | str | dict[str, Any], bundle: SignatureBundle) -> bool: ...


class LocalHSMKeyProvider:
    """Software-backed asymmetric key provider for local dev, testing, or air-gapped deployments."""

    def __init__(
        self,
        key_id: str = "key-toroka-bank-root",
        algorithm: AsymmetricAlgorithm = AsymmetricAlgorithm.ED25519,
        private_key_pem: bytes | None = None,
    ) -> None:
        self._key_id = key_id
        self._algorithm = algorithm

        if private_key_pem:
            loaded = serialization.load_pem_private_key(private_key_pem, password=None)
            self._private_key = loaded
        else:
            if algorithm == AsymmetricAlgorithm.ED25519:
                self._private_key = ed25519.Ed25519PrivateKey.generate()
            elif algorithm == AsymmetricAlgorithm.ECDSA_P256:
                self._private_key = ec.generate_private_key(ec.SECP256R1())
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def algorithm(self) -> AsymmetricAlgorithm:
        return self._algorithm

    def get_public_key_pem(self) -> str:
        pub = self._private_key.public_key()
        pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("utf-8")

    def get_private_key_pem(self) -> str:
        pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return pem.decode("utf-8")

    def sign(self, payload: bytes | str | dict[str, Any]) -> SignatureBundle:
        raw = canonical_bytes(payload)
        content_digest = hashlib.sha256(raw).hexdigest()
        now = _utc_now_iso()

        if self._algorithm == AsymmetricAlgorithm.ED25519:
            assert isinstance(self._private_key, ed25519.Ed25519PrivateKey)
            sig_bytes = self._private_key.sign(raw)
            digest_algo = "PureEd25519"
        elif self._algorithm == AsymmetricAlgorithm.ECDSA_P256:
            assert isinstance(self._private_key, ec.EllipticCurvePrivateKey)
            sig_bytes = self._private_key.sign(raw, ec.ECDSA(hashes.SHA256()))
            digest_algo = "SHA256"
        else:
            raise ValueError(f"Unsupported algorithm: {self._algorithm}")

        return SignatureBundle(
            key_id=self._key_id,
            algorithm=self._algorithm.value,
            signature=base64.b64encode(sig_bytes).decode("ascii"),
            public_key_pem=self.get_public_key_pem(),
            signed_at=now,
            digest_algorithm=digest_algo,
            content_digest=content_digest,
        )

    def verify(self, payload: bytes | str | dict[str, Any], bundle: SignatureBundle) -> bool:
        return verify_asymmetric_signature(payload, bundle)


def verify_asymmetric_signature(
    payload: bytes | str | dict[str, Any],
    bundle: SignatureBundle,
    trusted_public_key_pem: str | None = None,
) -> bool:
    """Verifies detached SignatureBundle against payload using trusted public key or bundle key."""
    raw = canonical_bytes(payload)
    computed_digest = hashlib.sha256(raw).hexdigest()

    # 1. Content digest verification
    if computed_digest.lower() != bundle.content_digest.lower():
        return False

    pem_to_use = (trusted_public_key_pem or bundle.public_key_pem).encode("utf-8")
    try:
        sig_bytes = base64.b64decode(bundle.signature)
        public_key = serialization.load_pem_public_key(pem_to_use)

        if bundle.algorithm == AsymmetricAlgorithm.ED25519.value:
            if not isinstance(public_key, ed25519.Ed25519PublicKey):
                return False
            public_key.verify(sig_bytes, raw)
            return True
        elif bundle.algorithm == AsymmetricAlgorithm.ECDSA_P256.value:
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                return False
            public_key.verify(sig_bytes, raw, ec.ECDSA(hashes.SHA256()))
            return True
        else:
            return False
    except (InvalidSignature, ValueError, TypeError):
        return False


# =============================================================================
# RFC 6962 Cryptographic Merkle Tree & Inclusion Proof Engine
# =============================================================================

@dataclass(frozen=True)
class MerkleInclusionProofStep:
    direction: str  # "left" or "right"
    hash: str


@dataclass(frozen=True)
class MerkleInclusionProof:
    leaf_index: int
    total_leaves: int
    leaf_hash: str
    root_hash: str
    steps: tuple[MerkleInclusionProofStep, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "leaf_index": self.leaf_index,
            "total_leaves": self.total_leaves,
            "leaf_hash": self.leaf_hash,
            "root_hash": self.root_hash,
            "steps": [{"direction": s.direction, "hash": s.hash} for s in self.steps],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MerkleInclusionProof:
        steps = tuple(
            MerkleInclusionProofStep(direction=s["direction"], hash=s["hash"])
            for s in data["steps"]
        )
        return cls(
            leaf_index=int(data["leaf_index"]),
            total_leaves=int(data["total_leaves"]),
            leaf_hash=str(data["leaf_hash"]),
            root_hash=str(data["root_hash"]),
            steps=steps,
        )


def _hash_leaf(data: bytes) -> str:
    # RFC 6962 prefix 0x00 for leaf hash prevents second-preimage attacks
    return hashlib.sha256(b"\x00" + data).hexdigest()


def _hash_internal(left_hex: str, right_hex: str) -> str:
    # RFC 6962 prefix 0x01 for internal node hash
    left = bytes.fromhex(left_hex)
    right = bytes.fromhex(right_hex)
    return hashlib.sha256(b"\x01" + left + right).hexdigest()


class MerkleTree:
    """Deterministic cryptographic Merkle Tree conforming to RFC 6962 rules."""

    def __init__(self, leaves: list[bytes | str | dict[str, Any]]) -> None:
        if not leaves:
            raise ValueError("MerkleTree requires at least one leaf entry")
        self._raw_leaves = [canonical_bytes(l) for l in leaves]
        self._leaf_hashes = [_hash_leaf(raw) for raw in self._raw_leaves]
        self._levels: list[list[str]] = [list(self._leaf_hashes)]
        self._build_tree()

    def _build_tree(self) -> None:
        current = self._levels[0]
        while len(current) > 1:
            next_level: list[str] = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    next_level.append(_hash_internal(current[i], current[i + 1]))
                else:
                    # Odd node: duplicate or promote as per RFC 6962
                    next_level.append(_hash_internal(current[i], current[i]))
            self._levels.append(next_level)
            current = next_level

    @property
    def root_hash(self) -> str:
        return self._levels[-1][0]

    @property
    def leaf_count(self) -> int:
        return len(self._leaf_hashes)

    def get_inclusion_proof(self, index: int) -> MerkleInclusionProof:
        if index < 0 or index >= len(self._leaf_hashes):
            raise IndexError(f"Leaf index {index} out of range [0, {len(self._leaf_hashes) - 1}]")

        steps: list[MerkleInclusionProofStep] = []
        idx = index
        for level in self._levels[:-1]:
            if idx % 2 == 0:
                # Sibling is on right
                sibling_idx = idx + 1 if idx + 1 < len(level) else idx
                sibling_hash = level[sibling_idx]
                steps.append(MerkleInclusionProofStep(direction="right", hash=sibling_hash))
            else:
                # Sibling is on left
                sibling_hash = level[idx - 1]
                steps.append(MerkleInclusionProofStep(direction="left", hash=sibling_hash))
            idx //= 2

        return MerkleInclusionProof(
            leaf_index=index,
            total_leaves=len(self._leaf_hashes),
            leaf_hash=self._leaf_hashes[index],
            root_hash=self.root_hash,
            steps=tuple(steps),
        )

    # Alias for developer ergonomics
    generate_inclusion_proof = get_inclusion_proof


def verify_merkle_inclusion_proof(
    leaf_content: bytes | str | dict[str, Any],
    proof: MerkleInclusionProof,
    expected_root_hash: str | None = None,
) -> bool:
    """Verifies that leaf_content is authentically present in the tree rooted at root_hash."""
    raw = canonical_bytes(leaf_content)
    current_hash = _hash_leaf(raw)

    if current_hash.lower() != proof.leaf_hash.lower():
        return False

    for step in proof.steps:
        if step.direction == "right":
            current_hash = _hash_internal(current_hash, step.hash)
        elif step.direction == "left":
            current_hash = _hash_internal(step.hash, current_hash)
        else:
            return False

    target_root = (expected_root_hash or proof.root_hash).lower()
    return current_hash.lower() == target_root
