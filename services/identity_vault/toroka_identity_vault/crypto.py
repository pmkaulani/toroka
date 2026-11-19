"""Envelope encryption, KMS key provider interfaces, and cipher implementations."""
from __future__ import annotations

import base64
import json
import os
from typing import Protocol
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class KMSKeyProvider(Protocol):
    """Adapter to a bank-managed KMS or HSM."""

    def generate_data_key(
        self,
        key_id: str,
    ) -> tuple[bytes, bytes]:
        """Return (plaintext_32_byte_data_key, kms_wrapped_data_key)."""
        ...

    def decrypt_data_key(
        self,
        key_id: str,
        encrypted_data_key: bytes,
    ) -> bytes:
        """Unwrap KMS-wrapped data key to return plaintext 32-byte data key."""
        ...


def encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


class LocalKMSKeyProvider:
    """Software-backed AES-GCM KMS simulation for development and testing.
    
    Uses a master Key Encryption Key (KEK) to wrap and unwrap Data Encryption Keys.
    In a real bank environment, this is replaced by the bank's KMS/HSM adapter.
    """

    def __init__(self, master_kek: bytes | None = None):
        # 256-bit Master KEK
        self.master_kek = master_kek or os.urandom(32)
        self._kek_cipher = AESGCM(self.master_kek)

    def generate_data_key(self, key_id: str) -> tuple[bytes, bytes]:
        plaintext_dek = os.urandom(32)
        nonce = os.urandom(12)
        aad = key_id.encode("utf-8")
        wrapped = nonce + self._kek_cipher.encrypt(nonce, plaintext_dek, aad)
        return plaintext_dek, wrapped

    def decrypt_data_key(self, key_id: str, encrypted_data_key: bytes) -> bytes:
        if len(encrypted_data_key) < 28:
            raise ValueError("Invalid wrapped data key payload")
        nonce = encrypted_data_key[:12]
        ciphertext = encrypted_data_key[12:]
        aad = key_id.encode("utf-8")
        try:
            return self._kek_cipher.decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise ValueError(f"Failed to unwrap data key with KMS key '{key_id}': {exc}") from exc


class DurableKMSKeyProvider:
    """Production-grade durable KMS Key Provider using a versioned master key encryption key (KEK).
    
    Requires an explicit 256-bit (32 bytes) master key loaded from bank secret stores or KMS.
    Refuses ephemeral in-memory generation to ensure key durability across replicas and restarts.
    """

    def __init__(self, master_kek: bytes, key_version: str = "v1"):
        if not master_kek or len(master_kek) < 32:
            raise ValueError("Durable master KEK must be at least 256 bits (32 bytes)")
        self.master_kek = master_kek
        self.key_version = key_version
        self._kek_cipher = AESGCM(self.master_kek)

    def generate_data_key(self, key_id: str) -> tuple[bytes, bytes]:
        plaintext_dek = os.urandom(32)
        nonce = os.urandom(12)
        aad = f"{key_id}:{self.key_version}".encode("utf-8")
        wrapped = nonce + self._kek_cipher.encrypt(nonce, plaintext_dek, aad)
        return plaintext_dek, wrapped

    def decrypt_data_key(self, key_id: str, encrypted_data_key: bytes) -> bytes:
        if len(encrypted_data_key) < 28:
            raise ValueError("Invalid wrapped data key payload")
        nonce = encrypted_data_key[:12]
        ciphertext = encrypted_data_key[12:]
        aad = f"{key_id}:{self.key_version}".encode("utf-8")
        try:
            return self._kek_cipher.decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise ValueError(f"Failed to unwrap data key with durable KMS key '{key_id}': {exc}") from exc


class VaultCipher(Protocol):
    """Encryption abstraction for identity vault at-rest protection."""

    def encrypt(
        self,
        plaintext: str,
        key_version: str | None = None,
        aad: bytes = b"",
    ) -> tuple[bytes, str]:
        ...

    def decrypt(
        self,
        ciphertext: bytes,
        key_version: str,
        aad: bytes = b"",
    ) -> str:
        ...

    def rotate(
        self,
        ciphertext: bytes,
        old_key_version: str,
        new_key_version: str,
        aad: bytes = b"",
    ) -> tuple[bytes, str]:
        ...


class EnvelopeVaultCipher:
    """Bank-grade envelope encryption using KMS/HSM and AES-256-GCM.
    
    Each identity mapping is encrypted with a unique, ephemeral 256-bit DEK.
    The DEK is wrapped by the KMS and stored alongside the ciphertext.
    Authenticated Additional Data (AAD) binds the ciphertext to the installation
    and pseudonym, preventing ciphertext tampering or cross-tenant substitution.
    """

    def __init__(
        self,
        key_provider: KMSKeyProvider,
        key_id_map: dict[str, str],
        current_version: str = "v1",
    ):
        self.key_provider = key_provider
        self.key_id_map = key_id_map
        if current_version not in key_id_map:
            raise ValueError(f"Current key version '{current_version}' not found in key map")
        self.current_version = current_version

    def encrypt(
        self,
        plaintext: str,
        key_version: str | None = None,
        aad: bytes = b"",
    ) -> tuple[bytes, str]:
        version = key_version or self.current_version
        if version not in self.key_id_map:
            raise ValueError(f"Key version '{version}' is not configured")
        kms_key_id = self.key_id_map[version]

        plaintext_dek, wrapped_dek = self.key_provider.generate_data_key(kms_key_id)
        aesgcm = AESGCM(plaintext_dek)
        nonce = os.urandom(12)
        ct_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)

        payload = {
            "format": "envelope_aes_256_gcm",
            "version": version,
            "kms_key_id": kms_key_id,
            "edks": encode(wrapped_dek),
            "nonce": encode(nonce),
            "ct": encode(ct_tag),
        }
        return json.dumps(payload).encode("utf-8"), version

    def decrypt(
        self,
        ciphertext: bytes,
        key_version: str,
        aad: bytes = b"",
    ) -> str:
        try:
            payload = json.loads(ciphertext.decode("utf-8"))
        except Exception:
            raise ValueError("Corrupted envelope ciphertext payload: not valid JSON")

        kms_key_id = payload.get("kms_key_id")
        if not kms_key_id:
            raise ValueError("Missing KMS key identifier in ciphertext envelope")

        wrapped_dek = decode(payload["edks"])
        nonce = decode(payload["nonce"])
        ct_tag = decode(payload["ct"])

        plaintext_dek = self.key_provider.decrypt_data_key(kms_key_id, wrapped_dek)
        aesgcm = AESGCM(plaintext_dek)
        try:
            plaintext_bytes = aesgcm.decrypt(nonce, ct_tag, aad)
            return plaintext_bytes.decode("utf-8")
        except Exception as exc:
            raise ValueError(f"Envelope decryption failed (AAD mismatch or corrupt data): {exc}") from exc

    def rotate(
        self,
        ciphertext: bytes,
        old_key_version: str,
        new_key_version: str,
        aad: bytes = b"",
    ) -> tuple[bytes, str]:
        plaintext = self.decrypt(ciphertext, old_key_version, aad=aad)
        return self.encrypt(plaintext, new_key_version, aad=aad)


class FernetVaultCipher:
    """Fernet implementation of VaultCipher for local development and testing."""

    def __init__(
        self,
        keys: dict[str, str | bytes],
        current_version: str = "v1",
    ):
        if not keys:
            raise ValueError("At least one vault encryption key must be provided")
        self._keys: dict[str, Fernet] = {}
        for ver, k in keys.items():
            key_bytes = k.encode("utf-8") if isinstance(k, str) else k
            self._keys[ver] = Fernet(key_bytes)
        if current_version not in self._keys:
            raise ValueError(f"Current key version '{current_version}' not found in key set")
        self.current_version = current_version

    def encrypt(
        self,
        plaintext: str,
        key_version: str | None = None,
        aad: bytes = b"",
    ) -> tuple[bytes, str]:
        version = key_version or self.current_version
        if version not in self._keys:
            raise ValueError(f"Key version '{version}' is not configured")
        fernet = self._keys[version]
        ciphertext = fernet.encrypt(plaintext.encode("utf-8"))
        return ciphertext, version

    def decrypt(
        self,
        ciphertext: bytes,
        key_version: str,
        aad: bytes = b"",
    ) -> str:
        if key_version not in self._keys:
            raise ValueError(f"Key version '{key_version}' is not configured")
        fernet = self._keys[key_version]
        try:
            plaintext_bytes = fernet.decrypt(ciphertext)
            return plaintext_bytes.decode("utf-8")
        except InvalidToken:
            raise ValueError("Decryption failed: invalid ciphertext or corrupted key")

    def rotate(
        self,
        ciphertext: bytes,
        old_key_version: str,
        new_key_version: str,
        aad: bytes = b"",
    ) -> tuple[bytes, str]:
        plaintext = self.decrypt(ciphertext, old_key_version, aad=aad)
        return self.encrypt(plaintext, new_key_version, aad=aad)
