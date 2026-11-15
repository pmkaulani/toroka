"""Separated Identity Vault persistence and encryption abstraction."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import DateTime, LargeBinary, String
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class VaultBase(DeclarativeBase):
    """Separate SQLAlchemy declarative base for identity vault tables."""
    pass


class VaultRecord(VaultBase):
    __tablename__ = "enterprise_identity_vault"

    pseudonym: Mapped[str] = mapped_column(
        String(255), primary_key=True
    )
    ciphertext: Mapped[bytes] = mapped_column(
        LargeBinary, nullable=False
    )
    key_version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="v1"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    rotated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class VaultCipher(Protocol):
    """Encryption abstraction for identity vault at-rest protection."""

    def encrypt(self, plaintext: str, key_version: str | None = None) -> tuple[bytes, str]:
        ...

    def decrypt(self, ciphertext: bytes, key_version: str) -> str:
        ...

    def rotate(
        self,
        ciphertext: bytes,
        old_key_version: str,
        new_key_version: str,
    ) -> tuple[bytes, str]:
        ...


class FernetVaultCipher:
    """Fernet implementation of VaultCipher with multi-version key support."""

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

    def encrypt(self, plaintext: str, key_version: str | None = None) -> tuple[bytes, str]:
        version = key_version or self.current_version
        if version not in self._keys:
            raise ValueError(f"Key version '{version}' is not configured")
        fernet = self._keys[version]
        ciphertext = fernet.encrypt(plaintext.encode("utf-8"))
        return ciphertext, version

    def decrypt(self, ciphertext: bytes, key_version: str) -> str:
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
    ) -> tuple[bytes, str]:
        plaintext = self.decrypt(ciphertext, old_key_version)
        return self.encrypt(plaintext, new_key_version)


class IdentityVaultRepository:
    """Repository managing isolated identity vault records."""

    def __init__(self, db: Session, cipher: VaultCipher):
        self.db = db
        self.cipher = cipher

    def store(
        self,
        pseudonym: str,
        plaintext_identity: str,
        key_version: str | None = None,
    ) -> VaultRecord:
        ciphertext, version = self.cipher.encrypt(plaintext_identity, key_version)
        record = self.db.get(VaultRecord, pseudonym)
        if record is None:
            record = VaultRecord(
                pseudonym=pseudonym,
                ciphertext=ciphertext,
                key_version=version,
            )
            self.db.add(record)
        else:
            record.ciphertext = ciphertext
            record.key_version = version
            record.rotated_at = utc_now()
        self.db.flush()
        return record

    def retrieve_and_decrypt(self, pseudonym: str) -> str | None:
        record = self.db.get(VaultRecord, pseudonym)
        if record is None:
            return None
        return self.cipher.decrypt(record.ciphertext, record.key_version)

    def has_pseudonym(self, pseudonym: str) -> bool:
        return self.db.get(VaultRecord, pseudonym) is not None

    def rotate_key(
        self,
        pseudonym: str,
        new_key_version: str,
    ) -> VaultRecord:
        record = self.db.get(VaultRecord, pseudonym)
        if record is None:
            raise LookupError(f"Pseudonym '{pseudonym}' not found in vault")
        new_ciphertext, version = self.cipher.rotate(
            record.ciphertext, record.key_version, new_key_version
        )
        record.ciphertext = new_ciphertext
        record.key_version = version
        record.rotated_at = utc_now()
        self.db.flush()
        return record
