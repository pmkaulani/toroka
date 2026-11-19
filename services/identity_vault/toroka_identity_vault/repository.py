"""Repository managing isolated identity vault records with AAD binding."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .crypto import VaultCipher
from .models import VaultRecord, utc_now


class IdentityVaultRepository:
    """Repository managing isolated identity vault records."""

    def __init__(self, db: Session, cipher: VaultCipher):
        self.db = db
        self.cipher = cipher

    def store(
        self,
        installation_id: str,
        pseudonym: str,
        plaintext_identity: str,
        key_version: str | None = None,
    ) -> VaultRecord:
        aad = f"{installation_id}:{pseudonym}".encode("utf-8")
        ciphertext, version = self.cipher.encrypt(plaintext_identity, key_version, aad=aad)

        stmt = select(VaultRecord).where(
            VaultRecord.installation_id == installation_id,
            VaultRecord.pseudonym == pseudonym,
        )
        record = self.db.execute(stmt).scalar_one_or_none()
        if record is None:
            record = VaultRecord(
                installation_id=installation_id,
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

    def retrieve_and_decrypt(self, installation_id: str, pseudonym: str) -> str | None:
        stmt = select(VaultRecord).where(
            VaultRecord.installation_id == installation_id,
            VaultRecord.pseudonym == pseudonym,
        )
        record = self.db.execute(stmt).scalar_one_or_none()
        if record is None:
            return None

        aad = f"{installation_id}:{pseudonym}".encode("utf-8")
        try:
            return self.cipher.decrypt(record.ciphertext, record.key_version, aad=aad)
        except Exception:
            # Fallback for legacy dev records created without AAD binding
            try:
                return self.cipher.decrypt(record.ciphertext, record.key_version, aad=b"")
            except Exception:
                return None

    def has_pseudonym(self, installation_id: str, pseudonym: str) -> bool:
        stmt = select(VaultRecord).where(
            VaultRecord.installation_id == installation_id,
            VaultRecord.pseudonym == pseudonym,
        )
        return self.db.execute(stmt).scalar_one_or_none() is not None

    def rotate_key(
        self,
        installation_id: str,
        pseudonym: str,
        new_key_version: str,
    ) -> VaultRecord:
        stmt = select(VaultRecord).where(
            VaultRecord.installation_id == installation_id,
            VaultRecord.pseudonym == pseudonym,
        )
        record = self.db.execute(stmt).scalar_one_or_none()
        if record is None:
            raise LookupError(f"Pseudonym '{pseudonym}' not found in vault for installation '{installation_id}'")

        aad = f"{installation_id}:{pseudonym}".encode("utf-8")
        new_ciphertext, version = self.cipher.rotate(
            record.ciphertext, record.key_version, new_key_version, aad=aad
        )
        record.ciphertext = new_ciphertext
        record.key_version = version
        record.rotated_at = utc_now()
        self.db.flush()
        return record
