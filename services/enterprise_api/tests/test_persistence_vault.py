"""Tests for separated Identity Vault encryption, key versioning, and rotation."""
from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from toroka_enterprise_api.persistence.vault import (
    FernetVaultCipher,
    IdentityVaultRepository,
    VaultRecord,
)


def test_vault_encryption_at_rest(test_vault_repo, vault_db_session):
    pseudonym = "STF-7489a2b8e39f"
    plaintext = "EMP-00123-JOHN-DOE"

    record = test_vault_repo.store(pseudonym, plaintext, key_version="v1")
    assert record.pseudonym == pseudonym
    assert record.key_version == "v1"

    # Assert record at rest is encrypted bytes, not plaintext
    raw = vault_db_session.get(VaultRecord, pseudonym)
    assert raw is not None
    assert raw.ciphertext != plaintext.encode("utf-8")
    assert isinstance(raw.ciphertext, bytes)
    assert plaintext.encode("utf-8") not in raw.ciphertext

    # Decrypt returns original plaintext
    decrypted = test_vault_repo.retrieve_and_decrypt(pseudonym)
    assert decrypted == plaintext


def test_vault_wrong_key_fails_safely():
    key1 = Fernet.generate_key().decode()
    key2 = Fernet.generate_key().decode()

    cipher1 = FernetVaultCipher({"v1": key1}, current_version="v1")
    cipher2 = FernetVaultCipher({"v1": key2}, current_version="v1")

    ciphertext, ver = cipher1.encrypt("SECRET-IDENTITY")

    # Decrypting with different key fails safely
    with pytest.raises(ValueError, match="Decryption failed"):
        cipher2.decrypt(ciphertext, ver)


def test_vault_key_rotation_preserves_access(vault_db_session):
    k1 = Fernet.generate_key().decode()
    k2 = Fernet.generate_key().decode()

    cipher = FernetVaultCipher({"v1": k1, "v2": k2}, current_version="v1")
    repo = IdentityVaultRepository(vault_db_session, cipher)

    pseudonym = "STF-ROTATION-01"
    plaintext = "CONFIDENTIAL-STAFF-ID"

    # Store with v1
    repo.store(pseudonym, plaintext, key_version="v1")
    raw1 = vault_db_session.get(VaultRecord, pseudonym)
    assert raw1.key_version == "v1"
    old_ciphertext = raw1.ciphertext

    # Rotate to v2
    rotated_rec = repo.rotate_key(pseudonym, new_key_version="v2")
    assert rotated_rec.key_version == "v2"
    assert rotated_rec.ciphertext != old_ciphertext

    # Can still decrypt with rotated key
    assert repo.retrieve_and_decrypt(pseudonym) == plaintext
