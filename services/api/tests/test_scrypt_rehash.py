"""Regression tests for security.py hardening changes:

- needs_rehash correctly detects old work factors
- login transparently re-hashes a low-n hash on successful login
"""
import base64
import hashlib
import os

import pytest

from app.security import hash_password, needs_rehash, verify_password


# ---------------------------------------------------------------------------
# Unit tests for needs_rehash
# ---------------------------------------------------------------------------

def _make_hash_with_n(pw: str, n: int) -> str:
    salt = os.urandom(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=8, p=1, dklen=32,
                       maxmem=256 * 1024 * 1024)
    return f"scrypt${n}$8$1$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(h).decode()


def test_needs_rehash_old_work_factor():
    stored = _make_hash_with_n("pw", 2**14)
    assert needs_rehash(stored) is True


def test_needs_rehash_current_work_factor():
    stored = hash_password("pw")
    assert needs_rehash(stored) is False


def test_needs_rehash_malformed_returns_false():
    assert needs_rehash("not-a-valid-hash") is False
    assert needs_rehash("") is False


def test_verify_password_still_works_on_old_n():
    pw = "hunter2"
    stored = _make_hash_with_n(pw, 2**14)
    assert verify_password(pw, stored) is True
    assert verify_password("wrong", stored) is False


# ---------------------------------------------------------------------------
# Integration test: login upgrades a low-n hash transparently
# ---------------------------------------------------------------------------

def test_login_rehashes_old_work_factor(tmp_path):
    """After a successful login the stored hash must use the current work factor."""
    from app import db as m
    from conftest import Env

    env = Env(tmp_path)
    # Register user (creates hash with current n)
    r = env.client.post("/v1/auth/register",
                        json={"email": "rehash@example.com", "password": "CorrectHorseBattery!"})
    assert r.status_code == 201, r.text
    uid = r.json()["user_id"]

    # Backdoor: overwrite stored hash with an old-n hash
    old_hash = _make_hash_with_n("CorrectHorseBattery!", 2**14)
    with env.db() as db:
        u = db.get(m.User, uid)
        u.password_hash = old_hash
        db.commit()

    # Login should succeed and transparently upgrade the hash
    r2 = env.client.post("/v1/auth/login",
                         json={"email": "rehash@example.com", "password": "CorrectHorseBattery!"})
    assert r2.status_code == 200, r2.text

    with env.db() as db:
        u = db.get(m.User, uid)
        assert not needs_rehash(u.password_hash), (
            "Hash should have been upgraded to current work factor on login"
        )
        # Verify the new hash still works
        assert verify_password("CorrectHorseBattery!", u.password_hash)
