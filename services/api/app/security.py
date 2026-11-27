from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from cryptography.fernet import Fernet


class Crypto:
    """Field encryption (Fernet) and keyed lookup digests (HMAC) so raw identifiers never sit in indexes or logs."""

    def __init__(self, encryption_key: str, hmac_key: str):
        self._f, self._k = Fernet(encryption_key.encode()), hmac_key.encode()

    def enc(self, value: str | bytes) -> str:
        return self._f.encrypt(value.encode() if isinstance(value, str) else value).decode()

    def dec(self, token: str) -> str:
        return self._f.decrypt(token.encode()).decode()

    def enc_bytes(self, data: bytes) -> bytes:
        return self._f.encrypt(data)

    def dec_bytes(self, data: bytes) -> bytes:
        return self._f.decrypt(data)

    def lookup(self, kind: str, value: str) -> str:
        return hmac.new(self._k, f"{kind}:{value}".encode(), hashlib.sha256).hexdigest()


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def new_token(n: int = 24) -> str:
    return secrets.token_urlsafe(n)


def same(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)


def hash_password(pw: str) -> str:
    salt = os.urandom(16)
    # OWASP recommended work factor n=2**17 (131,072)
    n = 2**17
    h = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=8, p=1, dklen=32, maxmem=256 * 1024 * 1024)
    return f"scrypt${n}$8$1$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(h).decode()


_CURRENT_N = 2**17  # keep in sync with hash_password


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32, maxmem=256 * 1024 * 1024)
        return hmac.compare_digest(calc, base64.b64decode(h))
    except Exception:
        return False


def needs_rehash(stored: str) -> bool:
    """Return True if the stored hash was produced with a lower work factor than the current one.

    Call this after a successful ``verify_password`` and, if True, replace the stored
    hash with ``hash_password(plaintext)`` before the response is committed.  This
    provides a transparent upgrade path from the old n=2**14 work factor without
    requiring a forced password-reset.
    """
    try:
        _, n, _r, _p, _salt, _h = stored.split("$")
        return int(n) < _CURRENT_N
    except Exception:
        return False
