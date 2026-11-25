"""Regression tests from the 2026-11 code review (rate limiter, proxy IP, env guard, PIN/OTP matching)."""
import pytest

from app.ai_agent import _PIN_OTP_RX
from app.config import Settings
from app.deps import client_key
from app.ratelimit import RateLimiter


class _Crypto:
    def lookup(self, kind, value):
        return f"{kind}:{value}"


class _Ctx:
    def __init__(self, trust=True, hops=1):
        self.settings = Settings(trust_proxy_headers=trust, trusted_proxy_hops=hops)
        self.crypto = _Crypto()


class _Req:
    def __init__(self, xff=None, host="10.0.0.1"):
        self.client = type("C", (), {"host": host})()
        self.headers = {"x-forwarded-for": xff} if xff else {}


def test_forged_leading_xff_entries_do_not_create_new_buckets():
    c = _Ctx(hops=1)
    keys = {client_key(_Req(f"203.0.113.{i}, 198.51.100.7"), c) for i in range(100)}
    assert keys == {"client:198.51.100.7"}


def test_two_trusted_hops_picks_second_from_right():
    c = _Ctx(hops=2)
    assert client_key(_Req("6.6.6.6, 198.51.100.7, 172.16.0.9"), c) == "client:198.51.100.7"


def test_xff_ignored_when_proxy_not_trusted():
    assert client_key(_Req("6.6.6.6", host="10.0.0.1"), _Ctx(trust=False)) == "client:10.0.0.1"


def test_limiter_still_limits():
    rl = RateLimiter()
    assert rl.hit("k", 2, 60) == 0 and rl.hit("k", 2, 60) == 0 and rl.hit("k", 2, 60) > 0


def test_limiter_evicts_expired_keys(monkeypatch):
    import app.ratelimit as r
    now = [1000.0]
    monkeypatch.setattr(r.time, "monotonic", lambda: now[0])
    rl = RateLimiter()
    for i in range(3000):
        rl.hit(f"k{i}", 5, 10)
    now[0] += 60
    for i in range(2048):
        rl.hit("fresh", 5, 10)
    assert len(rl._hits) < 100


@pytest.mark.parametrize("env", ["production", "prod", "PROD", " Production "])
def test_prod_env_requires_keys(env):
    with pytest.raises(RuntimeError):
        Settings(env=env, encryption_key="", hmac_key="").with_dev_keys()


def test_dev_env_still_gets_ephemeral_keys():
    s = Settings(env="dev", encryption_key="", hmac_key="").with_dev_keys()
    assert s.encryption_key and s.hmac_key


@pytest.mark.parametrize("msg", [
    "is this instagram shop legit? they are shopping online",
    "what is your opinion of this seller",
    "he sent a pineapple pic",
    "hotpot restaurant booking deposit",
])
def test_pin_otp_branch_ignores_substrings(msg):
    assert not _PIN_OTP_RX.search(msg.lower())


@pytest.mark.parametrize("msg", [
    "they asked for my m-pesa pin",
    "send the otp now",
    "enter your password here",
    "nipe nywila yako",
    "someone said safaricom called me",
])
def test_pin_otp_branch_still_fires_on_real_requests(msg):
    assert _PIN_OTP_RX.search(msg.lower())


def test_request_id_sanitization():
    from cryptography.fernet import Fernet
    from starlette.testclient import TestClient
    from app.main import create_app

    key = Fernet.generate_key().decode()
    app = create_app(Settings(env="dev", encryption_key=key, hmac_key="secret-hmac"))
    client = TestClient(app)

    # Valid ID accepted
    res1 = client.get("/v1/health", headers={"x-request-id": "valid-id_123"})
    assert res1.headers["x-request-id"] == "valid-id_123"

    # Malicious / invalid characters sanitized to fresh UUID
    res2 = client.get("/v1/health", headers={"x-request-id": "<script>alert(1)</script>"})
    assert res2.headers["x-request-id"] != "<script>alert(1)</script>"
    assert len(res2.headers["x-request-id"]) > 10


def test_docs_disabled_in_prod():
    from cryptography.fernet import Fernet
    from starlette.testclient import TestClient
    from app.main import create_app

    # Prod app disables docs
    key = Fernet.generate_key().decode()
    app = create_app(Settings(env="prod", encryption_key=key, hmac_key="secret-hmac"))
    client = TestClient(app)
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_scrypt_owasp_work_factor_and_backward_compatibility():
    from app.security import hash_password, verify_password

    h = hash_password("super-secret-pass")
    assert h.startswith("scrypt$131072$8$1$")
    assert verify_password("super-secret-pass", h) is True
    assert verify_password("wrong-pass", h) is False

    # Old 16384 hashes still verify cleanly
    import base64, hashlib, os
    old_salt = os.urandom(16)
    old_h = hashlib.scrypt(b"legacy-pass", salt=old_salt, n=16384, r=8, p=1, dklen=32)
    old_stored = "scrypt$16384$8$1$" + base64.b64encode(old_salt).decode() + "$" + base64.b64encode(old_h).decode()
    assert verify_password("legacy-pass", old_stored) is True


