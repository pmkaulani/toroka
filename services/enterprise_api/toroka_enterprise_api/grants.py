"""Cryptographically signed approval grant tokens for identity reveal operations."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


DEFAULT_DEV_GRANT_KEY = b"toroka-dev-approval-signing-key-32b-min!"


def get_grant_signing_key(configured_key: str | bytes | None = None) -> bytes:
    if configured_key:
        key_bytes = configured_key.encode("utf-8") if isinstance(configured_key, str) else configured_key
        if len(key_bytes) >= 32:
            return key_bytes
    env_key = os.environ.get("TOROKA_VAULT_APPROVAL_KEY", "") or os.environ.get("TOROKA_ENT_VAULT_SERVICE_TOKEN", "")
    if env_key and len(env_key.encode("utf-8")) >= 32:
        return env_key.encode("utf-8")
    return DEFAULT_DEV_GRANT_KEY


def create_signed_reveal_grant(
    *,
    grant_id: str,
    installation_id: str,
    case_id: str,
    requester_subject: str,
    approver_subject: str,
    pseudonym: str,
    expires_at: datetime,
    signing_key: bytes | None = None,
) -> str:
    key = signing_key or get_grant_signing_key()
    payload = {
        "grant_id": str(grant_id),
        "installation_id": str(installation_id),
        "case_id": str(case_id),
        "requester_subject": str(requester_subject),
        "approver_subject": str(approver_subject),
        "pseudonym": str(pseudonym),
        "expires_at": _ensure_utc(expires_at).isoformat(),
        "nonce": uuid.uuid4().hex,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    raw_b64 = base64.urlsafe_b64encode(canonical).decode("ascii").rstrip("=")
    return f"teg1.{raw_b64}.{sig}"


def verify_signed_reveal_grant(
    token: str,
    *,
    expected_installation_id: str,
    expected_requester_subject: str,
    expected_pseudonym: str,
    expected_grant_id: str | None = None,
    expected_case_id: str | None = None,
    signing_key: bytes | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    key = signing_key or get_grant_signing_key()
    if not token or not token.startswith("teg1."):
        raise ValueError("Invalid reveal grant token format")

    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed reveal grant token structure")

    _, raw_b64, supplied_sig = parts
    padded = raw_b64 + "=" * (-len(raw_b64) % 4)
    try:
        canonical = base64.urlsafe_b64decode(padded.encode("ascii"))
        payload = json.loads(canonical.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"Failed to decode reveal grant token: {exc}") from exc

    expected_sig = hmac.new(key, canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, supplied_sig):
        raise ValueError("Reveal grant signature verification failed")

    # Scope and expiry checks
    if payload.get("installation_id") != expected_installation_id:
        raise ValueError(
            f"Reveal grant installation scope mismatch: expected '{expected_installation_id}', got '{payload.get('installation_id')}'"
        )

    if payload.get("requester_subject") != expected_requester_subject:
        raise ValueError(
            f"Reveal grant requester scope mismatch: expected '{expected_requester_subject}', got '{payload.get('requester_subject')}'"
        )

    if payload.get("pseudonym") != expected_pseudonym:
        raise ValueError(
            f"Reveal grant pseudonym scope mismatch: expected '{expected_pseudonym}', got '{payload.get('pseudonym')}'"
        )

    if expected_grant_id and payload.get("grant_id") != expected_grant_id:
        raise ValueError(
            f"Reveal grant ID mismatch: expected '{expected_grant_id}', got '{payload.get('grant_id')}'"
        )

    if expected_case_id and payload.get("case_id") != expected_case_id:
        raise ValueError(
            f"Reveal grant case scope mismatch: expected '{expected_case_id}', got '{payload.get('case_id')}'"
        )

    # Separation of duty
    if payload.get("requester_subject") == payload.get("approver_subject"):
        raise ValueError("Reveal grant violates dual approval: requester cannot be approver")

    # Expiration check
    current_time = _ensure_utc(now or utc_now())
    exp_str = payload.get("expires_at")
    if not exp_str:
        raise ValueError("Reveal grant missing expiration timestamp")
    exp_dt = datetime.fromisoformat(exp_str)
    if _ensure_utc(exp_dt) <= current_time:
        raise ValueError("Reveal grant has expired")

    return payload
