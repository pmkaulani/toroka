"""Keyed pseudonymisation applied at ingest. Staff, system accounts and external parties never enter the engine in clear."""
from __future__ import annotations

import hashlib
import hmac

# Separate namespaces prevent a customer ID from colliding with a bank
# account, beneficiary, vendor, device or other operational identity.
PREFIX = {
    "stf": "STF",
    "acc": "ACC",
    "cus": "CUS",
    "bank_account": "BAC",
    "beneficiary": "BEN",
    "vendor": "VEN",
    "device": "DEV",
    "service_account": "SVC",
    "branch": "BRN",
    "gl_account": "GLA",
}


class Pseudonymiser:
    def __init__(self, secret: bytes | str):
        raw = secret.encode() if isinstance(secret, str) else secret
        if len(raw) < 32:
            raise ValueError("pseudonymisation secret must be at least 32 bytes")
        self._secret = raw
        self.vault: dict[str, str] = {}   # pseudonym -> raw; handed to the case store, which encrypts it

    def ref(self, kind: str, raw: str | None) -> str | None:
        if raw is None or not str(raw).strip():
            return None
        if kind not in PREFIX:
            raise ValueError(f"unknown identifier kind: {kind}")
        value = str(raw).strip()
        # Keep 128 bits of the keyed digest; 48 bits is too short for large-scale correlation.
        digest = hmac.new(self._secret, f"toroka-ent:{kind}:{value}".encode(), hashlib.sha256).hexdigest()[:32]
        pseudo = f"{PREFIX[kind]}-{digest}"
        self.vault[pseudo] = value
        return pseudo
