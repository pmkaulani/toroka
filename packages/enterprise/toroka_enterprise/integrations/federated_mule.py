"""Phase 14.2: Federated Mule Directory & Hash-Linked Interbank Blacklist Engine.

Aligns with:
- People's Bank of China (PBOC) Anti-Telecom Fraud Law (2022) Article 21 (Cross-Bank Account Restrictions)
- Swiss SMPC / SIX Interbank Fraud Collaboration Standards
- US Early Warning Services (EWS) / Zelle Consortia Blinded Query Architecture
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


def is_federation_enabled() -> bool:
    """Returns True only if federation is explicitly enabled via environment."""
    return os.environ.get("TOROKA_ENABLE_FEDERATION", "false").lower() in ("true", "1", "yes")


def get_federation_salt() -> str:
    """Retrieve consortium federation salt or fail closed in production.
    
    In production, a configured non-default salt or KMS-backed key is mandatory.
    Default federation salt fallback is strictly prohibited.
    """
    salt = os.environ.get("TOROKA_FEDERATED_MULE_SALT")
    is_prod = (
        os.environ.get("TOROKA_ENV", "").lower() == "production"
        or os.environ.get("ENVIRONMENT", "").lower() == "production"
        or os.environ.get("TOROKA_ENT_ENV", "").lower() == "production"
    )
    if not salt:
        if is_prod:
            raise RuntimeError(
                "Production federation requires explicit TOROKA_FEDERATED_MULE_SALT or KMS-backed key. "
                "Default federation salt fallback is strictly prohibited in production."
            )
        return "TOROKA_CONSORTIUM_MULE_SALT_KENYA_CBK_2026_DEV"
    if is_prod and salt == "TOROKA_CONSORTIUM_MULE_SALT_KENYA_CBK_2026_V1":
        raise RuntimeError(
            "Production cannot use the default or sample consortium salt. "
            "A distinct, KMS-backed consortium key is required."
        )
    return salt





class MuleEntityType(StrEnum):
    BANK_ACCOUNT = "BANK_ACCOUNT"
    MSISDN = "MSISDN"
    NATIONAL_ID = "NATIONAL_ID"
    PAYBILL_TILL = "PAYBILL_TILL"


class MuleSeverityTier(StrEnum):
    SUSPECT_MULE = "SUSPECT_MULE"
    CORROBORATED_MULE = "CORROBORATED_MULE"
    CONFIRMED_SYNDICATE_CONTROLLER = "CONFIRMED_SYNDICATE_CONTROLLER"


class MuleEntryStatus(StrEnum):
    ACTIVE = "ACTIVE"
    CONTESTED = "CONTESTED"
    EXPUNGED = "EXPUNGED"


@dataclass(frozen=True)
class FederatedMuleQuery:
    """Query to check an identifier against the cross-bank federated directory."""
    value: str
    entity_type: MuleEntityType = MuleEntityType.BANK_ACCOUNT
    querying_bank_bic: str = ""
    is_already_blinded: bool = False
    query_id: str = field(default_factory=lambda: f"mule-qry-{uuid.uuid4().hex[:12]}")
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "query_id": self.query_id,
            "entity_type": self.entity_type.value,
            "querying_bank_bic": self.querying_bank_bic,
            "is_already_blinded": self.is_already_blinded,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class FederatedMuleMatch:
    """Outcome of querying the federated mule directory."""
    is_match: bool
    blinded_token: str
    cleartext_preview: str
    entity_type: MuleEntityType
    severity_tier: MuleSeverityTier | None = None
    originating_bank_bic: str | None = None
    reason_code: str | None = None
    dossier_reference: str | None = None
    status: MuleEntryStatus = MuleEntryStatus.ACTIVE
    registered_at: datetime | None = None
    expires_at: datetime | None = None
    recommended_action: str = "NO_MULE_RECORD: Counterparty is not listed in the federated directory"

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_match": self.is_match,
            "blinded_token": self.blinded_token,
            "cleartext_preview": self.cleartext_preview,
            "entity_type": self.entity_type.value,
            "severity_tier": self.severity_tier.value if self.severity_tier else None,
            "originating_bank_bic": self.originating_bank_bic,
            "reason_code": self.reason_code,
            "dossier_reference": self.dossier_reference,
            "status": self.status.value,
            "registered_at": self.registered_at.isoformat() if self.registered_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "recommended_action": self.recommended_action,
        }


class FederatedMuleEngine:
    """Cryptographic blinded token generation and federated cross-bank directory matcher."""

    @classmethod
    def normalize_identifier(cls, raw: str, entity_type: MuleEntityType | str) -> str:
        """Normalizes identifiers into standard canonical format prior to hashing."""
        e_type = MuleEntityType(entity_type) if isinstance(entity_type, str) else entity_type
        cleaned = raw.strip().upper()

        if e_type == MuleEntityType.BANK_ACCOUNT:
            # Strip whitespace, hyphens, and leading zeros if common formatting
            return re.sub(r"[\s\-_]", "", cleaned)

        elif e_type == MuleEntityType.MSISDN:
            digits_only = re.sub(r"[^\d+]", "", cleaned)
            if digits_only.startswith("+"):
                return digits_only
            if digits_only.startswith("0") and len(digits_only) == 10:
                return "+254" + digits_only[1:]
            if digits_only.startswith("254") and len(digits_only) == 12:
                return "+" + digits_only
            if not digits_only.startswith("+"):
                return "+" + digits_only
            return digits_only

        elif e_type == MuleEntityType.NATIONAL_ID:
            return re.sub(r"[\s\-_]", "", cleaned)

        elif e_type == MuleEntityType.PAYBILL_TILL:
            return re.sub(r"[\s\-_]", "", cleaned)

        return cleaned

    @classmethod
    def compute_blinded_token(
        cls,
        raw: str,
        entity_type: MuleEntityType | str,
        salt: str | None = None,
    ) -> str:
        """Computes keyed HMAC-SHA256 blinded token over normalized identifier."""
        canonical = cls.normalize_identifier(raw, entity_type)
        salt_val = salt if salt is not None else get_federation_salt()
        actual_salt = salt_val.encode("utf-8")
        token = hmac.new(actual_salt, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        return token

    @classmethod
    def mask_identifier(cls, raw: str, entity_type: MuleEntityType | str) -> str:
        """Generates a privacy-safe preview mask (e.g. 0110****988)."""
        e_type = MuleEntityType(entity_type) if isinstance(entity_type, str) else entity_type
        norm = cls.normalize_identifier(raw, e_type)
        if len(norm) <= 4:
            return "****"
        if len(norm) <= 8:
            return f"{norm[:2]}****{norm[-2:]}"
        return f"{norm[:4]}****{norm[-3:]}"

    @classmethod
    def evaluate_mule_query(
        cls,
        query: FederatedMuleQuery,
        active_directory_entries: list[dict[str, Any]],
        salt: str | None = None,
    ) -> FederatedMuleMatch:
        """Evaluates whether an identifier exists in the federated directory."""
        if query.is_already_blinded:
            blinded_token = query.value.strip().lower()
            preview = "BLINDED_TOKEN"
        else:
            blinded_token = cls.compute_blinded_token(query.value, query.entity_type, salt=salt)
            preview = cls.mask_identifier(query.value, query.entity_type)

        now = datetime.now(timezone.utc)

        # Look up matching active entry by blinded token
        for entry in active_directory_entries:
            e_token = entry.get("blinded_token", "").strip().lower()
            e_status = entry.get("status", "ACTIVE")
            if e_token == blinded_token:
                if e_status == MuleEntryStatus.EXPUNGED.value:
                    continue  # Expunged entries are inactive

                # Check expiry if present
                expires_at = entry.get("expires_at")
                if expires_at:
                    if isinstance(expires_at, str):
                        try:
                            exp_dt = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                        except ValueError:
                            exp_dt = None
                    else:
                        exp_dt = expires_at

                    if exp_dt:
                        if exp_dt.tzinfo is None:
                            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                        if exp_dt < now:
                            continue  # Expired entry

                tier_val = entry.get("severity_tier", MuleSeverityTier.CORROBORATED_MULE.value)
                tier = MuleSeverityTier(tier_val)

                if tier == MuleSeverityTier.CONFIRMED_SYNDICATE_CONTROLLER:
                    action = (
                        "RECOMMEND_BLOCK: Counterparty is a confirmed cross-bank fraud syndicate controller. "
                        "Enforce immediate outbound hold and notify National FIU/DCI."
                    )
                elif tier == MuleSeverityTier.CORROBORATED_MULE:
                    action = (
                        "RECOMMEND_BLOCK: Counterparty is a corroborated mule account registered across the interbank network. "
                        "Initiate inflow-only restriction to capture victim funds."
                    )
                else:
                    action = (
                        "RECOMMEND_DELAY_SETTLEMENT_15M: Counterparty exhibits multi-bank mule velocity indicators. "
                        "Enforce 15-minute escrow delay and step-up identity challenge."
                    )

                reg_at = entry.get("registered_at")
                reg_dt = None
                if reg_at:
                    reg_dt = reg_at if isinstance(reg_at, datetime) else datetime.fromisoformat(str(reg_at).replace("Z", "+00:00"))

                return FederatedMuleMatch(
                    is_match=True,
                    blinded_token=blinded_token,
                    cleartext_preview=entry.get("cleartext_preview") or preview,
                    entity_type=MuleEntityType(entry.get("entity_type", query.entity_type.value)),
                    severity_tier=tier,
                    originating_bank_bic=entry.get("originating_bank_bic"),
                    reason_code=entry.get("reason_code"),
                    dossier_reference=entry.get("dossier_reference"),
                    status=MuleEntryStatus(e_status),
                    registered_at=reg_dt,
                    expires_at=exp_dt if "exp_dt" in locals() else None,
                    recommended_action=action,
                )

        # No match found
        return FederatedMuleMatch(
            is_match=False,
            blinded_token=blinded_token,
            cleartext_preview=preview,
            entity_type=query.entity_type,
            severity_tier=None,
            originating_bank_bic=None,
            reason_code=None,
            dossier_reference=None,
            status=MuleEntryStatus.ACTIVE,
            recommended_action="NO_MULE_RECORD: Counterparty is not listed in the federated directory",
        )
