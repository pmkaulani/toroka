from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class CollaborationMode(StrEnum):
    INTERNAL_ONLY = "internal_only"
    APPROVED_TYPOLOGY_EXCHANGE = "approved_typology_exchange"
    GOVERNED_INDICATOR_SHARING = "governed_indicator_sharing"
    PRIVACY_PRESERVING_MATCHING = "privacy_preserving_matching"


@dataclass(frozen=True)
class CollaborativeExchangeContract:
    """Formal governance contract specifying permitted inter-bank collaboration."""
    contract_id: str
    lead_installation_id: str
    participating_installations: tuple[str, ...]
    permitted_mode: CollaborationMode
    legal_framework_reference: str
    data_protection_officer_approval: str
    created_at: datetime
    expires_at: datetime
    active: bool = False

    def validate_permission(self, target_installation: str, mode: CollaborationMode) -> bool:
        if not self.active:
            return False
        if target_installation not in self.participating_installations:
            return False
        if mode != self.permitted_mode:
            return False
        if datetime.now(timezone.utc) > self.expires_at:
            return False
        return True


@dataclass(frozen=True)
class ApprovedTypologyPackage:
    """Zero-PII network pattern definition sharable under FATF collaborative guidance."""
    typology_id: str
    originating_installation_id: str
    pattern_type: str
    abstract_structure: dict[str, Any]
    detection_heuristics: dict[str, Any]
    alternative_explanations: tuple[str, ...]
    governance_notes: str
    created_at: datetime

    def __post_init__(self) -> None:
        # Zero-PII invariant: check abstract_structure for prohibited raw keys
        prohibited = {"account_number", "customer_name", "national_id", "email", "phone"}
        keys_str = str(self.abstract_structure).lower()
        for p in prohibited:
            if p in keys_str:
                raise ValueError(f"Prohibited identifier '{p}' found in typology package")


@dataclass(frozen=True)
class GovernedIndicatorPackage:
    """Vetted indicators with cryptographic commitment, participant limits, and expiration."""
    indicator_id: str
    contract_id: str
    indicator_type: str  # e.g. "mule_account_hash_psi", "malicious_device_hash_psi"
    commitment_hash: str
    created_at: datetime
    expires_at: datetime
    authorized_participants: tuple[str, ...]


class CollaborativeIntelligenceGateway:
    """Safeguarded gateway for future cross-institution intelligence sharing.

    CRITICAL SECURITY & PRIVACY INVARIANTS:
    1. Cross-bank operational graph sharing is DISABLED by default (INTERNAL_ONLY).
    2. Raw customer PII or plaintext accounts are strictly prohibited from crossing installation boundaries.
    3. Hashing alone does NOT constitute anonymization under GDPR / FATF data protection guidelines;
       private set intersection (PSI) or zero-knowledge commitments are mandatory.
    """

    def __init__(self, mode: CollaborationMode = CollaborationMode.INTERNAL_ONLY) -> None:
        self._mode = mode
        self._contracts: dict[str, CollaborativeExchangeContract] = {}

    @property
    def mode(self) -> CollaborationMode:
        return self._mode

    def is_sharing_permitted(self) -> bool:
        return self._mode != CollaborationMode.INTERNAL_ONLY

    def register_contract(self, contract: CollaborativeExchangeContract) -> None:
        self._contracts[contract.contract_id] = contract

    def export_typology_package(
        self,
        installation_id: str,
        pattern_type: str,
        heuristics: dict[str, Any],
        explanations: list[str],
    ) -> ApprovedTypologyPackage:
        """Export an abstract, zero-PII typology package for approved peer exchange."""
        tid = f"typ_{hashlib.sha256(f'{installation_id}:{pattern_type}'.encode()).hexdigest()[:16]}"
        return ApprovedTypologyPackage(
            typology_id=tid,
            originating_installation_id=installation_id,
            pattern_type=pattern_type,
            abstract_structure={"motif": pattern_type, "node_types": ["account", "entity"]},
            detection_heuristics=dict(heuristics),
            alternative_explanations=tuple(explanations),
            governance_notes="FATF compliant zero-PII collaborative pattern.",
            created_at=datetime.now(timezone.utc),
        )
