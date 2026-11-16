from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class GovernanceStatus(StrEnum):
    DRAFT = "draft"
    VALIDATION = "validation"
    APPROVED = "approved"
    STAGED = "staged"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    RETIRED = "retired"


class ComponentType(StrEnum):
    RULE = "rule"
    DETECTOR = "detector"
    STATISTICAL_MODEL = "statistical_model"
    ML_MODEL = "ml_model"
    LLM = "llm"
    PROMPT = "prompt"
    POLICY = "policy"
    SIMULATION = "simulation"


class RiskTier(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class GovernedComponent:
    component_id: str
    version: str
    component_type: ComponentType
    name: str
    status: GovernanceStatus
    risk_tier: RiskTier
    owner_team: str
    source_digest: str
    configuration_digest: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = ""
    approved_at: datetime | None = None
    approved_by: str | None = None
    suspended_at: datetime | None = None
    suspended_by: str | None = None
    retired_at: datetime | None = None
    retired_by: str | None = None
    description: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.component_id.strip():
            raise ValueError("component_id is required")
        if not self.version.strip():
            raise ValueError("version is required")
        if self.status == GovernanceStatus.APPROVED:
            if not self.approved_at or not self.approved_by:
                raise ValueError("Approved components require approval metadata")
        if self.status == GovernanceStatus.ACTIVE:
            if not self.approved_at or not self.approved_by:
                raise ValueError("Active components must have approval metadata")
