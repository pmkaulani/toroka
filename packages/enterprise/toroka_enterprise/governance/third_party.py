from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from .models import RiskTier


@dataclass(frozen=True)
class GovernedAIProvider:
    provider_id: str
    provider_name: str
    model_identifier: str
    model_version: str
    hosting_location: str
    data_retention_policy: str
    training_on_customer_data_permitted: bool
    risk_tier: RiskTier
    is_approved: bool = True
    evaluation_summary: dict[str, Any] = field(default_factory=dict)
    last_evaluated_at: datetime | None = None


def verify_provider_compliance(provider: GovernedAIProvider) -> tuple[bool, list[str]]:
    """Verifies that an AI model provider satisfies banking supervisory constraints."""
    violations: list[str] = []

    # 1. Training on bank data is strictly prohibited
    if provider.training_on_customer_data_permitted:
        violations.append("CRITICAL: Provider policy permits model training on customer data")

    # 2. Data retention policy
    if provider.data_retention_policy.lower() not in ("zero_retention", "stateless", "none"):
        violations.append(
            f"Policy warning: Data retention '{provider.data_retention_policy}' is not zero-retention"
        )

    # 3. Approval status
    if not provider.is_approved:
        violations.append("Provider is not in APPROVED state by bank vendor risk committee")

    is_compliant = len([v for v in violations if "CRITICAL" in v]) == 0
    return is_compliant, violations
