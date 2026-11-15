from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class EntityType(StrEnum):
    EMPLOYEE = "employee"
    CUSTOMER = "customer"
    ACCOUNT = "account"
    TRANSACTION = "transaction"
    DEVICE = "device"
    SESSION = "session"
    IP_ADDRESS = "ip_address"
    BRANCH = "branch"
    ROLE = "role"
    CASE = "case"


@dataclass(frozen=True)
class EntityRef:
    installation_id: str
    entity_type: EntityType
    entity_id: str
    display_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "installation_id": self.installation_id,
            "entity_type": self.entity_type.value,
            "entity_id": self.entity_id,
            "display_id": self.display_id,
        }


@dataclass(frozen=True)
class Relationship:
    installation_id: str
    source: EntityRef
    target: EntityRef
    relationship_type: str

    first_seen: datetime | None = None
    last_seen: datetime | None = None

    confidence: float = 1.0

    source_system: str | None = None
    source_record_id: str | None = None

    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")

        if self.source.installation_id != self.installation_id:
            raise ValueError("source installation mismatch")

        if self.target.installation_id != self.installation_id:
            raise ValueError("target installation mismatch")

    def to_dict(self) -> dict[str, Any]:
        return {
            "installation_id": self.installation_id,
            "source": self.source.to_dict(),
            "target": self.target.to_dict(),
            "relationship_type": self.relationship_type,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "confidence": self.confidence,
            "source_system": self.source_system,
            "source_record_id": self.source_record_id,
            "attributes": dict(self.attributes),
        }
