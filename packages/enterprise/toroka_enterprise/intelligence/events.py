from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class IntelligenceEvent:
    installation_id: str

    event_id: str
    event_type: str

    event_time: datetime

    actor: str | None = None
    subject: str | None = None

    source_system: str | None = None
    source_record_id: str | None = None

    entities: tuple[str, ...] = ()

    attributes: dict[str, Any] = field(default_factory=dict)

    provenance_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "installation_id": self.installation_id,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "event_time": self.event_time.isoformat(),
            "actor": self.actor,
            "subject": self.subject,
            "source_system": self.source_system,
            "source_record_id": self.source_record_id,
            "entities": list(self.entities),
            "attributes": dict(self.attributes),
            "provenance_digest": self.provenance_digest,
        }
