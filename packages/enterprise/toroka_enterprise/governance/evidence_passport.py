from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class TorokaEvidencePassport:
    passport_id: str
    finding_id: str
    case_id: str
    installation_id: str
    finding_type: str
    finding_status: str
    component_versions: dict[str, str]
    configuration_digest: str
    evidence_count: int
    source_systems: tuple[str, ...]
    detection_time: datetime
    earliest_event_time: datetime | None = None
    evidence_at_detection_count: int = 0
    delayed_evidence_count: int = 0
    contradictions_count: int = 0
    evidence_debt_level: str = "LOW"
    alternative_explanations: tuple[str, ...] = ()
    validation_result: str = "PASS"
    human_review_required: bool = True
    passport_digest: str = ""

    def __post_init__(self) -> None:
        if not self.passport_digest:
            payload = (
                f"{self.passport_id}:{self.finding_id}:{self.case_id}:{self.installation_id}:"
                f"{self.finding_type}:{self.configuration_digest}:{self.evidence_count}:"
                f"{json.dumps(self.component_versions, sort_keys=True)}"
            )
            digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            object.__setattr__(self, "passport_digest", digest)

    def verify_integrity(self) -> bool:
        payload = (
            f"{self.passport_id}:{self.finding_id}:{self.case_id}:{self.installation_id}:"
            f"{self.finding_type}:{self.configuration_digest}:{self.evidence_count}:"
            f"{json.dumps(self.component_versions, sort_keys=True)}"
        )
        expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        return self.passport_digest == expected
