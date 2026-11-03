from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any

@dataclass(frozen=True, slots=True)
class Indicator:
    indicator_type: str
    value: str
    confidence: float = 0.7
    labels: tuple[str, ...] = ()
    valid_until: str | None = None
    reference_url: str | None = None

@dataclass(frozen=True, slots=True)
class FetchResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes
    final_url: str

@dataclass(frozen=True, slots=True)
class FeedHealth:
    source_id: str
    state: str
    last_attempt: str | None
    last_success: str | None
    next_attempt: str | None
    consecutive_failures: int
    cached_indicators: int
    last_error_code: str | None
    circuit_open_until: str | None

@dataclass(frozen=True, slots=True)
class OperationalAlert:
    alert_id: str
    source_id: str
    alert_type: str
    severity: str
    message: str
    created_at: str
    status: str = "open"

@dataclass(frozen=True, slots=True)
class LanguageSignal:
    pattern_id: str
    category: str
    severity: str
    phrase: str
    language: str
    confidence: float
    excerpt: str

@dataclass(frozen=True, slots=True)
class LanguageAnalysis:
    language: str
    language_confidence: float
    signals: tuple[LanguageSignal, ...]
    categories: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "language": self.language,
            "language_confidence": self.language_confidence,
            "signals": [asdict(s) for s in self.signals],
            "categories": list(self.categories),
            "limitations": list(self.limitations),
            "verdict": None,
        }
