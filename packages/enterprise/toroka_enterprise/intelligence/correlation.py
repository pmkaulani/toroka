from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from .events import IntelligenceEvent


@dataclass(frozen=True)
class CorrelationWindow:
    start: datetime
    end: datetime

    def contains(self, event_time: datetime) -> bool:
        return self.start <= event_time <= self.end

    def to_dict(self) -> dict[str, str]:
        return {
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
        }


def build_window(
    event_time: datetime,
    *,
    before_minutes: int = 30,
    after_minutes: int = 30,
) -> CorrelationWindow:
    if before_minutes < 0 or after_minutes < 0:
        raise ValueError("window values cannot be negative")

    return CorrelationWindow(
        start=event_time - timedelta(minutes=before_minutes),
        end=event_time + timedelta(minutes=after_minutes),
    )


def events_in_window(
    events: list[IntelligenceEvent],
    window: CorrelationWindow,
    installation_id: str | None = None,
) -> list[IntelligenceEvent]:
    """Filter and sort events within a temporal correlation window.
    
    If installation_id is specified, strictly filters to that installation.
    """
    filtered = (
        event
        for event in events
        if window.contains(event.event_time)
        and (installation_id is None or event.installation_id == installation_id)
    )
    return sorted(filtered, key=lambda event: (event.event_time, event.event_id))
