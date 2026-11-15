"""Tests for temporal correlation windows and event filtering."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest

from toroka_enterprise.intelligence.correlation import (
    CorrelationWindow,
    build_window,
    events_in_window,
)
from toroka_enterprise.intelligence.events import IntelligenceEvent


def test_build_window_and_contains():
    t0 = datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc)
    w = build_window(t0, before_minutes=15, after_minutes=30)

    assert w.start == t0 - timedelta(minutes=15)
    assert w.end == t0 + timedelta(minutes=30)

    assert w.contains(t0) is True
    assert w.contains(t0 - timedelta(minutes=15)) is True
    assert w.contains(t0 + timedelta(minutes=30)) is True
    assert w.contains(t0 - timedelta(minutes=16)) is False
    assert w.contains(t0 + timedelta(minutes=31)) is False

    with pytest.raises(ValueError, match="window values cannot be negative"):
        build_window(t0, before_minutes=-5)


def test_events_in_window_ordering_and_isolation():
    t0 = datetime(2026, 11, 16, 14, 0, 0, tzinfo=timezone.utc)
    w = build_window(t0, before_minutes=60, after_minutes=60)

    e1 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-01",
        event_type="customer_record_access",
        event_time=t0 - timedelta(minutes=20),
        actor="emp_01",
    )
    e2 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-02",
        event_type="beneficiary_change",
        event_time=t0 + timedelta(minutes=10),
        actor="emp_01",
    )
    e3_outside = IntelligenceEvent(
        installation_id="inst-1",
        event_id="evt-03",
        event_type="login",
        event_time=t0 + timedelta(minutes=75),
    )
    e4_other_inst = IntelligenceEvent(
        installation_id="inst-2",
        event_id="evt-04",
        event_type="customer_record_access",
        event_time=t0 - timedelta(minutes=10),
    )

    # Arriving out of order: e2, e3_outside, e1, e4_other_inst
    raw_list = [e2, e3_outside, e1, e4_other_inst]

    result = events_in_window(raw_list, w, installation_id="inst-1")
    assert len(result) == 2
    assert result[0].event_id == "evt-01"
    assert result[1].event_id == "evt-02"
