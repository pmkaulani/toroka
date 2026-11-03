from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable


def _parse(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def build_case_timeline(
    evidence: Iterable[dict],
    link_assertions: Iterable[dict] = (),
    report_counts: dict[str, int] | None = None,
) -> dict:
    """Create a chronologically ordered, source-attributed case activity timeline."""
    events: list[dict] = []
    for item in evidence:
        when = _parse(item.get("observed_at") or item.get("created_at"))
        if not when:
            continue
        events.append({
            "event_type": "evidence_observed",
            "occurred_at": when.isoformat(),
            "title": str(item.get("source") or "Evidence source")[:160],
            "summary": str(item.get("summary") or "Evidence item recorded")[:500],
            "category": item.get("category"),
            "polarity": item.get("polarity"),
            "evidence_id": item.get("evidence_id"),
            "source_url": item.get("source_url"),
            "limitations": item.get("limitations") or [],
        })
    for link in link_assertions:
        when = _parse(link.get("observed_at"))
        if not when:
            continue
        events.append({
            "event_type": "relationship_observed",
            "occurred_at": when.isoformat(),
            "title": str(link.get("source_label") or "Relationship source")[:160],
            "summary": f"{link.get('relationship', 'relationship')} between {link.get('left_type', 'entity')} and {link.get('right_type', 'identifier')}",
            "assertion_id": link.get("assertion_id"),
            "basis": link.get("basis"),
            "status": link.get("status"),
            "risk_propagation": "never_automatic",
            "limitations": link.get("limitations") or [],
        })
    events.sort(key=lambda x: x["occurred_at"], reverse=True)
    counts = report_counts or {}
    return {
        "events": events,
        "event_count": len(events),
        "community_report_counts": {
            "pending": int(counts.get("pending", 0)),
            "reviewed_unverified": int(counts.get("reviewed_unverified", 0)),
            "corroborated": int(counts.get("corroborated", 0)),
            "rejected": int(counts.get("rejected", 0)),
        },
        "report_interpretation": "Report counts are displayed by moderation status. Pending and reviewed-unverified reports are not confirmed facts and must not be scored as verified fraud evidence.",
    }
