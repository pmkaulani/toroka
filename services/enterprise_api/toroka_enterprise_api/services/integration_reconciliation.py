"""Reconciliation engine comparing source and ingested bank records."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from sqlalchemy import select, func, and_
from sqlalchemy.orm import Session

from toroka_enterprise.integrations.models import (
    IntegrationCursor,
    IntegrationRecord,
    IntegrationRejectedRecord,
)


@dataclass(frozen=True, slots=True)
class ReconciliationReport:
    installation_id: str
    connector_id: str
    window_start: datetime | None
    window_end: datetime | None
    expected_source_count: int | None
    ingested_record_count: int
    corrected_record_count: int
    rejected_record_count: int
    discrepancy: int
    status: str  # "reconciled", "discrepancy_detected", "unverified_source"
    explanation: str


def generate_reconciliation_report(
    db: Session,
    *,
    installation_id: str,
    connector_id: str,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    expected_source_count: int | None = None,
) -> ReconciliationReport:
    """Compare ingested database records against expected source record metrics."""
    conditions = [
        IntegrationRecord.installation_id == installation_id,
        IntegrationRecord.connector_id == connector_id,
    ]
    if window_start:
        conditions.append(IntegrationRecord.source_event_timestamp >= window_start)
    if window_end:
        conditions.append(IntegrationRecord.source_event_timestamp <= window_end)

    # Ingested count (unique source record_id versions)
    stmt = select(func.count(IntegrationRecord.id)).where(and_(*conditions))
    ingested_count = db.execute(stmt).scalar() or 0

    # Corrected count
    corrected_stmt = select(func.count(IntegrationRecord.id)).where(
        and_(*conditions, IntegrationRecord.status == "corrected")
    )
    corrected_count = db.execute(corrected_stmt).scalar() or 0

    # Rejected count
    rej_conditions = [
        IntegrationRejectedRecord.installation_id == installation_id,
        IntegrationRejectedRecord.connector_id == connector_id,
    ]
    if window_start:
        rej_conditions.append(IntegrationRejectedRecord.rejected_at >= window_start)
    if window_end:
        rej_conditions.append(IntegrationRejectedRecord.rejected_at <= window_end)

    rej_stmt = select(func.count(IntegrationRejectedRecord.id)).where(and_(*rej_conditions))
    rejected_count = db.execute(rej_stmt).scalar() or 0

    if expected_source_count is None:
        status = "unverified_source"
        discrepancy = 0
        explanation = (
            f"Ingested {ingested_count} records ({corrected_count} corrections, "
            f"{rejected_count} rejections). Source total was not provided by bank interface."
        )
    else:
        discrepancy = expected_source_count - (ingested_count + rejected_count)
        if discrepancy == 0:
            status = "reconciled"
            explanation = f"Exact match: {expected_source_count} expected vs {ingested_count} ingested + {rejected_count} rejected."
        else:
            status = "discrepancy_detected"
            explanation = (
                f"Discrepancy of {discrepancy} records detected: "
                f"{expected_source_count} expected from source vs "
                f"{ingested_count} ingested and {rejected_count} rejected."
            )

    return ReconciliationReport(
        installation_id=installation_id,
        connector_id=connector_id,
        window_start=window_start,
        window_end=window_end,
        expected_source_count=expected_source_count,
        ingested_record_count=ingested_count,
        corrected_record_count=corrected_count,
        rejected_record_count=rejected_count,
        discrepancy=discrepancy,
        status=status,
        explanation=explanation,
    )
