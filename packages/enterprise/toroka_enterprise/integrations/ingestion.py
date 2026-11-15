"""Idempotent batch ingestion service with versioned conflict and correction handling."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from sqlalchemy import select, and_
from sqlalchemy.orm import Session

from .contracts import CanonicalRecord
from .models import (
    IntegrationCursor,
    IntegrationRecord,
    IntegrationRejectedRecord,
    utc_now,
)


@dataclass(frozen=True, slots=True)
class IngestionResult:
    inserted: int
    duplicates: int
    corrected: int
    rejected: int
    next_cursor: str | None


def canonical_digest(record: CanonicalRecord) -> str:
    """Compute deterministic SHA-256 digest of record payload."""
    payload = record.model_dump(mode="json")
    if "provenance" in payload and "payload_digest" in payload["provenance"]:
        payload["provenance"]["payload_digest"] = ""
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def ingest_batch(
    db: Session,
    *,
    installation_id: str,
    connector_id: str,
    records: list[CanonicalRecord],
    next_cursor: str | None = None,
    job_id: str | None = None,
) -> IngestionResult:
    """Ingest a batch of canonical records idempotently within the caller's transaction.
    
    Guarantees:
    1. Identical payloads with same (installation, connector, record_id) are recognized as duplicates.
    2. Modified payloads with same record_id are stored as versioned corrections, not silently overwritten.
    3. Cursors are updated atomically alongside records.
    """
    inserted = 0
    duplicates = 0
    corrected = 0
    rejected = 0

    now = utc_now()

    for record in records:
        digest = canonical_digest(record)

        # Query existing record versions for this source ID
        stmt = (
            select(IntegrationRecord)
            .where(
                and_(
                    IntegrationRecord.installation_id == installation_id,
                    IntegrationRecord.connector_id == connector_id,
                    IntegrationRecord.record_id == record.record_id,
                )
            )
            .order_by(IntegrationRecord.version.desc())
        )
        existing = db.execute(stmt).scalars().first()

        if existing is None:
            # First time seeing this record
            rec = IntegrationRecord(
                installation_id=installation_id,
                connector_id=connector_id,
                record_id=record.record_id,
                record_type=record.record_type.value,
                source_system=record.provenance.source_system.value,
                digest=digest,
                payload=record.model_dump(mode="json"),
                status="ingested",
                version=1,
                source_event_timestamp=record.provenance.source_event_timestamp,
                ingested_at=now,
            )
            db.add(rec)
            inserted += 1
        elif existing.digest == digest:
            # Replay of identical content -> idempotent duplicate
            duplicates += 1
        else:
            # Same record_id with differing content -> versioned correction
            new_version = existing.version + 1
            correction_rec = IntegrationRecord(
                installation_id=installation_id,
                connector_id=connector_id,
                record_id=record.record_id,
                record_type=record.record_type.value,
                source_system=record.provenance.source_system.value,
                digest=digest,
                payload=record.model_dump(mode="json"),
                status="corrected",
                version=new_version,
                source_event_timestamp=record.provenance.source_event_timestamp,
                ingested_at=now,
                updated_at=now,
            )
            db.add(correction_rec)
            corrected += 1

    # Update or insert cursor checkpoint
    cursor_stmt = select(IntegrationCursor).where(
        and_(
            IntegrationCursor.installation_id == installation_id,
            IntegrationCursor.connector_id == connector_id,
        )
    ).with_for_update()
    cursor_row = db.execute(cursor_stmt).scalar_one_or_none()

    if cursor_row is None:
        cursor_row = IntegrationCursor(
            installation_id=installation_id,
            connector_id=connector_id,
            cursor=next_cursor,
            last_success_at=now,
            records_ingested_total=inserted,
            records_duplicates_total=duplicates,
            records_corrected_total=corrected,
            updated_at=now,
        )
        db.add(cursor_row)
    else:
        if next_cursor is not None:
            cursor_row.cursor = next_cursor
        cursor_row.last_success_at = now
        cursor_row.records_ingested_total += inserted
        cursor_row.records_duplicates_total += duplicates
        cursor_row.records_corrected_total += corrected
        cursor_row.updated_at = now

    db.flush()

    return IngestionResult(
        inserted=inserted,
        duplicates=duplicates,
        corrected=corrected,
        rejected=rejected,
        next_cursor=next_cursor,
    )


def record_rejection(
    db: Session,
    *,
    installation_id: str,
    connector_id: str,
    job_id: str | None = None,
    source_record_id: str | None = None,
    reason_code: str,
    reason_message: str,
    raw_payload: dict | None = None,
) -> IntegrationRejectedRecord:
    """Record a rejected record in the dead-letter / rejection audit table."""
    rej = IntegrationRejectedRecord(
        installation_id=installation_id,
        connector_id=connector_id,
        job_id=job_id,
        source_record_id=source_record_id,
        reason_code=reason_code,
        reason_message=reason_message,
        raw_payload=raw_payload,
        rejected_at=utc_now(),
    )
    db.add(rej)
    db.flush()
    return rej
