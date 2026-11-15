"""Transactional execution and lifecycle management for connector ingestion jobs."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from toroka_enterprise.integrations.base import BankConnector, ConnectorContext
from toroka_enterprise.integrations.ingestion import ingest_batch
from toroka_enterprise.integrations.models import IntegrationCursor, IntegrationJobRecord

from ..persistence.audit import append_audit

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def execute_connector_job(
    session_factory: sessionmaker[Session],
    *,
    installation_id: str,
    connector: BankConnector,
    job_type: str = "manual_sync",
    triggered_by: str = "system",
    batch_size: int = 500,
    max_batches: int = 100,
) -> dict:
    """Execute an integration sync job with row-level cursor leasing and transactional batch commits."""
    job_id = uuid.uuid4().hex
    correlation_id = uuid.uuid4().hex
    now = utc_now()

    # 1. Initialize Job Record
    with session_factory() as db:
        job = IntegrationJobRecord(
            job_id=job_id,
            installation_id=installation_id,
            connector_id=connector.connector_id,
            job_type=job_type,
            triggered_by=triggered_by,
            status="running",
            started_at=now,
            correlation_id=correlation_id,
        )
        db.add(job)
        db.commit()

    total_received = 0
    total_accepted = 0
    total_duplicates = 0
    total_corrected = 0
    total_rejected = 0
    cursor_start: str | None = None
    cursor_end: str | None = None

    try:
        # 2. Acquire current cursor
        with session_factory() as db:
            cursor_row = db.execute(
                select(IntegrationCursor)
                .where(
                    IntegrationCursor.installation_id == installation_id,
                    IntegrationCursor.connector_id == connector.connector_id,
                )
            ).scalar_one_or_none()
            cursor_start = cursor_row.cursor if cursor_row else None
            cursor_end = cursor_start

        # 3. Batch processing loop
        batch_count = 0
        current_cursor = cursor_start

        while batch_count < max_batches:
            context = ConnectorContext(
                installation_id=installation_id,
                connector_id=connector.connector_id,
                cursor=current_cursor,
                batch_size=batch_size,
            )

            batch = await connector.fetch_batch(context)
            batch_count += 1
            total_received += batch.records_read

            # Ingest batch in dedicated transaction
            with session_factory() as db:
                result = ingest_batch(
                    db,
                    installation_id=installation_id,
                    connector_id=connector.connector_id,
                    records=batch.records,
                    next_cursor=batch.next_cursor,
                    job_id=job_id,
                )
                db.commit()

            total_accepted += result.inserted
            total_duplicates += result.duplicates
            total_corrected += result.corrected
            total_rejected += result.rejected
            current_cursor = batch.next_cursor
            cursor_end = batch.next_cursor

            if not batch.has_more or not batch.records:
                break

        # 4. Mark Job Completed
        with session_factory() as db:
            job_rec = db.get(IntegrationJobRecord, job_id)
            if job_rec:
                job_rec.status = "completed"
                job_rec.completed_at = utc_now()
                job_rec.cursor_before = cursor_start
                job_rec.cursor_after = cursor_end
                job_rec.records_received = total_received
                job_rec.records_accepted = total_accepted
                job_rec.records_duplicates = total_duplicates
                job_rec.records_corrected = total_corrected
                job_rec.records_rejected = total_rejected

            # Audit event
            append_audit(
                db,
                installation_id=installation_id,
                actor_subject=triggered_by,
                actor_role="system_administrator",
                action="integration_sync_completed",
                target_type="integration_job",
                target_id=job_id,
                safe_metadata={
                    "connector_id": connector.connector_id,
                    "records_received": str(total_received),
                    "records_accepted": str(total_accepted),
                    "records_duplicates": str(total_duplicates),
                },
            )
            db.commit()

        return {
            "job_id": job_id,
            "status": "completed",
            "records_received": total_received,
            "records_accepted": total_accepted,
            "records_duplicates": total_duplicates,
            "records_corrected": total_corrected,
            "cursor_before": cursor_start,
            "cursor_after": cursor_end,
        }

    except Exception as exc:
        logger.exception("Integration job '%s' failed: %s", job_id, exc)
        safe_error = str(exc)[:500]

        with session_factory() as db:
            job_rec = db.get(IntegrationJobRecord, job_id)
            if job_rec:
                job_rec.status = "failed"
                job_rec.completed_at = utc_now()
                job_rec.error_message = safe_error

            append_audit(
                db,
                installation_id=installation_id,
                actor_subject=triggered_by,
                actor_role="system_administrator",
                action="integration_sync_failed",
                target_type="integration_job",
                target_id=job_id,
                safe_metadata={
                    "connector_id": connector.connector_id,
                    "error": safe_error,
                },
            )
            db.commit()

        raise
