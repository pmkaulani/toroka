"""API router for bank connector management, ingestion jobs, quality, and reconciliation."""
from __future__ import annotations

from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from toroka_enterprise.integrations.models import (
    IntegrationCursor,
    IntegrationJobRecord,
    IntegrationRecord,
    IntegrationRejectedRecord,
)
from toroka_enterprise.integrations.quality import (
    assess_canonical_batch,
    assess_detector_readiness_from_integration,
)
from toroka_enterprise.integrations.registry import DEFAULT_CONNECTOR_REGISTRY

from ..auth import EnterprisePrincipal, get_current_principal, require_roles
from ..dependencies import get_db, get_installation_id
from ..permissions import (
    BANK_ROLES,
    ROLE_AUDITOR,
    ROLE_DATA_STEWARD,
    ROLE_SYSTEM_ADMINISTRATOR,
)
from ..integration_schemas import (
    ConnectorResponse,
    ConnectorSyncRequest,
    ConnectorSyncResponse,
    IntegrationJobResponse,
    IntegrationRejectedResponse,
    QualityAssessmentResponse,
    ReconciliationRequest,
    ReconciliationResponse,
)
from ..services.integration_jobs import execute_connector_job
from ..services.integration_reconciliation import generate_reconciliation_report

router = APIRouter(
    prefix="/api/enterprise/v1/integrations",
    tags=["Enterprise Bank Integrations"],
)


@router.get(
    "/connectors",
    response_model=list[ConnectorResponse],
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
def list_connectors(
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """List all registered bank connectors for the installation."""
    registered = DEFAULT_CONNECTOR_REGISTRY.list_connectors(installation_id)
    results: list[ConnectorResponse] = []

    for info in registered:
        conn = info.connector
        cursor_row = db.get(IntegrationCursor, (installation_id, conn.connector_id))
        results.append(
            ConnectorResponse(
                connector_id=conn.connector_id,
                connector_type=conn.connector_type,
                source_system=conn.source_system.value,
                version=conn.version,
                enabled=info.enabled,
                registered_at=info.registered_at,
                metadata=conn.metadata,
                capabilities=conn.capabilities,
                cursor=cursor_row.cursor if cursor_row else None,
                records_ingested=cursor_row.records_ingested_total if cursor_row else 0,
            )
        )
    return results


@router.get(
    "/connectors/{connector_id}",
    response_model=ConnectorResponse,
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
def get_connector_detail(
    connector_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """Retrieve detailed metadata and current status for a specific connector."""
    info = DEFAULT_CONNECTOR_REGISTRY.get_info(installation_id, connector_id)
    if info is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Connector '{connector_id}' not found")

    conn = info.connector
    cursor_row = db.get(IntegrationCursor, (installation_id, conn.connector_id))
    return ConnectorResponse(
        connector_id=conn.connector_id,
        connector_type=conn.connector_type,
        source_system=conn.source_system.value,
        version=conn.version,
        enabled=info.enabled,
        registered_at=info.registered_at,
        metadata=conn.metadata,
        capabilities=conn.capabilities,
        cursor=cursor_row.cursor if cursor_row else None,
        records_ingested=cursor_row.records_ingested_total if cursor_row else 0,
    )


@router.get(
    "/connectors/{connector_id}/health",
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
async def check_connector_health(
    connector_id: str,
    installation_id: str = Depends(get_installation_id),
):
    """Probe the upstream bank system to verify connectivity and credentials."""
    conn = DEFAULT_CONNECTOR_REGISTRY.get(installation_id, connector_id)
    if conn is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Connector '{connector_id}' not found")

    is_healthy = await conn.healthcheck()
    return {
        "connector_id": connector_id,
        "healthy": is_healthy,
        "status": "connected" if is_healthy else "unreachable",
    }


@router.post(
    "/connectors/{connector_id}/enable",
    dependencies=[Depends(require_roles(ROLE_SYSTEM_ADMINISTRATOR, ROLE_DATA_STEWARD))],
)
def enable_connector(
    connector_id: str,
    installation_id: str = Depends(get_installation_id),
):
    """Enable a connector for automated and manual ingestion."""
    success = DEFAULT_CONNECTOR_REGISTRY.set_enabled(installation_id, connector_id, True)
    if not success:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Connector '{connector_id}' not found")
    return {"connector_id": connector_id, "enabled": True}


@router.post(
    "/connectors/{connector_id}/disable",
    dependencies=[Depends(require_roles(ROLE_SYSTEM_ADMINISTRATOR, ROLE_DATA_STEWARD))],
)
def disable_connector(
    connector_id: str,
    installation_id: str = Depends(get_installation_id),
):
    """Disable a connector, pausing all scheduled ingestion jobs."""
    success = DEFAULT_CONNECTOR_REGISTRY.set_enabled(installation_id, connector_id, False)
    if not success:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Connector '{connector_id}' not found")
    return {"connector_id": connector_id, "enabled": False}


@router.post(
    "/connectors/{connector_id}/sync",
    response_model=ConnectorSyncResponse,
    dependencies=[Depends(require_roles(ROLE_SYSTEM_ADMINISTRATOR, ROLE_DATA_STEWARD))],
)
async def trigger_connector_sync(
    connector_id: str,
    req: ConnectorSyncRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """Execute a manual synchronization batch for an authorized connector."""
    info = DEFAULT_CONNECTOR_REGISTRY.get_info(installation_id, connector_id)
    if info is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"Connector '{connector_id}' not found")
    if not info.enabled:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"Connector '{connector_id}' is disabled")

    # Access the application session factory
    from fastapi import Request
    # We execute using the active session's sessionmaker or db.get_bind()
    from sqlalchemy.orm import sessionmaker
    bind = db.get_bind()
    factory = sessionmaker(bind=bind, expire_on_commit=False)

    try:
        job_summary = await execute_connector_job(
            factory,
            installation_id=installation_id,
            connector=info.connector,
            job_type="manual_sync",
            triggered_by=principal.subject,
            batch_size=req.batch_size,
            max_batches=req.max_batches,
        )
        return ConnectorSyncResponse(
            job_id=job_summary["job_id"],
            connector_id=connector_id,
            status=job_summary["status"],
            records_received=job_summary["records_received"],
            records_accepted=job_summary["records_accepted"],
            records_duplicates=job_summary["records_duplicates"],
            records_corrected=job_summary["records_corrected"],
            cursor_before=job_summary["cursor_before"],
            cursor_after=job_summary["cursor_after"],
        )
    except Exception as exc:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Ingestion job failed: {exc}")


@router.get(
    "/jobs",
    response_model=list[IntegrationJobResponse],
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
def list_integration_jobs(
    connector_id: str | None = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """List past and current integration sync jobs."""
    stmt = (
        select(IntegrationJobRecord)
        .where(IntegrationJobRecord.installation_id == installation_id)
        .order_by(desc(IntegrationJobRecord.started_at))
        .limit(limit)
        .offset(offset)
    )
    if connector_id:
        stmt = stmt.where(IntegrationJobRecord.connector_id == connector_id)

    jobs = db.execute(stmt).scalars().all()
    return [
        IntegrationJobResponse(
            job_id=j.job_id,
            installation_id=j.installation_id,
            connector_id=j.connector_id,
            job_type=j.job_type,
            triggered_by=j.triggered_by,
            status=j.status,
            started_at=j.started_at,
            completed_at=j.completed_at,
            records_received=j.records_received,
            records_accepted=j.records_accepted,
            records_rejected=j.records_rejected,
            records_duplicates=j.records_duplicates,
            records_corrected=j.records_corrected,
            error_message=j.error_message,
            cursor_before=j.cursor_before,
            cursor_after=j.cursor_after,
        )
        for j in jobs
    ]


@router.get(
    "/jobs/{job_id}",
    response_model=IntegrationJobResponse,
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
def get_job_detail(
    job_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """Retrieve details and metrics for an individual integration job."""
    job = db.get(IntegrationJobRecord, job_id)
    if job is None or job.installation_id != installation_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Integration job not found")

    return IntegrationJobResponse(
        job_id=job.job_id,
        installation_id=job.installation_id,
        connector_id=job.connector_id,
        job_type=job.job_type,
        triggered_by=job.triggered_by,
        status=job.status,
        started_at=job.started_at,
        completed_at=job.completed_at,
        records_received=job.records_received,
        records_accepted=job.records_accepted,
        records_rejected=job.records_rejected,
        records_duplicates=job.records_duplicates,
        records_corrected=job.records_corrected,
        error_message=job.error_message,
        cursor_before=job.cursor_before,
        cursor_after=job.cursor_after,
    )


@router.get(
    "/rejected-records",
    response_model=list[IntegrationRejectedResponse],
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
def list_rejected_records(
    connector_id: str | None = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """List records rejected during ingestion due to validation or schema errors."""
    stmt = (
        select(IntegrationRejectedRecord)
        .where(IntegrationRejectedRecord.installation_id == installation_id)
        .order_by(desc(IntegrationRejectedRecord.rejected_at))
        .limit(limit)
        .offset(offset)
    )
    if connector_id:
        stmt = stmt.where(IntegrationRejectedRecord.connector_id == connector_id)

    records = db.execute(stmt).scalars().all()
    return [
        IntegrationRejectedResponse(
            id=r.id,
            installation_id=r.installation_id,
            connector_id=r.connector_id,
            job_id=r.job_id,
            source_record_id=r.source_record_id,
            reason_code=r.reason_code,
            reason_message=r.reason_message,
            rejected_at=r.rejected_at,
        )
        for r in records
    ]


@router.post(
    "/reconciliation",
    response_model=ReconciliationResponse,
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
def trigger_reconciliation(
    req: ReconciliationRequest,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """Generate an explainable reconciliation report comparing expected source counts to ingested records."""
    report = generate_reconciliation_report(
        db,
        installation_id=installation_id,
        connector_id=req.connector_id,
        window_start=req.window_start,
        window_end=req.window_end,
        expected_source_count=req.expected_source_count,
    )
    return ReconciliationResponse(
        installation_id=report.installation_id,
        connector_id=report.connector_id,
        window_start=report.window_start,
        window_end=report.window_end,
        expected_source_count=report.expected_source_count,
        ingested_record_count=report.ingested_record_count,
        corrected_record_count=report.corrected_record_count,
        rejected_record_count=report.rejected_record_count,
        discrepancy=report.discrepancy,
        status=report.status,
        explanation=report.explanation,
    )


@router.get(
    "/quality",
    response_model=QualityAssessmentResponse,
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
def get_ingestion_quality(
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """Evaluate overall ingested data quality and impact on scenario detector readiness."""
    # Discover available feeds from stored integration records
    stmt = (
        select(IntegrationRecord.record_type)
        .where(IntegrationRecord.installation_id == installation_id)
        .distinct()
    )
    record_types = set(db.execute(stmt).scalars().all())

    available_feeds = set()
    if "transaction" in record_types:
        available_feeds.add("postings")
    if "employment_event" in record_types:
        available_feeds.add("hr_roster")
    if "staff_access" in record_types:
        available_feeds.add("audit_log")
    if "customer_change" in record_types:
        available_feeds.add("account_changes")

    detector_impact = assess_detector_readiness_from_integration(
        available_feeds=available_feeds,
        absent_fields=set(),
    )

    total_records = db.query(IntegrationRecord).filter_by(installation_id=installation_id).count()
    rejected_records = db.query(IntegrationRejectedRecord).filter_by(installation_id=installation_id).count()

    return QualityAssessmentResponse(
        total_records=total_records,
        valid_records=total_records,
        rejected_records=rejected_records,
        issues_count=rejected_records,
        issues=[],
        detector_impact=[
            {
                "detector_id": r.detector_id,
                "label": r.label,
                "status": r.status,
                "reasons": r.reasons,
                "missing_required_fields": r.missing_required_fields,
            }
            for r in detector_impact
        ],
    )
