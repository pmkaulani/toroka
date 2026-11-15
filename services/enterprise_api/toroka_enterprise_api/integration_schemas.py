"""Pydantic schemas for integration endpoints, connector lifecycle, and reconciliation."""
from __future__ import annotations

from datetime import datetime
from typing import Any
from pydantic import BaseModel, Field


class ConnectorResponse(BaseModel):
    connector_id: str
    connector_type: str
    source_system: str
    version: str
    enabled: bool
    registered_at: datetime
    metadata: dict[str, Any]
    capabilities: dict[str, Any]
    cursor: str | None = None
    records_ingested: int = 0


class ConnectorSyncRequest(BaseModel):
    batch_size: int = Field(default=500, ge=10, le=5000)
    max_batches: int = Field(default=10, ge=1, le=100)


class ConnectorSyncResponse(BaseModel):
    job_id: str
    connector_id: str
    status: str
    records_received: int
    records_accepted: int
    records_duplicates: int
    records_corrected: int
    cursor_before: str | None = None
    cursor_after: str | None = None


class IntegrationJobResponse(BaseModel):
    job_id: str
    installation_id: str
    connector_id: str
    job_type: str
    triggered_by: str
    status: str
    started_at: datetime
    completed_at: datetime | None = None
    records_received: int
    records_accepted: int
    records_rejected: int
    records_duplicates: int
    records_corrected: int
    error_message: str | None = None
    cursor_before: str | None = None
    cursor_after: str | None = None


class IntegrationRejectedResponse(BaseModel):
    id: str
    installation_id: str
    connector_id: str
    job_id: str | None = None
    source_record_id: str | None = None
    reason_code: str
    reason_message: str
    rejected_at: datetime


class ReconciliationRequest(BaseModel):
    connector_id: str
    window_start: datetime | None = None
    window_end: datetime | None = None
    expected_source_count: int | None = None


class ReconciliationResponse(BaseModel):
    installation_id: str
    connector_id: str
    window_start: datetime | None = None
    window_end: datetime | None = None
    expected_source_count: int | None = None
    ingested_record_count: int
    corrected_record_count: int
    rejected_record_count: int
    discrepancy: int
    status: str
    explanation: str


class QualityAssessmentResponse(BaseModel):
    total_records: int
    valid_records: int
    rejected_records: int
    issues_count: int
    issues: list[dict[str, Any]]
    detector_impact: list[dict[str, Any]]


class IncomingEvent(BaseModel):
    event_id: str = Field(min_length=1, max_length=255)
    event_type: str = Field(min_length=1, max_length=128)
    timestamp: int
    payload: dict[str, Any]


class IncomingEventResponse(BaseModel):
    status: str
    event_id: str
    payload_digest: str
    received_at: datetime
