"""Pydantic schemas for Enterprise API request and response validation."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CaseSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    installation_id: str
    label: str
    focus: str
    status: str
    version: int
    created_at: datetime
    updated_at: datetime


class CaseDetailResponse(CaseSummaryResponse):
    snapshot: dict[str, Any]
    snapshot_sha256: str
    manifest_id: str | None = None
    disposition: str | None = None
    closing_note: str | None = None
    alternatives_considered: str | None = None
    closed_at: datetime | None = None


class CaseListResponse(BaseModel):
    total: int
    items: list[CaseSummaryResponse]


class NoteCreateRequest(BaseModel):
    body: str = Field(min_length=1, max_length=10000)


class NoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    author_subject: str
    body: str
    created_at: datetime


class CaseAssignRequest(BaseModel):
    assignee_subject: str = Field(min_length=1, max_length=255)
    assignment_role: str = Field(default="investigator", max_length=40)


class CaseAssignmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    assigned_subject: str
    assignment_role: str
    assigned_by: str
    status: str
    assigned_at: datetime


class CaseCloseRequest(BaseModel):
    disposition: str = Field(min_length=1, max_length=64)
    closing_note: str = Field(min_length=1, max_length=10000)
    alternatives_considered: str = Field(min_length=1, max_length=10000)
    expected_version: int = Field(ge=1)


class RevealRequestCreate(BaseModel):
    pseudonym: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=10, max_length=2000)
    ttl_hours: int = Field(default=24, ge=1, le=168)


class RevealRequestResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    case_id: str
    pseudonym: str
    requested_by: str
    reason: str
    status: str
    created_at: datetime
    expires_at: datetime
    approved_by: str | None = None
    approved_at: datetime | None = None
    used_at: datetime | None = None
    rejection_reason: str | None = None


class RevealRejectRequest(BaseModel):
    rejection_reason: str = Field(min_length=1, max_length=2000)


class RevealConsumeResponse(BaseModel):
    request_id: str
    pseudonym: str
    plaintext_identity: str
    consumed_at: datetime


class RunSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    manifest_id: str
    result_digest: str | None = None
    status: str
    created_by: str
    created_at: datetime


class RunDetailResponse(RunSummaryResponse):
    manifest: dict[str, Any]
