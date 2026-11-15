"""Repository layer for operational Enterprise persistence."""
from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import (
    AuditHead,
    AuditRecord,
    CaseAssignment,
    CaseClosureProposal,
    CaseNote,
    EnterpriseCase,
    RevealRequest,
    RunRecord,
)


class CaseRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(self, case_id: str, *, for_update: bool = False) -> EnterpriseCase | None:
        stmt = select(EnterpriseCase).where(EnterpriseCase.id == case_id)
        if for_update:
            stmt = stmt.with_for_update()
        return self.db.execute(stmt).scalar_one_or_none()

    def get_by_dedupe_key(
        self, installation_id: str, dedupe_key: str
    ) -> EnterpriseCase | None:
        stmt = select(EnterpriseCase).where(
            EnterpriseCase.installation_id == installation_id,
            EnterpriseCase.dedupe_key == dedupe_key,
        )
        return self.db.execute(stmt).scalar_one_or_none()

    def list_cases(
        self,
        installation_id: str,
        *,
        case_ids_filter: set[str] | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[EnterpriseCase], int]:
        stmt = select(EnterpriseCase).where(
            EnterpriseCase.installation_id == installation_id
        )
        count_stmt = select(func.count(EnterpriseCase.id)).where(
            EnterpriseCase.installation_id == installation_id
        )

        if status:
            stmt = stmt.where(EnterpriseCase.status == status)
            count_stmt = count_stmt.where(EnterpriseCase.status == status)

        if case_ids_filter is not None:
            stmt = stmt.where(EnterpriseCase.id.in_(case_ids_filter))
            count_stmt = count_stmt.where(EnterpriseCase.id.in_(case_ids_filter))

        total = self.db.execute(count_stmt).scalar() or 0
        cases = (
            self.db.execute(
                stmt.order_by(EnterpriseCase.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
            .scalars()
            .all()
        )
        return list(cases), total

    def create(self, case: EnterpriseCase) -> EnterpriseCase:
        self.db.add(case)
        self.db.flush()
        return case


class CaseAssignmentRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_active_assignment(
        self, case_id: str, subject: str
    ) -> CaseAssignment | None:
        stmt = select(CaseAssignment).where(
            CaseAssignment.case_id == case_id,
            CaseAssignment.assigned_subject == subject,
            CaseAssignment.status == "active",
        )
        return self.db.execute(stmt).scalar_one_or_none()

    def list_active_assignments_for_case(
        self, case_id: str
    ) -> list[CaseAssignment]:
        stmt = select(CaseAssignment).where(
            CaseAssignment.case_id == case_id,
            CaseAssignment.status == "active",
        )
        return list(self.db.execute(stmt).scalars().all())

    def list_assigned_case_ids(self, subject: str) -> set[str]:
        stmt = select(CaseAssignment.case_id).where(
            CaseAssignment.assigned_subject == subject,
            CaseAssignment.status == "active",
        )
        return set(self.db.execute(stmt).scalars().all())

    def create(self, assignment: CaseAssignment) -> CaseAssignment:
        self.db.add(assignment)
        self.db.flush()
        return assignment


class CaseNoteRepository:
    def __init__(self, db: Session):
        self.db = db

    def list_notes_for_case(self, case_id: str) -> list[CaseNote]:
        stmt = (
            select(CaseNote)
            .where(CaseNote.case_id == case_id)
            .order_by(CaseNote.created_at.asc())
        )
        return list(self.db.execute(stmt).scalars().all())

    def create(self, note: CaseNote) -> CaseNote:
        self.db.add(note)
        self.db.flush()
        return note


class ClosureProposalRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(
        self, proposal_id: str, *, for_update: bool = False
    ) -> CaseClosureProposal | None:
        stmt = select(CaseClosureProposal).where(CaseClosureProposal.id == proposal_id)
        if for_update:
            stmt = stmt.with_for_update()
        return self.db.execute(stmt).scalar_one_or_none()

    def get_pending_for_case(self, case_id: str) -> CaseClosureProposal | None:
        stmt = select(CaseClosureProposal).where(
            CaseClosureProposal.case_id == case_id,
            CaseClosureProposal.status == "pending",
        )
        return self.db.execute(stmt).scalar_one_or_none()

    def list_pending(
        self,
        installation_id: str | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[CaseClosureProposal]:
        stmt = select(CaseClosureProposal).where(CaseClosureProposal.status == "pending")
        if installation_id:
            stmt = stmt.join(EnterpriseCase, CaseClosureProposal.case_id == EnterpriseCase.id).where(
                EnterpriseCase.installation_id == installation_id
            )
        stmt = stmt.order_by(CaseClosureProposal.requested_at.asc()).limit(limit).offset(offset)
        return list(self.db.execute(stmt).scalars().all())

    def list_by_case(self, case_id: str) -> list[CaseClosureProposal]:
        stmt = (
            select(CaseClosureProposal)
            .where(CaseClosureProposal.case_id == case_id)
            .order_by(CaseClosureProposal.requested_at.desc())
        )
        return list(self.db.execute(stmt).scalars().all())

    def create(self, proposal: CaseClosureProposal) -> CaseClosureProposal:
        self.db.add(proposal)
        self.db.flush()
        return proposal


class RevealRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_id(
        self, request_id: str, *, for_update: bool = False
    ) -> RevealRequest | None:
        stmt = select(RevealRequest).where(RevealRequest.id == request_id)
        if for_update:
            stmt = stmt.with_for_update()
        return self.db.execute(stmt).scalar_one_or_none()

    def list_pending(
        self,
        installation_id: str | None = None,
        *,
        requested_by: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[RevealRequest]:
        stmt = select(RevealRequest).where(RevealRequest.status == "pending")
        if installation_id:
            stmt = stmt.join(EnterpriseCase, RevealRequest.case_id == EnterpriseCase.id).where(
                EnterpriseCase.installation_id == installation_id
            )
        if requested_by:
            stmt = stmt.where(RevealRequest.requested_by == requested_by)
        stmt = (
            stmt.order_by(RevealRequest.created_at.asc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.db.execute(stmt).scalars().all())

    def list_by_case(self, case_id: str) -> list[RevealRequest]:
        stmt = (
            select(RevealRequest)
            .where(RevealRequest.case_id == case_id)
            .order_by(RevealRequest.created_at.desc())
        )
        return list(self.db.execute(stmt).scalars().all())

    def create(self, request: RevealRequest) -> RevealRequest:
        self.db.add(request)
        self.db.flush()
        return request


class RunRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_by_manifest_id(
        self, manifest_id: str, installation_id: str | None = None
    ) -> RunRecord | None:
        stmt = select(RunRecord).where(RunRecord.manifest_id == manifest_id)
        if installation_id:
            stmt = stmt.where(RunRecord.installation_id == installation_id)
        return self.db.execute(stmt).scalar_one_or_none()

    def list_runs(
        self,
        installation_id: str | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[RunRecord]:
        stmt = select(RunRecord)
        if installation_id:
            stmt = stmt.where(RunRecord.installation_id == installation_id)
        stmt = (
            stmt.order_by(RunRecord.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.db.execute(stmt).scalars().all())

    def create(self, run: RunRecord) -> RunRecord:
        self.db.add(run)
        self.db.flush()
        return run


class AuditRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_head(self, installation_id: str) -> AuditHead | None:
        stmt = select(AuditHead).where(
            AuditHead.installation_id == installation_id
        )
        return self.db.execute(stmt).scalar_one_or_none()

    def list_records(
        self, installation_id: str, *, limit: int = 50, offset: int = 0
    ) -> list[AuditRecord]:
        stmt = (
            select(AuditRecord)
            .where(AuditRecord.installation_id == installation_id)
            .order_by(AuditRecord.sequence.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.db.execute(stmt).scalars().all())
