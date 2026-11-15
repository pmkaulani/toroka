"""Case management service orchestrating case lifecycle, access control, and audit."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ..auth import EnterprisePrincipal
from ..permissions import (
    CASEWORK_ROLES,
    ROLE_AUDITOR,
    ROLE_AUTHORISER,
    ROLE_DATA_STEWARD,
    ROLE_INVESTIGATOR,
    ROLE_SYSTEM_ADMINISTRATOR,
)
from ..persistence.audit import append_audit
from ..persistence.models import (
    CaseAssignment,
    CaseNote,
    EnterpriseCase,
    calculate_dedupe_key,
    utc_now,
)
from ..persistence.repositories import (
    CaseAssignmentRepository,
    CaseNoteRepository,
    CaseRepository,
)

VALID_DISPOSITIONS = {
    "substantiated_referral",
    "not_substantiated",
    "data_gap_or_control_weakness",
}


class CaseService:
    def __init__(self, db: Session):
        self.db = db
        self.cases = CaseRepository(db)
        self.assignments = CaseAssignmentRepository(db)
        self.notes = CaseNoteRepository(db)

    def _assert_can_access_cases(self, principal: EnterprisePrincipal) -> None:
        if ROLE_DATA_STEWARD in principal.roles or ROLE_SYSTEM_ADMINISTRATOR in principal.roles:
            if not principal.roles.intersection(CASEWORK_ROLES):
                raise PermissionError("Access to investigation casework is not permitted for your role.")
        if not principal.roles.intersection(CASEWORK_ROLES):
            raise PermissionError("You do not have permission to view investigation cases.")

    def _assert_can_mutate_case(
        self, principal: EnterprisePrincipal, case: EnterpriseCase
    ) -> None:
        if ROLE_AUDITOR in principal.roles and not principal.roles.intersection({ROLE_INVESTIGATOR, ROLE_AUTHORISER}):
            raise PermissionError("Auditors have read-only access and cannot mutate cases.")

        if ROLE_INVESTIGATOR in principal.roles:
            # Check assignment
            assignment = self.assignments.get_active_assignment(
                case.id, principal.subject
            )
            if assignment is None and ROLE_AUTHORISER not in principal.roles:
                raise PermissionError("You are not assigned to this case.")

    def list_cases(
        self,
        principal: EnterprisePrincipal,
        installation_id: str,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[EnterpriseCase], int]:
        self._assert_can_access_cases(principal)

        case_ids_filter = None
        # Strict assignment filter for pure investigators
        if (
            ROLE_INVESTIGATOR in principal.roles
            and ROLE_AUDITOR not in principal.roles
            and ROLE_AUTHORISER not in principal.roles
        ):
            case_ids_filter = self.assignments.list_assigned_case_ids(
                principal.subject
            )

        return self.cases.list_cases(
            installation_id,
            case_ids_filter=case_ids_filter,
            status=status,
            limit=limit,
            offset=offset,
        )

    def get_case(
        self,
        principal: EnterprisePrincipal,
        case_id: str,
    ) -> EnterpriseCase:
        self._assert_can_access_cases(principal)
        case = self.cases.get_by_id(case_id)
        if case is None:
            raise LookupError("Case not found")

        # Do not disclose existence of case to unassigned investigator
        if (
            ROLE_INVESTIGATOR in principal.roles
            and ROLE_AUDITOR not in principal.roles
            and ROLE_AUTHORISER not in principal.roles
        ):
            assignment = self.assignments.get_active_assignment(
                case_id, principal.subject
            )
            if assignment is None:
                raise LookupError("Case not found")

        return case

    def create_case(
        self,
        principal: EnterprisePrincipal,
        *,
        installation_id: str,
        label: str,
        focus: str,
        snapshot: dict[str, Any],
        manifest_id: str | None = None,
        assign_to_subject: str | None = None,
    ) -> EnterpriseCase:
        self._assert_can_access_cases(principal)

        snapshot_canon = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
        snapshot_hash = hashlib.sha256(snapshot_canon.encode("utf-8")).hexdigest()
        dedupe = calculate_dedupe_key(installation_id, manifest_id or "", focus)

        existing = self.cases.get_by_dedupe_key(installation_id, dedupe)
        if existing:
            return existing

        case = EnterpriseCase(
            installation_id=installation_id,
            dedupe_key=dedupe,
            label=label,
            focus=focus,
            snapshot=snapshot,
            snapshot_sha256=snapshot_hash,
            manifest_id=manifest_id,
            created_by=principal.subject,
            status="open",
        )
        self.cases.create(case)

        # Initial assignment
        assignee = assign_to_subject or principal.subject
        assignment = CaseAssignment(
            case_id=case.id,
            assigned_subject=assignee,
            assignment_role="investigator",
            assigned_by=principal.subject,
        )
        self.assignments.create(assignment)

        append_audit(
            self.db,
            installation_id=installation_id,
            actor_subject=principal.subject,
            actor_role="investigator" if ROLE_INVESTIGATOR in principal.roles else "authoriser",
            action="case_created",
            target_type="case",
            target_id=case.id,
            safe_metadata={
                "case_id": case.id,
                "manifest_id": manifest_id or "",
                "assigned_subject": assignee,
            },
        )
        self.db.commit()
        return case

    def add_note(
        self,
        principal: EnterprisePrincipal,
        case_id: str,
        body: str,
    ) -> CaseNote:
        self._assert_can_access_cases(principal)
        case = self.get_case(principal, case_id)
        self._assert_can_mutate_case(principal, case)

        if not body or not body.strip():
            raise ValueError("Note body cannot be empty")

        note = CaseNote(
            case_id=case_id,
            author_subject=principal.subject,
            body=body.strip(),
        )
        self.notes.create(note)

        append_audit(
            self.db,
            installation_id=case.installation_id,
            actor_subject=principal.subject,
            actor_role="investigator" if ROLE_INVESTIGATOR in principal.roles else "authoriser",
            action="case_note_added",
            target_type="case",
            target_id=case_id,
            safe_metadata={"case_id": case_id},
        )
        self.db.commit()
        return note

    def assign_case(
        self,
        principal: EnterprisePrincipal,
        case_id: str,
        assignee_subject: str,
        assignment_role: str = "investigator",
    ) -> CaseAssignment:
        self._assert_can_access_cases(principal)
        if ROLE_AUTHORISER not in principal.roles and ROLE_SYSTEM_ADMINISTRATOR not in principal.roles:
            raise PermissionError("Only authorisers or administrators can delegate case assignments.")

        case = self.cases.get_by_id(case_id)
        if case is None:
            raise LookupError("Case not found")

        assignment = CaseAssignment(
            case_id=case_id,
            assigned_subject=assignee_subject,
            assignment_role=assignment_role,
            assigned_by=principal.subject,
        )
        self.assignments.create(assignment)

        append_audit(
            self.db,
            installation_id=case.installation_id,
            actor_subject=principal.subject,
            actor_role="authoriser" if ROLE_AUTHORISER in principal.roles else "system_administrator",
            action="case_assigned",
            target_type="case",
            target_id=case_id,
            safe_metadata={
                "case_id": case_id,
                "assigned_subject": assignee_subject,
                "assignment_role": assignment_role,
            },
        )
        self.db.commit()
        return assignment

    def close_case(
        self,
        principal: EnterprisePrincipal,
        case_id: str,
        *,
        disposition: str,
        closing_note: str,
        alternatives_considered: str,
        expected_version: int,
    ) -> EnterpriseCase:
        self._assert_can_access_cases(principal)
        case = self.cases.get_by_id(case_id, for_update=True)
        if case is None:
            raise LookupError("Case not found")

        self._assert_can_mutate_case(principal, case)

        if case.status == "closed":
            raise ValueError("Case is already closed")

        if disposition not in VALID_DISPOSITIONS:
            raise ValueError(
                f"Invalid disposition '{disposition}'. Must be one of {sorted(VALID_DISPOSITIONS)}"
            )

        if not closing_note or not closing_note.strip():
            raise ValueError("Closing note is required to close a case")

        if not alternatives_considered or not alternatives_considered.strip():
            raise ValueError(
                "Documenting alternative explanations considered is mandatory before closing"
            )

        if case.version != expected_version:
            raise ValueError(
                f"Concurrent modification conflict: expected version {expected_version}, but case is at version {case.version}"
            )

        now = utc_now()
        case.status = "closed"
        case.disposition = disposition
        case.closing_note = closing_note.strip()
        case.alternatives_considered = alternatives_considered.strip()
        case.closed_at = now
        case.updated_at = now
        case.version += 1

        append_audit(
            self.db,
            installation_id=case.installation_id,
            actor_subject=principal.subject,
            actor_role="investigator" if ROLE_INVESTIGATOR in principal.roles else "authoriser",
            action="case_closed",
            target_type="case",
            target_id=case_id,
            safe_metadata={
                "case_id": case_id,
                "disposition": disposition,
                "version": case.version,
            },
        )
        self.db.commit()
        return case
