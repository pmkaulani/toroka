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
    assert_dual_approval,
)
from ..persistence.audit import append_audit
from ..persistence.models import (
    CaseAssignment,
    CaseClosureProposal,
    CaseNote,
    EnterpriseCase,
    calculate_dedupe_key,
    utc_now,
)
from ..persistence.repositories import (
    CaseAssignmentRepository,
    CaseNoteRepository,
    CaseRepository,
    ClosureProposalRepository,
    RunRepository,
)

VALID_DISPOSITIONS = {
    "substantiated_referral",
    "not_substantiated",
    "data_gap_or_control_weakness",
}


def resolve_installation_id(
    principal: EnterprisePrincipal,
    supplied_installation_id: str | None = None,
) -> str:
    """Derives installation identity consistently from principal, strictly rejecting conflicts."""
    if principal.installation_id:
        if supplied_installation_id and principal.installation_id != supplied_installation_id:
            raise PermissionError(
                f"Installation mismatch: principal installation '{principal.installation_id}' "
                f"conflicts with requested installation '{supplied_installation_id}'"
            )
        return principal.installation_id
    return supplied_installation_id or "toroka-default-installation"


class CaseService:
    def __init__(self, db: Session):
        self.db = db
        self.cases = CaseRepository(db)
        self.assignments = CaseAssignmentRepository(db)
        self.notes = CaseNoteRepository(db)
        self.closure_proposals = ClosureProposalRepository(db)
        self.runs = RunRepository(db)

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
        installation_id: str | None = None,
        *,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[EnterpriseCase], int]:
        self._assert_can_access_cases(principal)
        effective_inst = resolve_installation_id(principal, installation_id)

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
            effective_inst,
            case_ids_filter=case_ids_filter,
            status=status,
            limit=limit,
            offset=offset,
        )

    def get_case(
        self,
        principal: EnterprisePrincipal,
        case_id: str,
        installation_id: str | None = None,
    ) -> EnterpriseCase:
        self._assert_can_access_cases(principal)
        effective_inst = resolve_installation_id(principal, installation_id)
        case = self.cases.get_by_id(case_id, installation_id=effective_inst)
        if case is None:
            raise LookupError("Case not found")

        # Do not disclose existence of case to unassigned investigator
        if (
            ROLE_INVESTIGATOR in principal.roles
            and ROLE_AUDITOR not in principal.roles
            and ROLE_AUTHORISER not in principal.roles
        ):
            assignment = self.assignments.get_active_assignment(
                case_id, principal.subject, installation_id=effective_inst
            )
            if assignment is None:
                raise LookupError("Case not found")

        return case

    def create_case(
        self,
        principal: EnterprisePrincipal,
        *,
        installation_id: str | None = None,
        label: str,
        focus: str,
        snapshot: dict[str, Any],
        manifest_id: str | None = None,
        assign_to_subject: str | None = None,
    ) -> EnterpriseCase:
        self._assert_can_access_cases(principal)
        effective_inst = resolve_installation_id(principal, installation_id)

        snapshot_canon = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
        snapshot_hash = hashlib.sha256(snapshot_canon.encode("utf-8")).hexdigest()
        dedupe = calculate_dedupe_key(effective_inst, manifest_id or "", focus)

        existing = self.cases.get_by_dedupe_key(effective_inst, dedupe)
        if existing:
            return existing

        case = EnterpriseCase(
            installation_id=effective_inst,
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
        installation_id: str | None = None,
    ) -> CaseAssignment:
        self._assert_can_access_cases(principal)
        if ROLE_AUTHORISER not in principal.roles and ROLE_SYSTEM_ADMINISTRATOR not in principal.roles:
            raise PermissionError("Only authorisers or administrators can delegate case assignments.")

        case = self.get_case(principal, case_id, installation_id=installation_id)

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
        installation_id: str | None = None,
    ) -> EnterpriseCase:
        self._assert_can_access_cases(principal)
        effective_inst = resolve_installation_id(principal, installation_id)
        case = self.cases.get_by_id(case_id, installation_id=effective_inst, for_update=True)
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

    def propose_closure(
        self,
        principal: EnterprisePrincipal,
        case_id: str,
        *,
        disposition: str,
        closing_note: str,
        alternatives_considered: str,
        expected_case_version: int,
    ) -> CaseClosureProposal:
        self._assert_can_access_cases(principal)
        case = self.get_case(principal, case_id)
        self._assert_can_mutate_case(principal, case)

        if case.status == "closed":
            raise ValueError("Cannot propose closure on a closed case")

        if disposition not in VALID_DISPOSITIONS:
            raise ValueError(
                f"Invalid disposition '{disposition}'. Must be one of {sorted(VALID_DISPOSITIONS)}"
            )

        if not closing_note or not closing_note.strip():
            raise ValueError("Closing note is required to propose case closure")

        if not alternatives_considered or not alternatives_considered.strip():
            raise ValueError(
                "Documenting alternative explanations considered is mandatory before proposing closure"
            )

        if case.version != expected_case_version:
            raise ValueError(
                f"Concurrent modification conflict: expected version {expected_case_version}, but case is at version {case.version}"
            )

        existing = self.closure_proposals.get_pending_for_case(case_id)
        if existing:
            raise ValueError("A closure proposal is already pending for this case")

        proposal = CaseClosureProposal(
            case_id=case_id,
            requested_by=principal.subject,
            disposition=disposition,
            closing_note=closing_note.strip(),
            alternatives_considered=alternatives_considered.strip(),
            expected_case_version=case.version,
            status="pending",
        )
        self.closure_proposals.create(proposal)

        append_audit(
            self.db,
            installation_id=case.installation_id,
            actor_subject=principal.subject,
            actor_role="investigator" if ROLE_INVESTIGATOR in principal.roles else "authoriser",
            action="closure_proposed",
            target_type="case_closure_proposal",
            target_id=proposal.id,
            safe_metadata={
                "case_id": case_id,
                "proposal_id": proposal.id,
                "disposition": disposition,
                "expected_case_version": case.version,
            },
        )
        self.db.commit()
        return proposal

    def review_closure(
        self,
        principal: EnterprisePrincipal,
        proposal_id: str,
        *,
        approve: bool,
        review_note: str | None = None,
        installation_id: str | None = None,
    ) -> CaseClosureProposal:
        self._assert_can_access_cases(principal)
        if ROLE_AUTHORISER not in principal.roles:
            raise PermissionError("Only authorisers can review case closure proposals.")

        effective_inst = resolve_installation_id(principal, installation_id)
        proposal = self.closure_proposals.get_by_id(proposal_id, installation_id=effective_inst, for_update=True)
        if proposal is None:
            raise LookupError("Closure proposal not found")

        if proposal.status != "pending":
            raise ValueError(f"Closure proposal has already been processed (current status: '{proposal.status}')")

        # Dual approval: maker != checker
        assert_dual_approval(
            proposal.requested_by,
            principal.subject,
            action_name="case closure proposal",
        )

        case = self.cases.get_by_id(proposal.case_id, installation_id=effective_inst, for_update=True)
        if case is None:
            raise LookupError("Associated case not found")

        now = utc_now()
        if approve:
            if case.status == "closed":
                raise ValueError("Case is already closed")

            if case.version != proposal.expected_case_version:
                raise ValueError(
                    f"Concurrent modification conflict: expected version {proposal.expected_case_version}, but case is at version {case.version}"
                )

            case.status = "closed"
            case.disposition = proposal.disposition
            case.closing_note = proposal.closing_note
            case.alternatives_considered = proposal.alternatives_considered
            case.closed_at = now
            case.updated_at = now
            case.version += 1

            proposal.status = "approved"
            proposal.reviewed_by = principal.subject
            proposal.review_note = review_note.strip() if review_note else None
            proposal.reviewed_at = now

            append_audit(
                self.db,
                installation_id=case.installation_id,
                actor_subject=principal.subject,
                actor_role="authoriser",
                action="closure_approved",
                target_type="case_closure_proposal",
                target_id=proposal.id,
                safe_metadata={
                    "case_id": case.id,
                    "proposal_id": proposal.id,
                    "disposition": case.disposition,
                    "version": case.version,
                    "reviewed_by": principal.subject,
                },
            )
        else:
            proposal.status = "rejected"
            proposal.reviewed_by = principal.subject
            proposal.review_note = review_note.strip() if review_note else "Rejected without comment"
            proposal.reviewed_at = now

            append_audit(
                self.db,
                installation_id=case.installation_id,
                actor_subject=principal.subject,
                actor_role="authoriser",
                action="closure_rejected",
                target_type="case_closure_proposal",
                target_id=proposal.id,
                safe_metadata={
                    "case_id": case.id,
                    "proposal_id": proposal.id,
                    "reviewed_by": principal.subject,
                    "review_note": proposal.review_note,
                },
            )

        self.db.commit()
        return proposal

    def list_pending_closure_proposals(
        self,
        principal: EnterprisePrincipal,
        installation_id: str | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[CaseClosureProposal]:
        self._assert_can_access_cases(principal)
        if ROLE_AUTHORISER not in principal.roles:
            raise PermissionError("Only authorisers can view the pending closure review queue.")
        effective_inst = resolve_installation_id(principal, installation_id)
        return self.closure_proposals.list_pending(effective_inst, limit=limit, offset=offset)

    def list_case_closure_proposals(
        self,
        principal: EnterprisePrincipal,
        case_id: str,
        installation_id: str | None = None,
    ) -> list[CaseClosureProposal]:
        self._assert_can_access_cases(principal)
        self.get_case(principal, case_id, installation_id=installation_id)
        effective_inst = resolve_installation_id(principal, installation_id)
        return self.closure_proposals.list_by_case(case_id, installation_id=effective_inst)

    def intake_from_run(
        self,
        principal: EnterprisePrincipal,
        *,
        installation_id: str | None = None,
        manifest_id: str,
        leads: list[dict[str, Any]] | None = None,
        assign_to_subject: str | None = None,
    ) -> dict[str, Any]:
        if not principal.roles.intersection(CASEWORK_ROLES) and ROLE_SYSTEM_ADMINISTRATOR not in principal.roles:
            raise PermissionError("Permission denied.")

        effective_inst = resolve_installation_id(principal, installation_id)
        run = self.runs.get_by_manifest_id(manifest_id, installation_id=effective_inst)
        if run is None:
            raise LookupError(f"Run manifest '{manifest_id}' not found. Cannot intake cases from an unverified run.")

        intake_leads = leads
        if intake_leads is None:
            manifest_dict = run.manifest if isinstance(run.manifest, dict) else {}
            intake_leads = manifest_dict.get("leads") or manifest_dict.get("results") or []

        if not intake_leads:
            return {
                "manifest_id": manifest_id,
                "created_count": 0,
                "existing_count": 0,
                "case_ids": [],
            }

        created_count = 0
        existing_count = 0
        case_ids: list[str] = []

        for lead in intake_leads:
            focus = lead.get("focus") or lead.get("target") or "unknown_focus"
            label = lead.get("label") or lead.get("verdict") or "REVIEW"
            dedupe = calculate_dedupe_key(effective_inst, manifest_id, focus)

            existing = self.cases.get_by_dedupe_key(effective_inst, dedupe)
            if existing:
                existing_count += 1
                case_ids.append(existing.id)
                continue

            snapshot_canon = json.dumps(lead, sort_keys=True, separators=(",", ":"))
            snapshot_hash = hashlib.sha256(snapshot_canon.encode("utf-8")).hexdigest()

            case = EnterpriseCase(
                installation_id=installation_id,
                dedupe_key=dedupe,
                label=label,
                focus=focus,
                snapshot=lead,
                snapshot_sha256=snapshot_hash,
                manifest_id=manifest_id,
                created_by=principal.subject,
                status="open",
            )
            self.cases.create(case)

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
                actor_role="investigator" if ROLE_INVESTIGATOR in principal.roles else ("authoriser" if ROLE_AUTHORISER in principal.roles else "system_administrator"),
                action="case_created",
                target_type="case",
                target_id=case.id,
                safe_metadata={
                    "case_id": case.id,
                    "manifest_id": manifest_id,
                    "assigned_subject": assignee,
                },
            )
            created_count += 1
            case_ids.append(case.id)

        self.db.commit()
        return {
            "manifest_id": manifest_id,
            "created_count": created_count,
            "existing_count": existing_count,
            "case_ids": case_ids,
        }
