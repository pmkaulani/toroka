"""Transaction-safe identity reveal request, approval, and consumption workflow."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from ..auth import EnterprisePrincipal
from ..grants import create_signed_reveal_grant
from ..permissions import (
    ROLE_AUTHORISER,
    ROLE_INVESTIGATOR,
    assert_dual_approval,
)
from ..persistence.audit import append_audit
from ..persistence.models import EnterpriseCase, RevealRequest, utc_now
from ..persistence.repositories import (
    CaseAssignmentRepository,
    CaseRepository,
    RevealRepository,
)
from ..persistence.vault import IdentityVaultRepository

REVEAL_TTL = timedelta(hours=24)


def _ensure_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class RevealService:
    def __init__(self, db: Session, vault_repo: IdentityVaultRepository):
        self.db = db
        self.vault_repo = vault_repo
        self.reveals = RevealRepository(db)
        self.cases = CaseRepository(db)
        self.assignments = CaseAssignmentRepository(db)

    def request_reveal(
        self,
        principal: EnterprisePrincipal,
        *,
        case_id: str,
        pseudonym: str,
        reason: str,
        ttl_hours: int = 24,
    ) -> RevealRequest:
        if ROLE_INVESTIGATOR not in principal.roles:
            raise PermissionError("Only investigators can request an identity reveal.")

        case = self.cases.get_by_id(case_id)
        if case is None:
            raise LookupError("Case not found")

        if case.status == "closed":
            raise ValueError("Cannot request identity reveal on a closed case")

        # Verify assignment
        assignment = self.assignments.get_active_assignment(case_id, principal.subject)
        if assignment is None and ROLE_AUTHORISER not in principal.roles:
            raise PermissionError("You are not assigned to this case.")

        if not reason or len(reason.strip()) < 10:
            raise ValueError("A substantive written justification (at least 10 characters) is required.")

        now = utc_now()
        req = RevealRequest(
            case_id=case_id,
            pseudonym=pseudonym.strip(),
            requested_by=principal.subject,
            reason=reason.strip(),
            status="pending",
            created_at=now,
            expires_at=now + timedelta(hours=ttl_hours),
        )
        self.reveals.create(req)

        append_audit(
            self.db,
            installation_id=case.installation_id,
            actor_subject=principal.subject,
            actor_role="investigator",
            action="reveal_requested",
            target_type="reveal_request",
            target_id=req.id,
            safe_metadata={
                "case_id": case_id,
                "pseudonym": pseudonym.strip(),
                "reason": reason.strip(),
            },
        )
        self.db.commit()
        return req

    def list_pending(
        self,
        principal: EnterprisePrincipal,
        installation_id: str | None = None,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[RevealRequest]:
        if ROLE_AUTHORISER not in principal.roles and ROLE_INVESTIGATOR not in principal.roles:
            raise PermissionError("Permission denied.")

        requested_by = None
        if ROLE_INVESTIGATOR in principal.roles and ROLE_AUTHORISER not in principal.roles:
            requested_by = principal.subject

        return self.reveals.list_pending(
            installation_id=installation_id,
            requested_by=requested_by,
            limit=limit,
            offset=offset,
        )

    def approve_reveal(
        self,
        principal: EnterprisePrincipal,
        *,
        request_id: str,
    ) -> RevealRequest:
        if ROLE_AUTHORISER not in principal.roles:
            raise PermissionError("Only authorisers can approve identity reveal requests.")

        now = utc_now()
        req = self.reveals.get_by_id(request_id, for_update=True)
        if req is None:
            raise LookupError("Reveal request not found")

        if req.status != "pending":
            raise ValueError(f"Reveal request cannot be approved (current status: '{req.status}')")

        if _ensure_utc(req.expires_at) <= now:
            req.status = "expired"
            self.db.commit()
            raise ValueError("Reveal request has expired")

        # Strict dual-approval check: requester != authoriser
        assert_dual_approval(req.requested_by, principal.subject)

        req.status = "approved"
        req.approved_by = principal.subject
        req.approved_at = now

        case = self.cases.get_by_id(req.case_id)
        inst_id = case.installation_id if case else "default"

        req.reveal_token = create_signed_reveal_grant(
            grant_id=req.id,
            installation_id=inst_id,
            case_id=req.case_id,
            requester_subject=req.requested_by,
            approver_subject=principal.subject,
            pseudonym=req.pseudonym,
            expires_at=req.expires_at,
        )

        append_audit(
            self.db,
            installation_id=inst_id,
            actor_subject=principal.subject,
            actor_role="authoriser",
            action="reveal_approved",
            target_type="reveal_request",
            target_id=req.id,
            safe_metadata={
                "case_id": req.case_id,
                "pseudonym": req.pseudonym,
            },
        )
        self.db.commit()
        return req

    def reject_reveal(
        self,
        principal: EnterprisePrincipal,
        *,
        request_id: str,
        rejection_reason: str,
    ) -> RevealRequest:
        if ROLE_AUTHORISER not in principal.roles:
            raise PermissionError("Only authorisers can reject identity reveal requests.")

        if not rejection_reason or not rejection_reason.strip():
            raise ValueError("A rejection reason is required.")

        now = utc_now()
        req = self.reveals.get_by_id(request_id, for_update=True)
        if req is None:
            raise LookupError("Reveal request not found")

        if req.status != "pending":
            raise ValueError(f"Reveal request cannot be rejected (current status: '{req.status}')")

        req.status = "rejected"
        req.rejection_reason = rejection_reason.strip()
        req.approved_by = principal.subject
        req.approved_at = now

        case = self.cases.get_by_id(req.case_id)
        inst_id = case.installation_id if case else "default"

        append_audit(
            self.db,
            installation_id=inst_id,
            actor_subject=principal.subject,
            actor_role="authoriser",
            action="reveal_rejected",
            target_type="reveal_request",
            target_id=req.id,
            safe_metadata={
                "case_id": req.case_id,
                "pseudonym": req.pseudonym,
                "reason": rejection_reason.strip(),
            },
        )
        self.db.commit()
        return req

    def consume_reveal(
        self,
        principal: EnterprisePrincipal,
        *,
        request_id: str,
    ) -> str:
        """Consume an approved identity reveal once. Returns the decrypted plaintext identity."""
        now = utc_now()
        req = self.reveals.get_by_id(request_id, for_update=True)
        if req is None:
            raise LookupError("Reveal request not found")

        if req.status == "used":
            raise ValueError("Reveal token has already been consumed (single use only)")

        if req.status != "approved":
            raise ValueError(f"Reveal request is not approved (status: '{req.status}')")

        if _ensure_utc(req.expires_at) <= now:
            req.status = "expired"
            self.db.commit()
            raise ValueError("Reveal token has expired")

        # Only the original requesting investigator can consume
        if req.requested_by != principal.subject:
            raise PermissionError("Only the original requesting investigator may consume this reveal token.")

        case = self.cases.get_by_id(req.case_id)
        inst_id = case.installation_id if case else "default"

        # Decrypt from the separated vault
        if hasattr(self.vault_repo, "consume_reveal"):
            plaintext = self.vault_repo.consume_reveal(
                installation_id=inst_id,
                pseudonym=req.pseudonym,
                request_id=req.id,
                requester_subject=principal.subject,
                reveal_token=getattr(req, "reveal_token", None),
            )
        else:
            plaintext = self.vault_repo.retrieve_and_decrypt(req.pseudonym, installation_id=inst_id)

        if plaintext is None:
            # If vault retrieval fails, do NOT mark consumed!
            raise LookupError(f"Pseudonym '{req.pseudonym}' could not be resolved in the identity vault")

        # Atomically mark as consumed
        req.status = "used"
        req.used_at = now

        # Audit consumption: NEVER log the plaintext identity!
        append_audit(
            self.db,
            installation_id=inst_id,
            actor_subject=principal.subject,
            actor_role="investigator",
            action="reveal_consumed",
            target_type="reveal_request",
            target_id=req.id,
            safe_metadata={
                "case_id": req.case_id,
                "pseudonym": req.pseudonym,
            },
        )
        self.db.commit()
        return plaintext
