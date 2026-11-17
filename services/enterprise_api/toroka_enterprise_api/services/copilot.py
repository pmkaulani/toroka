from __future__ import annotations

import hashlib
import hmac
import logging
import uuid
from datetime import datetime, timezone
from typing import Any
from fastapi import HTTPException
from sqlalchemy import select, and_, desc
from sqlalchemy.orm import Session

from toroka_enterprise.intelligence.copilot.contracts import (
    ClaimKind,
    CopilotTaskType,
    ReportDraftStatus,
)
from toroka_enterprise.intelligence.copilot.grounding import (
    evidence_context_from_snapshot,
    validate_report_markdown,
)
from toroka_enterprise.intelligence.copilot.tool_policy import (
    ALLOWED_TOOLS,
)
from toroka_enterprise.intelligence.models import (
    CopilotFeedbackRecord,
    CopilotMessageRecord,
    CopilotReportDraftRecord,
    CopilotThreadRecord,
)
from ..copilot.orchestrator import CopilotOrchestrator
from ..copilot.provider import get_copilot_provider
from ..copilot_schemas import (
    CopilotFeedbackResponse,
    CopilotMessageResponse,
    CopilotReportDraftResponse,
    CopilotStatusResponse,
    CopilotThreadResponse,
    CreateCopilotThreadRequest,
    GenerateReportDraftRequest,
    GroundedClaimResponse,
    GroundingReportResponse,
)
from ..persistence.audit import append_audit
from ..persistence.models import EnterpriseCase

logger = logging.getLogger(__name__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CopilotService:
    """Operational service for AI Investigation Copilot conversations, drafts, and audits."""

    def __init__(self, session: Session, installation_id: str) -> None:
        self.session = session
        self.installation_id = installation_id
        self.provider = get_copilot_provider()
        self.orchestrator = CopilotOrchestrator(session, installation_id, self.provider)

    def _verify_case(self, case_id: str) -> EnterpriseCase:
        stmt = select(EnterpriseCase).where(
            and_(
                EnterpriseCase.id == case_id,
                EnterpriseCase.installation_id == self.installation_id,
            )
        )
        case = self.session.execute(stmt).scalar_one_or_none()
        if not case:
            raise HTTPException(
                status_code=404,
                detail=f"Case '{case_id}' not found or not in installation '{self.installation_id}'",
            )
        return case

    # =========================================================================
    # Threads
    # =========================================================================

    def create_thread(
        self,
        request: CreateCopilotThreadRequest,
        actor_subject: str,
    ) -> CopilotThreadResponse:
        self._verify_case(request.case_id)

        now = _utc_now()
        thread_id = f"thread_{uuid.uuid4().hex[:12]}"
        thread = CopilotThreadRecord(
            thread_id=thread_id,
            installation_id=self.installation_id,
            case_id=request.case_id,
            title=request.title,
            created_by=actor_subject,
            is_archived=False,
            created_at=now,
            updated_at=now,
        )
        self.session.add(thread)
        self.session.commit()

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role="investigator",
            action="create_copilot_thread",
            target_type="copilot_thread",
            target_id=thread_id,
            safe_metadata={
                "thread_id": thread_id,
                "case_id": request.case_id,
            },
        )
        self.session.commit()

        return self._to_thread_response(thread)

    def list_threads(self, case_id: str) -> list[CopilotThreadResponse]:
        self._verify_case(case_id)
        stmt = select(CopilotThreadRecord).where(
            and_(
                CopilotThreadRecord.installation_id == self.installation_id,
                CopilotThreadRecord.case_id == case_id,
                CopilotThreadRecord.is_archived.is_(False),
            )
        ).order_by(desc(CopilotThreadRecord.updated_at))

        records = list(self.session.execute(stmt).scalars().all())
        return [self._to_thread_response(r) for r in records]

    def get_thread(self, thread_id: str) -> CopilotThreadResponse:
        stmt = select(CopilotThreadRecord).where(
            and_(
                CopilotThreadRecord.thread_id == thread_id,
                CopilotThreadRecord.installation_id == self.installation_id,
            )
        )
        thread = self.session.execute(stmt).scalar_one_or_none()
        if not thread:
            raise HTTPException(status_code=404, detail=f"Thread '{thread_id}' not found")
        return self._to_thread_response(thread)

    def archive_thread(self, thread_id: str, actor_subject: str) -> None:
        stmt = select(CopilotThreadRecord).where(
            and_(
                CopilotThreadRecord.thread_id == thread_id,
                CopilotThreadRecord.installation_id == self.installation_id,
            )
        )
        thread = self.session.execute(stmt).scalar_one_or_none()
        if not thread:
            raise HTTPException(status_code=404, detail=f"Thread '{thread_id}' not found")

        thread.is_archived = True
        thread.updated_at = _utc_now()
        self.session.commit()

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role="investigator",
            action="archive_copilot_thread",
            target_type="copilot_thread",
            target_id=thread_id,
            safe_metadata={"thread_id": thread_id, "case_id": thread.case_id},
        )
        self.session.commit()

    # =========================================================================
    # Messages & Turns
    # =========================================================================

    def send_message(
        self,
        thread_id: str,
        content: str,
        actor_subject: str,
        actor_role: str,
    ) -> CopilotMessageResponse:
        thread = self.session.execute(
            select(CopilotThreadRecord).where(
                and_(
                    CopilotThreadRecord.thread_id == thread_id,
                    CopilotThreadRecord.installation_id == self.installation_id,
                )
            )
        ).scalar_one_or_none()
        if not thread:
            raise HTTPException(status_code=404, detail=f"Thread '{thread_id}' not found")

        # 1. Record investigator question
        now = _utc_now()
        user_msg_id = f"msg_{uuid.uuid4().hex[:12]}"
        user_msg = CopilotMessageRecord(
            message_id=user_msg_id,
            thread_id=thread_id,
            installation_id=self.installation_id,
            case_id=thread.case_id,
            role="user",
            content=content,
            task_type=None,
            claims=[],
            citations=[],
            tool_calls=[],
            grounding_report={},
            created_at=now,
        )
        self.session.add(user_msg)
        self.session.commit()

        # 2. Run investigation turn via orchestrator
        copilot_resp = self.orchestrator.run_investigation_turn(
            case_id=thread.case_id,
            user_prompt=content,
            actor_subject=actor_subject,
            actor_role=actor_role,
            thread_id=thread_id,
        )

        # 3. Format claims & citations for persistence
        claims_json = [
            {
                "claim_id": c.claim_id,
                "kind": c.kind.value,
                "statement": c.statement,
                "evidence_ids": list(c.evidence_ids),
                "quotes": [{"evidence_id": q.evidence_id, "quoted_text": q.quoted_text} for q in c.quotes],
                "limitations": c.limitations,
                "investigative_basis": c.investigative_basis,
                "alternative_explanations": list(c.alternative_explanations),
            }
            for c in copilot_resp.claims
        ]

        citations_json: list[dict[str, Any]] = []
        for c in copilot_resp.claims:
            for q in c.quotes:
                citations_json.append({"evidence_id": q.evidence_id, "quoted_text": q.quoted_text})

        grounding_json = {}
        if copilot_resp.grounding_report:
            grounding_json = {
                "valid": copilot_resp.grounding_report.valid,
                "verified_claims": copilot_resp.grounding_report.verified_claims,
                "rejected_claims": list(copilot_resp.grounding_report.rejected_claims),
                "rejection_reasons": list(copilot_resp.grounding_report.rejection_reasons),
            }

        asst_msg_id = f"msg_{uuid.uuid4().hex[:12]}"
        asst_msg = CopilotMessageRecord(
            message_id=asst_msg_id,
            thread_id=thread_id,
            installation_id=self.installation_id,
            case_id=thread.case_id,
            role="assistant",
            content=copilot_resp.summary,
            task_type=copilot_resp.task_type.value,
            claims=claims_json,
            citations=citations_json,
            tool_calls=list(copilot_resp.tool_calls_executed),
            grounding_report=grounding_json,
            created_at=_utc_now(),
        )
        self.session.add(asst_msg)

        thread.updated_at = _utc_now()
        self.session.commit()

        # Audit Copilot investigation turn
        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="copilot_investigation_turn",
            target_type="copilot_message",
            target_id=asst_msg_id,
            safe_metadata={
                "thread_id": thread_id,
                "message_id": asst_msg_id,
                "case_id": thread.case_id,
                "task_type": copilot_resp.task_type.value,
                "verified_claims": len(claims_json),
                "grounding_valid": str(copilot_resp.grounding_report.valid if copilot_resp.grounding_report else True),
                "requested_provider": copilot_resp.requested_provider,
                "actual_provider": copilot_resp.actual_provider,
                "requested_model": copilot_resp.requested_model,
                "actual_model": copilot_resp.actual_model,
                "fallback_used": copilot_resp.fallback_used,
                "fallback_reason": str(copilot_resp.fallback_reason or ""),
                "is_degraded_mode": copilot_resp.is_degraded_mode,
            },
        )
        self.session.commit()

        return self._to_message_response(asst_msg)

    def list_messages(self, thread_id: str) -> list[CopilotMessageResponse]:
        stmt = select(CopilotMessageRecord).where(
            and_(
                CopilotMessageRecord.thread_id == thread_id,
                CopilotMessageRecord.installation_id == self.installation_id,
            )
        ).order_by(CopilotMessageRecord.created_at)

        recs = list(self.session.execute(stmt).scalars().all())
        return [self._to_message_response(r) for r in recs]

    def get_citations(self, message_id: str) -> list[dict[str, Any]]:
        stmt = select(CopilotMessageRecord).where(
            and_(
                CopilotMessageRecord.message_id == message_id,
                CopilotMessageRecord.installation_id == self.installation_id,
            )
        )
        msg = self.session.execute(stmt).scalar_one_or_none()
        if not msg:
            raise HTTPException(status_code=404, detail="Message not found")
        return list(msg.citations)

    # =========================================================================
    # Report Drafting & Review Governance
    # =========================================================================

    def generate_report_draft(
        self,
        request: GenerateReportDraftRequest,
        actor_subject: str,
        actor_role: str,
    ) -> CopilotReportDraftResponse:
        self._verify_case(request.case_id)

        # Retrieve exact evidence context for the case
        evidence_ctx = self.orchestrator.get_evidence_context(request.case_id)

        # Run turn with DRAFT_REPORT task
        resp = self.orchestrator.run_investigation_turn(
            case_id=request.case_id,
            user_prompt=f"Draft an investigation {request.report_type} report for case {request.case_id}",
            actor_subject=actor_subject,
            actor_role=actor_role,
            thread_id=request.thread_id,
        )

        md = resp.report_draft.content_markdown if resp.report_draft else resp.summary
        citations = [
            {"evidence_id": q.evidence_id, "quoted_text": q.quoted_text}
            for c in resp.claims
            for q in c.quotes
        ]

        # Context hash must be real SHA-256, never a mock fallback
        context_hash = (
            resp.report_draft.evidence_context_hash
            if resp.report_draft and resp.report_draft.evidence_context_hash and len(resp.report_draft.evidence_context_hash) == 64
            else evidence_ctx.context_digest
        )

        snapshot = {
            "installation_id": self.installation_id,
            "case_id": request.case_id,
            "actor_subject": actor_subject,
            "actor_role": actor_role,
            "items": [
                {
                    "evidence_id": item.evidence_id,
                    "source_system": item.source_system,
                    "source_record_id": item.source_record_id,
                    "event_type": item.record_type,
                    "timestamp": item.event_time.isoformat() if item.event_time else None,
                    "excerpt": item.excerpt,
                    "title": item.title,
                }
                for item in evidence_ctx.items
            ],
        }
        content_digest = hashlib.sha256(md.encode("utf-8")).hexdigest()

        draft_id = f"draft_{uuid.uuid4().hex[:12]}"
        now = _utc_now()
        draft = CopilotReportDraftRecord(
            draft_id=draft_id,
            installation_id=self.installation_id,
            case_id=request.case_id,
            thread_id=request.thread_id,
            report_type=request.report_type,
            title=request.title or f"Investigation Report {request.case_id[:8]}",
            content_markdown=md,
            investigator_edits_markdown=None,
            status=ReportDraftStatus.DRAFT.value,
            evidence_context_hash=context_hash,
            citations=citations,
            model_info=resp.provider_info,
            created_by=actor_subject,
            edited_by=None,
            edit_version=0,
            content_digest=content_digest,
            grounding_status="VALID" if getattr(resp, "report_grounded", True) else "REQUIRES_REVIEW",
            grounding_report=getattr(resp.grounding_report, "__dict__", {}) if getattr(resp, "grounding_report", None) else {},
            evidence_context_snapshot=snapshot,
            review_notes=None,
            reviewed_by=None,
            reviewed_at=None,
            created_at=now,
            updated_at=now,
        )
        self.session.add(draft)
        self.session.commit()

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="generate_report_draft",
            target_type="copilot_report_draft",
            target_id=draft_id,
            safe_metadata={
                "draft_id": draft_id,
                "case_id": request.case_id,
                "report_type": request.report_type,
            },
        )
        self.session.commit()

        return self._to_report_draft_response(draft)

    def list_report_drafts(self, case_id: str) -> list[CopilotReportDraftResponse]:
        self._verify_case(case_id)
        stmt = select(CopilotReportDraftRecord).where(
            and_(
                CopilotReportDraftRecord.case_id == case_id,
                CopilotReportDraftRecord.installation_id == self.installation_id,
            )
        ).order_by(desc(CopilotReportDraftRecord.created_at))

        records = list(self.session.execute(stmt).scalars().all())
        return [self._to_report_draft_response(r) for r in records]

    def get_report_draft(self, draft_id: str) -> CopilotReportDraftResponse:
        stmt = select(CopilotReportDraftRecord).where(
            and_(
                CopilotReportDraftRecord.draft_id == draft_id,
                CopilotReportDraftRecord.installation_id == self.installation_id,
            )
        )
        draft = self.session.execute(stmt).scalar_one_or_none()
        if not draft:
            raise HTTPException(status_code=404, detail="Draft not found")
        return self._to_report_draft_response(draft)

    def update_report_draft(
        self,
        draft_id: str,
        investigator_edits_markdown: str,
        actor_subject: str,
    ) -> CopilotReportDraftResponse:
        stmt = select(CopilotReportDraftRecord).where(
            and_(
                CopilotReportDraftRecord.draft_id == draft_id,
                CopilotReportDraftRecord.installation_id == self.installation_id,
            )
        )
        draft = self.session.execute(stmt).scalar_one_or_none()
        if not draft:
            raise HTTPException(status_code=404, detail="Draft not found")

        before_text = draft.investigator_edits_markdown or draft.content_markdown
        before_digest = hashlib.sha256(before_text.encode("utf-8")).hexdigest()

        # Rebuild the exact persisted EvidenceContext from snapshot
        if draft.evidence_context_snapshot:
            context = evidence_context_from_snapshot(draft.evidence_context_snapshot)
        else:
            context = self.orchestrator.get_evidence_context(draft.case_id)

        clean_text, is_valid, grounding_details = validate_report_markdown(
            investigator_edits_markdown,
            context,
        )

        after_digest = hashlib.sha256(clean_text.encode("utf-8")).hexdigest()
        draft.investigator_edits_markdown = clean_text
        draft.edited_by = actor_subject
        draft.edit_version = (draft.edit_version or 0) + 1
        draft.content_digest = after_digest
        draft.grounding_status = "VALID" if is_valid else "REQUIRES_REVIEW"
        draft.grounding_report = grounding_details
        draft.status = "INVESTIGATOR_REVIEW" if is_valid else "GROUNDING_REVIEW_REQUIRED"
        draft.updated_at = _utc_now()

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role="investigator",
            action="copilot_report_edited",
            target_type="copilot_report_draft",
            target_id=draft_id,
            safe_metadata={
                "draft_id": draft_id,
                "case_id": draft.case_id,
                "previous_content_digest": before_digest,
                "content_digest": after_digest,
                "edit_version": draft.edit_version,
                "grounding_status": draft.grounding_status,
            },
        )
        self.session.commit()

        return self._to_report_draft_response(draft)

    def review_report_draft(
        self,
        draft_id: str,
        decision: str,
        notes: str | None,
        actor_subject: str,
        actor_role: str,
    ) -> CopilotReportDraftResponse:
        if decision not in ("ACCEPTED", "REJECTED"):
            raise HTTPException(status_code=400, detail="Decision must be ACCEPTED or REJECTED")

        stmt = select(CopilotReportDraftRecord).where(
            and_(
                CopilotReportDraftRecord.draft_id == draft_id,
                CopilotReportDraftRecord.installation_id == self.installation_id,
            )
        )
        draft = self.session.execute(stmt).scalar_one_or_none()
        if not draft:
            raise HTTPException(status_code=404, detail="Draft not found")

        # Independent maker-checker review enforcement: creator/editor cannot approve own report
        if actor_subject in {draft.created_by, draft.edited_by}:
            raise HTTPException(status_code=403, detail="Report maker/editor cannot approve their own report")

        normalized_role = (actor_role or "").lower()
        if "investigator" in normalized_role and not any(r in normalized_role for r in ("authoriser", "admin", "system_administrator")):
            raise HTTPException(status_code=403, detail="Independent review role required to review or accept reports")

        if draft.status not in ("INVESTIGATOR_REVIEW",):
            raise HTTPException(status_code=409, detail="Report is not ready for independent review")

        if draft.grounding_status != "VALID":
            raise HTTPException(status_code=422, detail="Report grounding must pass before acceptance")

        if decision == "ACCEPTED" and not (notes and notes.strip()):
            raise HTTPException(status_code=422, detail="Acceptance requires a review rationale")

        current_text = draft.investigator_edits_markdown or draft.content_markdown
        current_digest = hashlib.sha256(current_text.encode("utf-8")).hexdigest()
        if draft.content_digest and not hmac.compare_digest(draft.content_digest, current_digest):
            raise HTTPException(status_code=422, detail="Report content digest mismatch; revalidation required")

        now = _utc_now()
        draft.status = decision
        draft.review_notes = notes.strip() if notes else None
        draft.reviewed_by = actor_subject
        draft.reviewed_at = now
        draft.updated_at = now

        append_audit(
            self.session,
            installation_id=self.installation_id,
            actor_subject=actor_subject,
            actor_role=actor_role,
            action="review_report_draft",
            target_type="copilot_report_draft",
            target_id=draft_id,
            safe_metadata={
                "draft_id": draft_id,
                "case_id": draft.case_id,
                "decision": decision,
            },
        )
        self.session.commit()

        return self._to_report_draft_response(draft)

    # =========================================================================
    # Feedback
    # =========================================================================

    def submit_feedback(
        self,
        message_id: str,
        rating: int,
        feedback_text: str | None,
        actor_subject: str,
    ) -> CopilotFeedbackResponse:
        stmt = select(CopilotMessageRecord).where(
            and_(
                CopilotMessageRecord.message_id == message_id,
                CopilotMessageRecord.installation_id == self.installation_id,
            )
        )
        msg = self.session.execute(stmt).scalar_one_or_none()
        if not msg:
            raise HTTPException(status_code=404, detail="Message not found")

        feedback_id = f"fb_{uuid.uuid4().hex[:12]}"
        now = _utc_now()
        rec = CopilotFeedbackRecord(
            feedback_id=feedback_id,
            installation_id=self.installation_id,
            case_id=msg.case_id,
            message_id=message_id,
            rating=rating,
            feedback_text=feedback_text,
            created_by=actor_subject,
            created_at=now,
        )
        self.session.add(rec)
        self.session.commit()

        return CopilotFeedbackResponse(
            feedback_id=rec.feedback_id,
            message_id=rec.message_id,
            rating=rec.rating,
            feedback_text=rec.feedback_text,
            created_by=rec.created_by,
            created_at=rec.created_at.isoformat(),
        )

    # =========================================================================
    # Service Status
    # =========================================================================

    def get_service_status(self) -> CopilotStatusResponse:
        h = self.provider.check_health()
        return CopilotStatusResponse(
            status=h.get("status", "healthy"),
            provider=h.get("provider", "deterministic"),
            model=h.get("model", "toroka-financial-crime-v1"),
            air_gapped=bool(h.get("air_gapped", True)),
            data_retention_verified=bool(h.get("data_retention_verified", True)),
            active_tools_count=len(ALLOWED_TOOLS),
            allowed_tools=sorted(list(ALLOWED_TOOLS)),
        )

    # =========================================================================
    # Helpers
    # =========================================================================

    def _to_thread_response(self, t: CopilotThreadRecord) -> CopilotThreadResponse:
        return CopilotThreadResponse(
            thread_id=t.thread_id,
            installation_id=t.installation_id,
            case_id=t.case_id,
            title=t.title,
            created_by=t.created_by,
            is_archived=t.is_archived,
            created_at=t.created_at.isoformat(),
            updated_at=t.updated_at.isoformat(),
        )

    def _to_message_response(self, m: CopilotMessageRecord) -> CopilotMessageResponse:
        claims: list[GroundedClaimResponse] = []
        for c in m.claims:
            quotes = [
                {"evidence_id": q.get("evidence_id", ""), "quoted_text": q.get("quoted_text", "")}
                for q in c.get("quotes", [])
            ]
            claims.append(
                GroundedClaimResponse(
                    claim_id=c.get("claim_id", ""),
                    kind=c.get("kind", "fact"),
                    statement=c.get("statement", ""),
                    evidence_ids=c.get("evidence_ids", []),
                    quotes=quotes,
                    limitations=c.get("limitations"),
                    investigative_basis=c.get("investigative_basis"),
                    alternative_explanations=c.get("alternative_explanations", []),
                )
            )

        grounding_resp: GroundingReportResponse | None = None
        if m.grounding_report:
            grounding_resp = GroundingReportResponse(
                valid=m.grounding_report.get("valid", True),
                verified_claims=m.grounding_report.get("verified_claims", len(claims)),
                rejected_claims=m.grounding_report.get("rejected_claims", []),
                rejection_reasons=m.grounding_report.get("rejection_reasons", []),
            )

        return CopilotMessageResponse(
            message_id=m.message_id,
            thread_id=m.thread_id,
            installation_id=m.installation_id,
            case_id=m.case_id,
            role=m.role,
            content=m.content,
            task_type=m.task_type,
            claims=claims,
            citations=m.citations,
            tool_calls=m.tool_calls,
            grounding_report=grounding_resp,
            created_at=m.created_at.isoformat(),
        )

    def _to_report_draft_response(self, r: CopilotReportDraftRecord) -> CopilotReportDraftResponse:
        return CopilotReportDraftResponse(
            draft_id=r.draft_id,
            installation_id=r.installation_id,
            case_id=r.case_id,
            thread_id=r.thread_id,
            report_type=r.report_type,
            title=r.title,
            content_markdown=r.content_markdown,
            investigator_edits_markdown=r.investigator_edits_markdown,
            status=r.status,
            evidence_context_hash=r.evidence_context_hash,
            citations=r.citations,
            model_info=r.model_info,
            created_by=r.created_by or "system",
            edited_by=r.edited_by,
            edit_version=r.edit_version or 0,
            content_digest=r.content_digest or "",
            grounding_status=r.grounding_status or "UNVERIFIED",
            grounding_report=r.grounding_report or {},
            review_notes=r.review_notes,
            reviewed_by=r.reviewed_by,
            reviewed_at=r.reviewed_at.isoformat() if r.reviewed_at else None,
            created_at=r.created_at.isoformat(),
            updated_at=r.updated_at.isoformat(),
        )
