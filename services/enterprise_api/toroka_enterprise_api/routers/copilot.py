from __future__ import annotations

from typing import Any
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from ..auth import EnterprisePrincipal, get_current_principal, require_roles
from ..copilot_schemas import (
    CopilotFeedbackResponse,
    CopilotMessageResponse,
    CopilotReportDraftResponse,
    CopilotStatusResponse,
    CopilotThreadResponse,
    CreateCopilotThreadRequest,
    GenerateReportDraftRequest,
    ReviewReportDraftRequest,
    SendCopilotMessageRequest,
    SubmitCopilotFeedbackRequest,
    UpdateReportDraftRequest,
)
from ..dependencies import get_db, get_installation_id
from ..permissions import (
    ROLE_AUDITOR,
    ROLE_AUTHORISER,
    ROLE_INVESTIGATOR,
    ROLE_SYSTEM_ADMINISTRATOR,
)
from ..services.copilot import CopilotService

router = APIRouter(prefix="/api/enterprise/v1/copilot", tags=["AI Investigation Copilot"])


def _primary_role(principal: EnterprisePrincipal) -> str:
    return sorted(principal.roles)[0] if principal.roles else "investigator"


@router.get("/status", response_model=CopilotStatusResponse)
def get_copilot_status(
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> CopilotStatusResponse:
    """Returns AI Copilot engine status, provider availability, and tool allowlist."""
    effective_inst = principal.installation_id or installation_id
    service = CopilotService(db, effective_inst)
    return service.get_service_status()


@router.post(
    "/threads",
    response_model=CopilotThreadResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def create_copilot_thread(
    request: CreateCopilotThreadRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> CopilotThreadResponse:
    """Creates a new investigation conversation thread scoped to an authorized case."""
    effective_inst = principal.installation_id or installation_id
    service = CopilotService(db, effective_inst)
    return service.create_thread(request, actor_subject=principal.subject)


@router.get(
    "/threads",
    response_model=list[CopilotThreadResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def list_copilot_threads(
    case_id: str = Query(..., description="Target case ID"),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[CopilotThreadResponse]:
    """Lists all active Copilot conversation threads for the specified case."""
    effective_inst = principal.installation_id or installation_id
    service = CopilotService(db, effective_inst)
    return service.list_threads(case_id=case_id)


@router.get(
    "/threads/{thread_id}",
    response_model=CopilotThreadResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def get_copilot_thread(
    thread_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> CopilotThreadResponse:
    """Retrieves metadata for a specific Copilot thread."""
    effective_inst = principal.installation_id or installation_id
    service = CopilotService(db, effective_inst)
    return service.get_thread(thread_id)


@router.delete(
    "/threads/{thread_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def archive_copilot_thread(
    thread_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> None:
    """Archives a Copilot conversation thread."""
    effective_inst = principal.installation_id or installation_id
    service = CopilotService(db, effective_inst)
    service.archive_thread(thread_id, actor_subject=principal.subject)


@router.post(
    "/threads/{thread_id}/messages",
    response_model=CopilotMessageResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def send_copilot_message(
    thread_id: str,
    request: SendCopilotMessageRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> CopilotMessageResponse:
    """Sends an investigator question, executes bounded tools, and returns a grounded response."""
    effective_inst = principal.installation_id or installation_id
    service = CopilotService(db, effective_inst)
    return service.send_message(
        thread_id=thread_id,
        content=request.content,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


@router.get(
    "/threads/{thread_id}/messages",
    response_model=list[CopilotMessageResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def list_copilot_messages(
    thread_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[CopilotMessageResponse]:
    """Retrieves all messages and grounded claim breakdowns for a thread."""
    effective_inst = principal.installation_id or installation_id
    service = CopilotService(db, effective_inst)
    return service.list_messages(thread_id)


@router.get(
    "/messages/{message_id}/citations",
    response_model=list[dict[str, Any]],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def get_message_citations(
    message_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    """Retrieves full citation excerpts and evidence IDs for a specific Copilot message."""
    effective_inst = principal.installation_id or installation_id
    service = CopilotService(db, effective_inst)
    return service.get_citations(message_id)


# =============================================================================
# Report Drafting Endpoints
# =============================================================================

@router.post(
    "/reports/generate",
    response_model=CopilotReportDraftResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def generate_report_draft(
    request: GenerateReportDraftRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> CopilotReportDraftResponse:
    """Generates an evidence-grounded report draft for investigator review."""
    effective_inst = principal.installation_id or installation_id
    service = CopilotService(db, effective_inst)
    return service.generate_report_draft(request, actor_subject=principal.subject, actor_role=_primary_role(principal))


@router.get(
    "/reports",
    response_model=list[CopilotReportDraftResponse],
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def list_report_drafts(
    case_id: str = Query(..., description="Target case ID"),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> list[CopilotReportDraftResponse]:
    """Lists all report drafts and review states for a case."""
    effective_inst = principal.installation_id or installation_id
    service = CopilotService(db, effective_inst)
    return service.list_report_drafts(case_id)


@router.get(
    "/reports/{draft_id}",
    response_model=CopilotReportDraftResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def get_report_draft(
    draft_id: str,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> CopilotReportDraftResponse:
    """Retrieves a single report draft by ID."""
    effective_inst = principal.installation_id or installation_id
    service = CopilotService(db, effective_inst)
    return service.get_report_draft(draft_id)


@router.put(
    "/reports/{draft_id}",
    response_model=CopilotReportDraftResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def update_report_draft(
    draft_id: str,
    request: UpdateReportDraftRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> CopilotReportDraftResponse:
    """Saves human investigator edits to an AI-drafted report."""
    effective_inst = principal.installation_id or installation_id
    service = CopilotService(db, effective_inst)
    return service.update_report_draft(
        draft_id=draft_id,
        investigator_edits_markdown=request.investigator_edits_markdown,
        actor_subject=principal.subject,
    )


@router.post(
    "/reports/{draft_id}/review",
    response_model=CopilotReportDraftResponse,
    dependencies=[Depends(require_roles(ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def review_report_draft(
    draft_id: str,
    request: ReviewReportDraftRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> CopilotReportDraftResponse:
    """Human investigator review: Accepts or rejects a drafted report with review rationale."""
    effective_inst = principal.installation_id or installation_id
    service = CopilotService(db, effective_inst)
    return service.review_report_draft(
        draft_id=draft_id,
        decision=request.decision,
        notes=request.notes,
        actor_subject=principal.subject,
        actor_role=_primary_role(principal),
    )


# =============================================================================
# Feedback
# =============================================================================

@router.post(
    "/messages/{message_id}/feedback",
    response_model=CopilotFeedbackResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_AUDITOR, ROLE_SYSTEM_ADMINISTRATOR))],
)
def submit_copilot_feedback(
    message_id: str,
    request: SubmitCopilotFeedbackRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
) -> CopilotFeedbackResponse:
    """Submits quality feedback on a Copilot answer."""
    effective_inst = principal.installation_id or installation_id
    service = CopilotService(db, effective_inst)
    return service.submit_feedback(
        message_id=message_id,
        rating=request.rating,
        feedback_text=request.feedback_text,
        actor_subject=principal.subject,
    )
