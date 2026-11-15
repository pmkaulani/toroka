"""API router for cross-system fraud intelligence, temporal correlation, and investigation hypotheses."""
from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from toroka_enterprise.intelligence.hypotheses import HypothesisStatus, InvestigationHypothesis
from toroka_enterprise.intelligence.investigation import InvestigationBundle
from toroka_enterprise.intelligence.summary import summarize

from ..auth import EnterprisePrincipal, get_current_principal, require_roles
from ..dependencies import get_db, get_installation_id
from ..intelligence_schemas import (
    CorrelateCaseRequest,
    CorrelateCaseResponse,
    CorrelationSignalResponse,
    IntelligenceEventResponse,
    InvestigationBundleResponse,
    InvestigationHypothesisRequest,
    InvestigationHypothesisResponse,
    InvestigationSummaryResponse,
    RelationshipResponse,
)
from ..permissions import (
    BANK_ROLES,
    ROLE_AUDITOR,
    ROLE_AUTHORISER,
    ROLE_INVESTIGATOR,
    ROLE_SYSTEM_ADMINISTRATOR,
)
from ..services.intelligence import IntelligenceService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/enterprise/v1/intelligence",
    tags=["Enterprise Fraud Intelligence"],
)


@router.post(
    "/cases/{case_id}/correlate",
    response_model=CorrelateCaseResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER, ROLE_SYSTEM_ADMINISTRATOR))],
)
def correlate_case_events(
    case_id: str,
    payload: CorrelateCaseRequest = CorrelateCaseRequest(),
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """Execute temporal cross-system correlation against events for a case."""
    svc = IntelligenceService(db, installation_id)
    try:
        bundle, bundle_rec = svc.correlate_case(
            case_id=case_id,
            before_minutes=payload.window_before_minutes,
            after_minutes=payload.window_after_minutes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

    signals_resp = [
        CorrelationSignalResponse(
            signal_id=s.signal_id,
            signal_type=s.signal_type,
            severity=s.severity.value,
            title=s.title,
            explanation=s.explanation,
            event_ids=list(s.event_ids),
            confidence=s.confidence,
            evidence=[dict(e) for e in s.evidence],
            alternative_explanations=list(s.alternative_explanations),
            missing_evidence=list(s.missing_evidence),
        )
        for s in bundle.signals
    ]

    return CorrelateCaseResponse(
        case_id=case_id,
        events_evaluated=len(bundle.events),
        signals_detected=len(bundle.signals),
        signals=signals_resp,
        investigation_bundle_id=bundle_rec.investigation_id,
    )


@router.get(
    "/cases/{case_id}/investigation",
    response_model=InvestigationBundleResponse,
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
def get_case_investigation_bundle(
    case_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """Retrieve the structured investigation bundle for a case."""
    svc = IntelligenceService(db, installation_id)
    bundle_rec = svc.get_investigation_bundle(case_id)
    if not bundle_rec:
        # Trigger an initial correlation to construct the bundle
        try:
            bundle, bundle_rec = svc.correlate_case(case_id=case_id)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

    b_json = bundle_rec.bundle_json or {}

    events_resp = [
        IntelligenceEventResponse(
            event_id=e["event_id"],
            installation_id=e["installation_id"],
            event_type=e["event_type"],
            event_time=e["event_time"],
            actor=e.get("actor"),
            subject=e.get("subject"),
            source_system=e.get("source_system"),
            source_record_id=e.get("source_record_id"),
            entities=e.get("entities", []),
            attributes=e.get("attributes", {}),
            provenance_digest=e.get("provenance_digest"),
        )
        for e in b_json.get("events", [])
    ]

    relationships_resp = [
        RelationshipResponse(
            id=r.get("id"),
            installation_id=r["installation_id"],
            source_type=r["source"]["entity_type"],
            source_id=r["source"]["entity_id"],
            target_type=r["target"]["entity_type"],
            target_id=r["target"]["entity_id"],
            relationship_type=r["relationship_type"],
            first_seen=r.get("first_seen"),
            last_seen=r.get("last_seen"),
            confidence=r["confidence"],
            source_system=r.get("source_system"),
            source_record_id=r.get("source_record_id"),
            attributes=r.get("attributes", {}),
        )
        for r in b_json.get("relationships", [])
    ]

    signals_resp = [
        CorrelationSignalResponse(
            signal_id=s["signal_id"],
            signal_type=s["signal_type"],
            severity=s["severity"],
            title=s["title"],
            explanation=s["explanation"],
            event_ids=s["event_ids"],
            confidence=s["confidence"],
            evidence=s.get("evidence", []),
            alternative_explanations=s.get("alternative_explanations", []),
            missing_evidence=s.get("missing_evidence", []),
        )
        for s in b_json.get("signals", [])
    ]

    hypotheses_resp = [
        InvestigationHypothesisResponse(
            hypothesis_id=h["hypothesis_id"],
            installation_id=installation_id,
            case_id=case_id,
            title=h["title"],
            description=h["description"],
            status=h["status"],
            supporting_signal_ids=h.get("supporting_signal_ids", []),
            contradicting_signal_ids=h.get("contradicting_signal_ids", []),
            confidence=h.get("confidence", 0.0),
            investigator_note=h.get("investigator_note"),
            created_at=bundle_rec.created_at,
            updated_at=bundle_rec.updated_at,
        )
        for h in b_json.get("hypotheses", [])
    ]

    # Reconstruct summary
    alt_exps: list[str] = []
    missing_evs: list[str] = []
    facts: list[str] = []
    for s in signals_resp:
        facts.append(s.title)
        alt_exps.extend(s.alternative_explanations)
        missing_evs.extend(s.missing_evidence)

    summary_resp = InvestigationSummaryResponse(
        finding=bundle_rec.finding,
        confidence=bundle_rec.confidence,
        supporting_facts=list(dict.fromkeys(facts)),
        alternative_explanations=list(dict.fromkeys(alt_exps)),
        missing_evidence=list(dict.fromkeys(missing_evs)),
        requires_human_review=bundle_rec.requires_human_review,
    )

    return InvestigationBundleResponse(
        investigation_id=bundle_rec.investigation_id,
        installation_id=bundle_rec.installation_id,
        case_id=bundle_rec.case_id,
        anchor_event_ids=bundle_rec.anchor_event_ids or [],
        events=events_resp,
        relationships=relationships_resp,
        signals=signals_resp,
        hypotheses=hypotheses_resp,
        missing_evidence=summary_resp.missing_evidence,
        summary=summary_resp,
        created_at=bundle_rec.created_at,
    )


@router.post(
    "/cases/{case_id}/hypotheses",
    response_model=InvestigationHypothesisResponse,
    dependencies=[Depends(require_roles(ROLE_INVESTIGATOR, ROLE_AUTHORISER))],
)
def save_case_hypothesis(
    case_id: str,
    payload: InvestigationHypothesisRequest,
    principal: EnterprisePrincipal = Depends(get_current_principal),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """Add or update an investigation hypothesis testing competing explanations."""
    svc = IntelligenceService(db, installation_id)
    try:
        status_enum = HypothesisStatus(payload.status)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid hypothesis status '{payload.status}'. Valid: open, supported, weakened, disproven",
        )

    hypo = InvestigationHypothesis(
        hypothesis_id=payload.hypothesis_id,
        title=payload.title,
        description=payload.description,
        status=status_enum,
        supporting_signal_ids=tuple(payload.supporting_signal_ids),
        contradicting_signal_ids=tuple(payload.contradicting_signal_ids),
        confidence=payload.confidence,
        investigator_note=payload.investigator_note,
    )

    try:
        rec = svc.save_hypothesis(case_id, hypo)
        db.commit()
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return InvestigationHypothesisResponse(
        hypothesis_id=rec.hypothesis_id,
        installation_id=rec.installation_id,
        case_id=rec.case_id,
        title=rec.title,
        description=rec.description,
        status=rec.status,
        supporting_signal_ids=rec.supporting_signal_ids or [],
        contradicting_signal_ids=rec.contradicting_signal_ids or [],
        confidence=rec.confidence,
        investigator_note=rec.investigator_note,
        created_at=rec.created_at,
        updated_at=rec.updated_at,
    )


@router.get(
    "/cases/{case_id}/hypotheses",
    response_model=list[InvestigationHypothesisResponse],
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
def list_case_hypotheses(
    case_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """List all hypotheses testing competing explanations for a case."""
    svc = IntelligenceService(db, installation_id)
    recs = svc.list_hypotheses(case_id)
    return [
        InvestigationHypothesisResponse(
            hypothesis_id=r.hypothesis_id,
            installation_id=r.installation_id,
            case_id=r.case_id,
            title=r.title,
            description=r.description,
            status=r.status,
            supporting_signal_ids=r.supporting_signal_ids or [],
            contradicting_signal_ids=r.contradicting_signal_ids or [],
            confidence=r.confidence,
            investigator_note=r.investigator_note,
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in recs
    ]


@router.get(
    "/cases/{case_id}/relationships",
    response_model=list[RelationshipResponse],
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
def get_case_relationships(
    case_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """Retrieve entity relationships (employee, account, device, session) relevant to the case."""
    svc = IntelligenceService(db, installation_id)
    recs = svc.get_case_relationships(case_id)
    return [
        RelationshipResponse(
            id=r.id,
            installation_id=r.installation_id,
            source_type=r.source_type,
            source_id=r.source_id,
            target_type=r.target_type,
            target_id=r.target_id,
            relationship_type=r.relationship_type,
            first_seen=r.first_seen,
            last_seen=r.last_seen,
            confidence=r.confidence,
            source_system=r.source_system,
            source_record_id=r.source_record_id,
            attributes=r.attributes or {},
        )
        for r in recs
    ]


@router.get(
    "/cases/{case_id}/timeline",
    response_model=list[IntelligenceEventResponse],
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
def get_case_timeline(
    case_id: str,
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """Chronologically order events linked to entities in the case."""
    svc = IntelligenceService(db, installation_id)
    recs = svc.get_case_timeline(case_id)
    return [
        IntelligenceEventResponse(
            event_id=r.event_id,
            installation_id=r.installation_id,
            event_type=r.event_type,
            event_time=r.event_time,
            actor=r.actor,
            subject=r.subject,
            source_system=r.source_system,
            source_record_id=r.source_record_id,
            entities=r.entities or [],
            attributes=r.attributes or {},
            provenance_digest=r.provenance_digest,
        )
        for r in recs
    ]


@router.get(
    "/signals",
    response_model=list[CorrelationSignalResponse],
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
def list_correlation_signals(
    limit: int = Query(default=50, ge=1, le=200),
    installation_id: str = Depends(get_installation_id),
    db: Session = Depends(get_db),
):
    """List cross-system correlation signals across the installation."""
    svc = IntelligenceService(db, installation_id)
    recs = svc.list_signals(limit=limit)
    return [
        CorrelationSignalResponse(
            signal_id=r.signal_id,
            signal_type=r.signal_type,
            severity=r.severity,
            title=r.title,
            explanation=r.explanation,
            event_ids=r.event_ids or [],
            confidence=r.confidence,
            evidence=r.evidence or [],
            alternative_explanations=r.alternative_explanations or [],
            missing_evidence=r.missing_evidence or [],
            created_at=r.created_at,
        )
        for r in recs
    ]
