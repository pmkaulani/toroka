"""Build 4: moderator-only fraud-campaign review queue."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db as m
from .deps import Ctx, audit, ctx, get_db, require_role, throttle
from .ratelimit import RateLimiter
from toroka_build4.campaigns import moderation_campaign_candidates

router = APIRouter(tags=["build-4-campaign-intelligence"])
MOD = require_role("moderator", "admin")


class CampaignReviewIn(BaseModel):
    status: str = Field(pattern=r"^(under_review|confirmed_coordinated|not_coordinated|insufficient_evidence)$")
    reason_code: str = Field(min_length=3, max_length=40)
    notes: str | None = Field(default=None, max_length=1200)


@router.get("/v1/moderation/build4/campaigns")
def get_campaign_candidates(
    request: Request,
    limit: int = 50,
    db: Session = Depends(get_db),
    c: Ctx = Depends(ctx),
    moderator: m.User = Depends(MOD),
):
    throttle(request, c, "build4_campaign_queue", (30, 3600), moderator.id)
    campaigns = moderation_campaign_candidates(db, limit=limit)
    # Moderator-only disclosure of prior review notes. Notes remain encrypted at rest.
    review_rows = {row.campaign_id: row for row in db.execute(select(m.CampaignReview)).scalars()}
    for item in campaigns:
        review = review_rows.get(item["campaign_id"])
        if review and review.notes_encrypted:
            try:
                item["review"]["notes"] = c.crypto.dec(review.notes_encrypted)
            except Exception:
                item["review"]["notes"] = "Stored review notes could not be decrypted."
    audit(db, request, moderator.id, "build4.campaign_queue.read", "campaign", None, {"count": len(campaigns)})
    db.commit()
    return {
        "campaigns": campaigns,
        "interpretation_note": "These are investigative candidates, not findings of wrongdoing. Similar messages, shared payment identifiers or reused images can have legitimate explanations. Each underlying report and source must be assessed independently.",
    }


@router.post("/v1/moderation/build4/campaigns/{campaign_id}/review")
def review_campaign_candidate(
    campaign_id: str,
    body: CampaignReviewIn,
    request: Request,
    db: Session = Depends(get_db),
    c: Ctx = Depends(ctx),
    moderator: m.User = Depends(MOD),
):
    throttle(request, c, "build4_campaign_review", (60, 3600), moderator.id)
    candidate = next((item for item in moderation_campaign_candidates(db, limit=100) if item["campaign_id"] == campaign_id), None)
    if not candidate:
        raise HTTPException(404, "Campaign candidate not found or no longer present in the current review window.")
    record = db.execute(select(m.CampaignReview).where(m.CampaignReview.campaign_id == campaign_id)).scalar_one_or_none()
    if record is None:
        record = m.CampaignReview(campaign_id=campaign_id, campaign_type=candidate["campaign_type"], reviewer_id=moderator.id)
        db.add(record)
    record.campaign_type = candidate["campaign_type"]
    record.status = body.status
    record.reason_code = body.reason_code
    record.notes_encrypted = c.crypto.enc(body.notes.strip()) if body.notes and body.notes.strip() else None
    record.reviewer_id = moderator.id
    record.reviewed_at = m.now_iso()
    db.add(m.ModerationAction(
        moderator_id=moderator.id,
        target_type="campaign",
        target_id=campaign_id,
        action="build4_campaign_review",
        reason_code=body.reason_code,
        notes="Detailed notes stored in the encrypted campaign review record." if body.notes and body.notes.strip() else "",
    ))
    audit(db, request, moderator.id, "build4.campaign.review", "campaign", campaign_id,
          {"status": body.status, "campaign_type": candidate["campaign_type"], "reason_code": body.reason_code})
    db.commit()
    return {"campaign_id": campaign_id, "status": record.status, "reviewed_at": record.reviewed_at,
            "note": "This is an internal moderation disposition. It does not automatically change any seller's or identifier's public risk status."}

@router.get("/v1/moderation/build4/reports/{report_id}")
def get_campaign_report(
    report_id: str,
    request: Request,
    db: Session = Depends(get_db),
    c: Ctx = Depends(ctx),
    moderator: m.User = Depends(MOD),
):
    """Audited moderator-only access to the original report behind a campaign lead."""
    throttle(request, c, "build4_campaign_report_detail", (60, 3600), moderator.id)
    report = db.get(m.Report, report_id)
    if not report:
        raise HTTPException(404, "Report not found.")
    try:
        narrative = c.crypto.dec(report.narrative_encrypted)
    except Exception:
        raise HTTPException(410, "The report content is no longer available.")
    identifiers = db.execute(
        select(m.Subject.subject_type, m.Subject.display_masked)
        .join(m.ReportSubject, m.ReportSubject.subject_id == m.Subject.id)
        .where(m.ReportSubject.report_id == report.id)
    ).all()
    audit(db, request, moderator.id, "build4.campaign_report.read", "report", report.id,
          {"moderation_status": report.moderation_status, "category": report.category})
    db.commit()
    return {
        "report_id": report.id,
        "category": report.category,
        "moderation_status": report.moderation_status,
        "created_at": report.created_at,
        "incident_date": report.incident_date,
        "amount_band": report.amount_band,
        "narrative": narrative,
        "identifiers": [{"kind": kind, "masked_value": masked} for kind, masked in identifiers],
        "publication_scope": report.publication_scope,
        "note": "This is a private report shown to an authorized moderator. It is an allegation to assess, not a verified finding."
    }

