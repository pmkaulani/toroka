"""FastAPI routes for Toroka Phase 5 (multimodal fusion) and Phase 6 (advanced forensics)."""
from __future__ import annotations

import logging
from typing import Any
from fastapi import APIRouter, HTTPException, Path
from pydantic import BaseModel, Field

from toroka_phase5 import Phase5Investigator, ArtifactInput, ConversationMessage
from toroka_phase6 import Phase6Investigator

logger = logging.getLogger("toroka.investigations")

router = APIRouter(prefix="/v1/investigations", tags=["advanced-investigations"])
phase5_investigator = Phase5Investigator()
phase6_investigator = Phase6Investigator()


class ArtifactIn(BaseModel):
    artifact_ref: str = Field(min_length=8, max_length=80)
    artifact_type: str = Field(default="message")
    extracted_text: str = Field(default="", max_length=50000)
    source_group: str = Field(default="user_submitted_artifact")
    language: str = Field(default="undetermined", max_length=24)
    observed_at: str | None = None
    extraction_method: str = Field(default="host_ocr_or_text_extractor")


class ExpectedPaymentIn(BaseModel):
    amount: str | None = None
    recipient_identifier: str | None = None
    recipient_name: str | None = None


class ConversationMsgIn(BaseModel):
    role: str
    text: str


class MultimodalAnalysisIn(BaseModel):
    artifacts: list[ArtifactIn] = Field(min_length=1, max_length=30)
    expected_payment: ExpectedPaymentIn | None = None
    conversation: list[ConversationMsgIn] | None = None
    phase4_results: list[dict[str, Any]] | None = None
    phase3_relationships: list[dict[str, Any]] | None = None


class Phase6AnalysisIn(BaseModel):
    website_snapshot: dict[str, Any] | None = None
    social_observations: list[dict[str, Any]] | None = None
    image_artifacts: list[dict[str, Any]] | None = None
    audio_transcripts: list[dict[str, Any]] | None = None
    business_checks: list[dict[str, Any]] | None = None


def _to_dict(model_instance: Any) -> dict[str, Any]:
    if hasattr(model_instance, "model_dump"):
        return model_instance.model_dump()
    if hasattr(model_instance, "dict"):
        return model_instance.dict()
    return {}


@router.post("/{case_ref}/multimodal-analysis")
def analyze_multimodal(
    case_ref: str = Path(..., min_length=8, max_length=80),
    body: MultimodalAnalysisIn = ...,
):
    try:
        norm_artifacts = [
            ArtifactInput(
                artifact_ref=a.artifact_ref,
                artifact_type=a.artifact_type,
                extracted_text=a.extracted_text,
                source_group=a.source_group,
                language=a.language,
                observed_at=a.observed_at,
                extraction_method=a.extraction_method,
            )
            for a in body.artifacts
        ]
        conv = (
            [ConversationMessage(role=m.role, text=m.text) for m in body.conversation]
            if body.conversation
            else None
        )
        exp = _to_dict(body.expected_payment) if body.expected_payment else None
        res = phase5_investigator.investigate(
            case_ref=case_ref,
            artifacts=norm_artifacts,
            phase4_results=body.phase4_results,
            phase3_relationships=body.phase3_relationships,
            expected_payment=exp,
            conversation=conv,
        )
        return res.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"Multimodal analysis error for {case_ref}: {e}")
        raise HTTPException(status_code=500, detail="Internal analysis error")


@router.post("/{case_ref}/phase6")
def analyze_phase6(
    case_ref: str = Path(..., min_length=8, max_length=80),
    body: Phase6AnalysisIn = ...,
):
    try:
        norm_images = None
        if body.image_artifacts is not None:
            norm_images = []
            for img in body.image_artifacts:
                img_copy = dict(img)
                b = img_copy.get("bytes")
                if isinstance(b, str):
                    try:
                        import base64
                        img_copy["bytes"] = base64.b64decode(b)
                    except Exception:
                        img_copy["bytes"] = b.encode("utf-8")
                elif not b and "base64" in img_copy:
                    import base64
                    img_copy["bytes"] = base64.b64decode(img_copy["base64"])
                norm_images.append(img_copy)

        res = phase6_investigator.investigate(
            case_ref=case_ref,
            website_snapshot=body.website_snapshot,
            social_observations=body.social_observations,
            image_artifacts=norm_images,
            audio_transcripts=body.audio_transcripts,
            business_checks=body.business_checks,
        )
        return res.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception(f"Phase 6 analysis error for {case_ref}: {e}")
        raise HTTPException(status_code=500, detail="Internal forensic analysis error")
