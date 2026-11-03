"""FastAPI routes for Toroka Phase 7 (intelligence operations, multilingual signals, and feed health)."""
from __future__ import annotations

import logging
from typing import Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from toroka_phase7 import (
    Phase7Coordinator,
    OperationsStore,
    analyze_message,
    kenya_reference_sources,
)

logger = logging.getLogger("toroka.phase7")

router = APIRouter(prefix="/v1/phase7", tags=["phase7-operations"])

ops_store = OperationsStore(":memory:")
coordinator = Phase7Coordinator(operations_store=ops_store)


class TextAnalysisIn(BaseModel):
    text: str = Field(min_length=1, max_length=10000)


@router.post("/language/analyze")
def analyze_language(body: TextAnalysisIn):
    try:
        # analyze_text never persists raw text and never returns a seller verdict
        res = coordinator.analyze_text(body.text)
        return res
    except Exception as e:
        logger.exception("Error analyzing language in Phase 7")
        raise HTTPException(status_code=500, detail="Text analysis error")


@router.get("/ops/status")
def get_ops_status():
    try:
        return coordinator.operational_status()
    except Exception as e:
        logger.exception("Error fetching Phase 7 ops status")
        raise HTTPException(status_code=500, detail="Operational status error")


@router.get("/ops/metrics")
def get_ops_metrics():
    try:
        return ops_store.metrics_snapshot()
    except Exception as e:
        logger.exception("Error fetching Phase 7 ops metrics")
        raise HTTPException(status_code=500, detail="Operational metrics error")


@router.get("/advisories/kenya")
def get_kenya_advisories():
    try:
        return {"advisories": kenya_reference_sources()}
    except Exception as e:
        logger.exception("Error fetching Kenya advisories")
        raise HTTPException(status_code=500, detail="Advisory fetch error")
