"""Illustrative FastAPI adapter. Copy the route into Toroka's existing API module.

Do not create a second app instance if Toroka already owns one; mount the router instead.
"""
from dataclasses import asdict
from fastapi import APIRouter
from pydantic import BaseModel, Field
from .engine import EvidenceEngine
from .models import InvestigationRequest
from .providers import VirusTotalProvider, UrlscanProvider, RdapProvider, GooglePlacesProvider, PhishTankProvider

router = APIRouter(prefix="/v2/investigations", tags=["evidence-investigations"])
engine = EvidenceEngine(
    providers=[PhishTankProvider(), UrlscanProvider(), VirusTotalProvider(), RdapProvider()],
    location_providers=[GooglePlacesProvider()],
)


class InvestigateBody(BaseModel):
    target: str = Field(min_length=3, max_length=2048)
    business_name: str | None = Field(default=None, max_length=200)
    social_handle: str | None = Field(default=None, max_length=120)
    search_location: str | None = Field(default=None, max_length=200)
    claimed_phone: str | None = Field(default=None, max_length=40)
    claimed_payment_identifier: str | None = Field(default=None, max_length=80)
    claimed_payment_name: str | None = Field(default=None, max_length=200)
    claimed_website: str | None = Field(default=None, max_length=2048)


@router.post("")
def investigate(body: InvestigateBody):
    payload = body.model_dump() if hasattr(body, "model_dump") else body.dict()
    request = InvestigationRequest(**payload)
    return engine.investigate(request).to_dict()
