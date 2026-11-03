from __future__ import annotations
from typing import Protocol
from ..models import Evidence, InvestigationRequest, LocationMatch


class Provider(Protocol):
    name: str
    def investigate(self, request: InvestigationRequest) -> list[Evidence]: ...


class LocationProvider(Protocol):
    name: str
    def find_locations(self, request: InvestigationRequest) -> list[LocationMatch]: ...
