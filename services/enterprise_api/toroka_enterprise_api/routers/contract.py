"""Data contract and detector registry routes."""
from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends
from toroka_enterprise.data_contract import (
    CONTRACT_VERSION,
    DETECTOR_DEPENDENCIES,
    contract_dict,
    contract_fingerprint,
)

from ..auth import require_roles
from ..permissions import BANK_ROLES

router = APIRouter(
    prefix="/api/enterprise/v1",
    tags=["Enterprise Data Contract"],
)


@router.get(
    "/data-contract",
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
def get_data_contract():
    """Return the versioned bank data contract specification and fingerprint."""
    return {
        "version": CONTRACT_VERSION,
        "sha256": contract_fingerprint(),
        "contract": contract_dict(),
    }


@router.get(
    "/detectors",
    dependencies=[Depends(require_roles(*BANK_ROLES))],
)
def get_detectors():
    """Expose the canonical detector registry directly from the central data contract."""
    return {
        "count": len(DETECTOR_DEPENDENCIES),
        "detectors": [asdict(d) for d in DETECTOR_DEPENDENCIES],
    }
