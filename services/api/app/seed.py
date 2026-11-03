"""Seed the official-programme registry. Only records verified from a primary source belong here, and each stays
`unreviewed` until a human confirms it against the live page (see TASKS.md)."""
from __future__ import annotations

from datetime import date, timedelta

from sqlalchemy.orm import Session

from ssi_rules import load_registry
from ssi_rules.registry import verified_entities_from_registry

from .db import Opportunity, VerifiedRecord

TODAY = date(2026, 10, 20)
SEED = [
    dict(id="kra-careers", opportunity_type="job", official_name="KRA careers and recruitment", administering_body="Kenya Revenue Authority",
         aliases=["kra", "kenya revenue authority"], official_domain="kra.go.ke", application_url="https://kra.go.ke/careers",
         eligibility=None, counties=[], status=None, fee_policy="no_fee",
         source_url="https://kra.go.ke/news-center/public-notices/586-recruitment-fraud"),
]


def seed_opportunities(db: Session) -> int:
    n = 0
    for s in SEED:
        if not db.get(Opportunity, s["id"]):
            db.add(Opportunity(**s, last_verified_at=TODAY.isoformat(), review_due=(TODAY + timedelta(days=90)).isoformat(), reviewer="unreviewed"))
            n += 1
    db.commit()
    return n


def seed_verified(db: Session) -> int:
    """Seed official-domain candidates; unreviewed records must not be presented as verified."""
    n = 0
    for e in verified_entities_from_registry(load_registry()):
        if not db.get(VerifiedRecord, e.id):
            db.add(VerifiedRecord(id=e.id, name=e.name, entity_type=e.entity_type, domains=e.domains, handles=[], include_subdomains=True, basis=e.basis, source_url=e.source_url,
                                  evidence_note="Domains are stated on the organisation's own fraud-awareness or public notice pages.", last_verified_at=e.last_verified_at, review_due=e.review_due, reviewer=e.reviewer))
            n += 1
    db.commit()
    return n
