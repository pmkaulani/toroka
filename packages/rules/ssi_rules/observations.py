"""Facts gathered by connectors and the database, handed to the pure assessment function.

Keeping these as plain data means assess() stays deterministic and testable: connectors can
fail, time out or be switched off, and the result says so instead of guessing.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .vocabulary import CoverageStatus


@dataclass
class Reputation:
    status: CoverageStatus
    source: str
    threat_types: list[str] = field(default_factory=list)
    observed_at: str | None = None
    valid_until: str | None = None
    licence_note: str = ""


@dataclass
class UrlObservation:
    url: str                                   # as submitted (matches ParsedUrl.original)
    reputation: Reputation | None = None
    final_url: str | None = None
    hops: int = 0
    redirect_status: CoverageStatus | None = None
    domain_age_days: int | None = None
    domain_facts_status: CoverageStatus | None = None


@dataclass
class ReportHit:
    kind: str                                  # phone | till | paybill | domain | handle
    independent_reports: int
    published: bool
    indicator_id: str | None = None
    last_reported: str | None = None
    under_review: bool = False


@dataclass
class Opportunity:
    id: str
    official_name: str
    administering_body: str
    official_domain: str
    application_url: str | None = None
    fee_policy: str | None = None              # "no_fee" when the agency says it charges nothing
    counties: list[str] = field(default_factory=list)   # empty means national
    source_url: str = ""
    last_verified_at: str = ""                 # ISO date
    review_due: str = ""                       # ISO date
    reviewer: str = "unreviewed"


@dataclass
class VerifiedEntity:
    """A reviewed record that a website or shop is genuinely who it says it is. It vouches for the SITE, never for a particular offer."""
    id: str
    name: str
    entity_type: str                           # organisation | online_shop | website | social_shop
    domains: list[str] = field(default_factory=list)
    handles: list[str] = field(default_factory=list)       # "instagram:duka_la_viatu"
    include_subdomains: bool = False
    basis: str = "moderator_verified_documents"
    source_url: str = ""
    last_verified_at: str = ""
    review_due: str = ""
    reviewer: str = "unreviewed"


@dataclass
class GeocodeObservation:
    place: str
    status: CoverageStatus
    found: bool | None = None
    provider: str = ""
    observed_at: str | None = None


@dataclass
class Observations:
    urls: dict[str, UrlObservation] = field(default_factory=dict)
    report_hits: dict[str, ReportHit] = field(default_factory=dict)   # key: "phone:+2547...", "till:123456", "domain:example.com"
    report_lookup_ran: bool = False
    opportunities: list[Opportunity] = field(default_factory=list)
    opportunity_lookup_ran: bool = False
    geocodes: dict[str, GeocodeObservation] = field(default_factory=dict)
    extra_coverage: list[dict] = field(default_factory=list)          # {id,name,status,detail,blocking}
    verified_entities: list[VerifiedEntity] = field(default_factory=list)
    extra_findings: list = field(default_factory=list)                # Finding objects produced outside the pure layer (e.g. image leads)
