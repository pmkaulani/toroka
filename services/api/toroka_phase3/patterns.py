from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable


@dataclass(slots=True)
class SellerFootprint:
    seller_ref: str
    identifiers: dict[str, str]
    pending_reports: int = 0
    corroborated_reports: int = 0
    independently_sourced_risk_items: int = 0


@dataclass(slots=True)
class SharedInfrastructurePattern:
    pattern: str
    identifier_type: str
    linked_seller_refs: list[str]
    seller_count: int
    evidence_level: str
    interpretation: str
    risk_propagation: str = "never_automatic"
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def detect_shared_infrastructure(sellers: Iterable[SellerFootprint]) -> list[SharedInfrastructurePattern]:
    """Find exact shared identifiers without deciding that linked sellers are fraudulent."""
    index: dict[tuple[str, str], list[SellerFootprint]] = {}
    for seller in sellers:
        for kind, digest in seller.identifiers.items():
            if kind and digest:
                index.setdefault((kind, digest), []).append(seller)
    patterns = []
    for (kind, _), group in index.items():
        unique = {s.seller_ref: s for s in group}
        if len(unique) < 2:
            continue
        sellers_unique = list(unique.values())
        corr = sum(s.corroborated_reports for s in sellers_unique)
        pending = sum(s.pending_reports for s in sellers_unique)
        risk = sum(s.independently_sourced_risk_items for s in sellers_unique)
        if risk and corr:
            level = "shared_identifier_with_independent_risk_and_corroborated_reports"
            interpretation = "The same identifier is linked to multiple seller records and there are additional corroborated reports or independent risk signals. Investigate each account separately."
        elif corr:
            level = "shared_identifier_with_corroborated_reports"
            interpretation = "A shared identifier and moderated corroborated reports warrant further review, but do not prove common ownership or fraud."
        else:
            level = "shared_identifier_only"
            interpretation = "The identifier appears in multiple seller records. This may reflect shared staff, agencies, family businesses, payment providers, or reuse; it is not a fraud finding."
        patterns.append(SharedInfrastructurePattern(
            pattern="shared_infrastructure",
            identifier_type=kind,
            linked_seller_refs=sorted(unique.keys()),
            seller_count=len(unique),
            evidence_level=level,
            interpretation=interpretation,
            limitations=[
                "Only an exact normalized identifier match is counted.",
                "Shared identifiers do not prove common ownership, coordination, or wrongdoing.",
                f"Pending reports ({pending}) are disclosed context only and are not treated as corroborated reports.",
                "Do not automatically copy one seller's verdict to another seller.",
            ],
        ))
    return sorted(patterns, key=lambda item: (-item.seller_count, item.identifier_type))
