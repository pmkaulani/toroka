from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .fingerprint import CaseFingerprint


@dataclass(frozen=True)
class FeatureComparison:
    dimension: str
    current_value: str
    historical_value: str
    matched: bool
    current_event_ids: tuple[str, ...]
    historical_event_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension,
            "current_value": self.current_value,
            "historical_value": self.historical_value,
            "matched": self.matched,
            "current_event_ids": list(self.current_event_ids),
            "historical_event_ids": list(self.historical_event_ids),
        }


@dataclass(frozen=True)
class CaseSimilarity:
    """Deterministic comparison between a current case and an adjudicated historical case."""

    current_case_id: str
    historical_case_id: str
    similarity_index: float | None
    comparison_coverage: float
    matched_features: tuple[str, ...]
    different_features: tuple[str, ...]
    comparisons: tuple[FeatureComparison, ...]
    historical_outcome: str | None = None
    historical_control_weaknesses: tuple[str, ...] = ()
    shared_control_weaknesses: tuple[str, ...] = ()
    summary_explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "current_case_id": self.current_case_id,
            "historical_case_id": self.historical_case_id,
            "similarity_index": self.similarity_index,
            "comparison_coverage": self.comparison_coverage,
            "matched_features": list(self.matched_features),
            "different_features": list(self.different_features),
            "comparisons": [c.to_dict() for c in self.comparisons],
            "historical_outcome": self.historical_outcome,
            "historical_control_weaknesses": list(self.historical_control_weaknesses),
            "shared_control_weaknesses": list(self.shared_control_weaknesses),
            "summary_explanation": self.summary_explanation,
        }


def feature_weight(dimension: str) -> float:
    """Configurable deterministic weight per behavioral feature dimension."""
    if dimension.startswith("sequence."):
        return 2.0
    if dimension.startswith("control_weakness."):
        return 1.8
    if dimension.startswith("sensitive_change."):
        return 1.5
    if dimension.startswith("source_presence."):
        return 0.8
    return 1.0


def compare_fingerprints(
    current: CaseFingerprint,
    historical: CaseFingerprint,
    min_coverage: float = 0.2,
) -> CaseSimilarity:
    """Deterministically compare two case fingerprints within the same tenant installation.

    Explicitly separates the similarity index from comparison coverage. Unknown dimensions
    are preserved and excluded from comparable calculations rather than assumed absent.
    """
    if current.installation_id != historical.installation_id:
        raise ValueError(
            f"Cross-installation comparison prohibited: current '{current.installation_id}' "
            f"vs historical '{historical.installation_id}'."
        )

    # Index evidence event references for both cases
    curr_ev_map = {e.dimension: e.event_ids for e in current.evidence}
    hist_ev_map = {e.dimension: e.event_ids for e in historical.evidence}

    all_dims = sorted(set(current.features.keys()) | set(historical.features.keys()))

    total_weight = sum(feature_weight(d) for d in all_dims)
    comparable_weight = 0.0
    matched_weight = 0.0

    matched_features: list[str] = []
    different_features: list[str] = []
    comparisons: list[FeatureComparison] = []

    for dim in all_dims:
        v_curr = current.features.get(dim, "unknown")
        v_hist = historical.features.get(dim, "unknown")
        w = feature_weight(dim)

        curr_e_ids = curr_ev_map.get(dim, ())
        hist_e_ids = hist_ev_map.get(dim, ())

        # Only evaluate match if both dimensions are known
        if v_curr != "unknown" and v_hist != "unknown":
            comparable_weight += w

            # A match occurs if exact value matches, or if both represent the same event sequence
            is_match = False
            if v_curr == v_hist:
                is_match = True
            elif v_curr.startswith("present") and v_hist.startswith("present"):
                # Both present sequences with potentially differing latency buckets
                is_match = True

            if is_match:
                matched_weight += w
                matched_features.append(dim)
            else:
                different_features.append(dim)

            comparisons.append(
                FeatureComparison(
                    dimension=dim,
                    current_value=v_curr,
                    historical_value=v_hist,
                    matched=is_match,
                    current_event_ids=curr_e_ids,
                    historical_event_ids=hist_e_ids,
                )
            )
        else:
            # Dimension is unknown in at least one case
            comparisons.append(
                FeatureComparison(
                    dimension=dim,
                    current_value=v_curr,
                    historical_value=v_hist,
                    matched=False,
                    current_event_ids=curr_e_ids,
                    historical_event_ids=hist_e_ids,
                )
            )

    comparison_coverage = (
        round(comparable_weight / total_weight, 4) if total_weight > 0 else 0.0
    )

    if comparable_weight > 0:
        similarity_index = round(matched_weight / comparable_weight, 4)
    else:
        similarity_index = None

    shared_weaknesses = tuple(
        sorted(set(current.control_weaknesses) & set(historical.control_weaknesses))
    )

    # Build non-accusatory, explainable narrative
    outcome_str = historical.adjudicated_label or "unlabelled"
    shared_seq = [f for f in matched_features if f.startswith("sequence.")]
    shared_cw = [f for f in matched_features if f.startswith("control_weakness.")]

    narrative_parts = [
        f"Shares {len(matched_features)} behavioral feature(s) with historical case '{historical.case_id}' "
        f"({len(different_features)} differing).",
        f"Comparison coverage is {comparison_coverage * 100:.1f}%.",
    ]
    if shared_seq:
        narrative_parts.append(f"Matching sequence(s): {', '.join(shared_seq[:2])}.")
    if shared_cw:
        narrative_parts.append(f"Common control weakness(es): {', '.join(shared_cw)}.")
    narrative_parts.append(f"Historical case adjudicated outcome: {outcome_str}.")

    summary_explanation = " ".join(narrative_parts)

    return CaseSimilarity(
        current_case_id=current.case_id,
        historical_case_id=historical.case_id,
        similarity_index=similarity_index,
        comparison_coverage=comparison_coverage,
        matched_features=tuple(matched_features),
        different_features=tuple(different_features),
        comparisons=tuple(comparisons),
        historical_outcome=historical.adjudicated_label,
        historical_control_weaknesses=historical.control_weaknesses,
        shared_control_weaknesses=shared_weaknesses,
        summary_explanation=summary_explanation,
    )
