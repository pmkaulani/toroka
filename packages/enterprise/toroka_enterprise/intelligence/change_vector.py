"""Change vector representing subject-level shifts against baseline distributions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .profiles import BehavioralProfile


@dataclass(frozen=True)
class ChangeVector:
    subject_id: str
    changed_dimensions: tuple[str, ...]
    baseline_dimensions: tuple[str, ...]
    unusual_dimensions: tuple[str, ...]
    explanation: str
    completeness: float

    def __post_init__(self) -> None:
        if not 0.0 <= self.completeness <= 1.0:
            raise ValueError(
                "completeness must be between 0 and 1"
            )


def build_change_vector(
    subject_id: str,
    *,
    observed_attributes: dict[str, Any],
    profile: BehavioralProfile | None = None,
) -> ChangeVector:
    """Builds an explainable change vector by comparing observed dimensions with the baseline profile."""
    tracked_dimensions = [
        "device",
        "ip_address",
        "working_hours",
        "customer_set",
        "permissions",
        "transaction_value",
        "transaction_frequency",
        "branch_location",
    ]

    changed: list[str] = []
    unusual: list[str] = []
    baseline_dims: list[str] = []

    if profile and profile.dimensions:
        baseline_dims = [dim.value if hasattr(dim, "value") else str(dim) for dim in profile.dimensions.keys()]

    # Evaluate observable changes
    for dim in tracked_dimensions:
        val = observed_attributes.get(dim)
        if val is not None:
            # Check if flagged as new/changed
            if isinstance(val, dict):
                is_changed = val.get("changed", False)
                is_unusual = val.get("unusual", False)
            elif isinstance(val, str):
                v_lower = val.lower()
                is_changed = "new" in v_lower or "changed" in v_lower or "unusual" in v_lower
                is_unusual = "unusual" in v_lower
            else:
                is_changed = False
                is_unusual = False

            if is_changed:
                changed.append(dim)
            if is_unusual:
                unusual.append(dim)

    # Compute dimension completeness (how many of the 8 tracked dimensions were measured)
    measured_count = sum(1 for dim in tracked_dimensions if dim in observed_attributes)
    completeness = round(measured_count / len(tracked_dimensions), 2) if tracked_dimensions else 1.0

    explanation = (
        f"Subject {subject_id} exhibits {len(changed)} changed dimension(s) and {len(unusual)} "
        f"statistically unusual dimension(s) with {int(completeness * 100)}% telemetry completeness. "
        "Evidence indicates operational change, which does not constitute proof of misconduct."
    )

    return ChangeVector(
        subject_id=subject_id,
        changed_dimensions=tuple(changed),
        baseline_dimensions=tuple(baseline_dims),
        unusual_dimensions=tuple(unusual),
        explanation=explanation,
        completeness=completeness,
    )
