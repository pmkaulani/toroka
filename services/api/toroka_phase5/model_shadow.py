from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Callable
import math

ALLOWED_LABELS = {"legitimate", "suspicious", "scam", "inconclusive"}


@dataclass(frozen=True, slots=True)
class ModelPrediction:
    model_version: str
    probabilities: dict[str, float]
    evidence_refs: tuple[str, ...]
    calibration_version: str | None = None

    def __post_init__(self):
        if not self.model_version or len(self.model_version) > 80:
            raise ValueError("model_version is required and must be short")
        if not self.probabilities or set(self.probabilities) - ALLOWED_LABELS:
            raise ValueError("probabilities must use only supported labels")
        if any(not math.isfinite(v) or v < 0 or v > 1 for v in self.probabilities.values()):
            raise ValueError("probabilities must be finite values between 0 and 1")
        if abs(sum(self.probabilities.values()) - 1.0) > 0.02:
            raise ValueError("probabilities must sum to approximately 1")
        if len(self.evidence_refs) > 50:
            raise ValueError("too many evidence references")


@dataclass(slots=True)
class ShadowResult:
    status: str
    mode: str = "shadow_only"
    model_version: str | None = None
    calibration_version: str | None = None
    suggested_label: str | None = None
    probabilities: dict[str, float] | None = None
    evidence_refs_validated: bool = False
    error_code: str | None = None
    affects_user_verdict: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def run_shadow_model(
    predictor: Callable[[dict[str, Any]], ModelPrediction], *,
    safe_case_features: dict[str, Any], known_evidence_refs: set[str],
) -> ShadowResult:
    """Run an optional model on sanitized features; never feed raw artifact content."""
    try:
        prediction = predictor(safe_case_features)
        if not isinstance(prediction, ModelPrediction):
            return ShadowResult(status="invalid_model_response", error_code="invalid_schema")
        if not set(prediction.evidence_refs).issubset(known_evidence_refs):
            return ShadowResult(status="invalid_model_response", model_version=prediction.model_version,
                                error_code="unknown_evidence_reference")
        label = max(prediction.probabilities, key=prediction.probabilities.get)
        return ShadowResult(
            status="completed", model_version=prediction.model_version,
            calibration_version=prediction.calibration_version,
            suggested_label=label, probabilities=dict(prediction.probabilities),
            evidence_refs_validated=True, affects_user_verdict=False,
        )
    except Exception:
        # Do not leak provider messages, tokens, URLs or stack traces into API responses.
        return ShadowResult(status="unavailable", error_code="model_provider_error")
