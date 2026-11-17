"""Toroka Enterprise — Champion-Challenger Shadow Governance Engine.

Provides bank-grade shadow evaluation and non-inferiority promotion gating
in compliance with OCC SR 11-7 / Fed SR 15-18 model risk management.

Enforces:
1. Parallel shadow execution tracking without customer impact.
2. Non-inferiority gate: False Discovery Rate (FDR) increase <= 2.0% (0.02).
3. Performance preservation: F1 score retention >= 98% of Champion.
4. Latency SLA enforcement: p95 latency within production budget.
5. Demographic fairness gate: Disparate Impact Ratio >= 0.80 across protected groups.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from toroka_enterprise.governance.quantitative_risk import DisparateImpactSummary


class PromotionDecision(StrEnum):
    APPROVED_FOR_PROMOTION = "APPROVED_FOR_PROMOTION"
    REJECTED_EXCESSIVE_FDR = "REJECTED_EXCESSIVE_FDR"
    REJECTED_F1_REGRESSION = "REJECTED_F1_REGRESSION"
    REJECTED_LATENCY_VIOLATION = "REJECTED_LATENCY_VIOLATION"
    REJECTED_FAIRNESS_VIOLATION = "REJECTED_FAIRNESS_VIOLATION"
    INSUFFICIENT_EVALUATION_VOLUME = "INSUFFICIENT_EVALUATION_VOLUME"


@dataclass(frozen=True)
class ModelPerformanceMetrics:
    model_role: str  # "CHAMPION" or "CHALLENGER"
    component_id: str
    component_version: str
    sample_size: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    latency_ms_p50: float
    latency_ms_p95: float

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return (self.true_positives / denom) if denom > 0 else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return (self.true_positives / denom) if denom > 0 else 0.0

    @property
    def f1_score(self) -> float:
        p = self.precision
        r = self.recall
        return (2.0 * p * r / (p + r)) if (p + r) > 0 else 0.0

    @property
    def false_discovery_rate(self) -> float:
        """FDR = FP / (TP + FP). Critical financial crime metric for bank investigator workload."""
        denom = self.true_positives + self.false_positives
        return (self.false_positives / denom) if denom > 0 else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.false_positives + self.true_negatives
        return (self.false_positives / denom) if denom > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_role": self.model_role,
            "component_id": self.component_id,
            "component_version": self.component_version,
            "sample_size": self.sample_size,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1_score": round(self.f1_score, 4),
            "false_discovery_rate": round(self.false_discovery_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "latency_ms_p50": round(self.latency_ms_p50, 2),
            "latency_ms_p95": round(self.latency_ms_p95, 2),
        }


@dataclass(frozen=True)
class ChallengerEvaluationResult:
    decision: PromotionDecision
    is_promotable: bool
    champion_metrics: ModelPerformanceMetrics
    challenger_metrics: ModelPerformanceMetrics
    fdr_delta: float  # Challenger FDR - Champion FDR (positive = worse)
    f1_ratio: float   # Challenger F1 / Champion F1 (must be >= min_retention)
    latency_p95_delta_ms: float
    reasons: tuple[str, ...]
    fairness_summary: DisparateImpactSummary | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "is_promotable": self.is_promotable,
            "fdr_delta": round(self.fdr_delta, 4),
            "f1_ratio": round(self.f1_ratio, 4),
            "latency_p95_delta_ms": round(self.latency_p95_delta_ms, 2),
            "reasons": list(self.reasons),
            "champion_metrics": self.champion_metrics.to_dict(),
            "challenger_metrics": self.challenger_metrics.to_dict(),
            "fairness_summary": self.fairness_summary.to_dict() if self.fairness_summary else None,
        }


def evaluate_challenger_promotion(
    champion: ModelPerformanceMetrics,
    challenger: ModelPerformanceMetrics,
    *,
    min_sample_size: int = 100,
    max_fdr_increase: float = 0.02,     # Max 2% increase in False Discovery Rate
    min_f1_retention: float = 0.98,     # Challenger F1 >= 98% of Champion
    max_p95_latency_ms: float = 250.0,   # Absolute SLA limit
    fairness_summary: DisparateImpactSummary | None = None,
) -> ChallengerEvaluationResult:
    """Rigorous regulatory evaluation gate for promoting a Challenger model to Champion."""
    reasons: list[str] = []
    is_promotable = True
    primary_decision = PromotionDecision.APPROVED_FOR_PROMOTION

    # 1. Sample size check
    if challenger.sample_size < min_sample_size:
        reasons.append(
            f"Challenger evaluated on {challenger.sample_size} cases, below mandatory minimum {min_sample_size}"
        )
        is_promotable = False
        primary_decision = PromotionDecision.INSUFFICIENT_EVALUATION_VOLUME

    # 2. False Discovery Rate (FDR) non-inferiority check
    fdr_delta = challenger.false_discovery_rate - champion.false_discovery_rate
    if fdr_delta > max_fdr_increase:
        reasons.append(
            f"False Discovery Rate increased by {fdr_delta:+.2%} (threshold: max +{max_fdr_increase:.2%}). "
            f"Champion FDR={champion.false_discovery_rate:.2%}, Challenger FDR={challenger.false_discovery_rate:.2%}"
        )
        is_promotable = False
        if primary_decision == PromotionDecision.APPROVED_FOR_PROMOTION:
            primary_decision = PromotionDecision.REJECTED_EXCESSIVE_FDR

    # 3. F1 score retention check
    f1_ratio = (challenger.f1_score / champion.f1_score) if champion.f1_score > 0 else 1.0
    if f1_ratio < min_f1_retention:
        reasons.append(
            f"F1 score retained is {f1_ratio:.2%} (below minimum {min_f1_retention:.2%}). "
            f"Champion F1={champion.f1_score:.4f}, Challenger F1={challenger.f1_score:.4f}"
        )
        is_promotable = False
        if primary_decision == PromotionDecision.APPROVED_FOR_PROMOTION:
            primary_decision = PromotionDecision.REJECTED_F1_REGRESSION

    # 4. Latency SLA check
    latency_delta = challenger.latency_ms_p95 - champion.latency_ms_p95
    if challenger.latency_ms_p95 > max_p95_latency_ms:
        reasons.append(
            f"Challenger p95 latency ({challenger.latency_ms_p95:.1f}ms) exceeds SLA ceiling ({max_p95_latency_ms:.1f}ms)"
        )
        is_promotable = False
        if primary_decision == PromotionDecision.APPROVED_FOR_PROMOTION:
            primary_decision = PromotionDecision.REJECTED_LATENCY_VIOLATION

    # 5. Fairness & Disparate Impact check
    if fairness_summary and fairness_summary.has_adverse_impact:
        adverse_groups = [s.group_name for s in fairness_summary.subgroups if s.is_adverse_impact]
        reasons.append(
            f"Challenger introduces adverse demographic impact for protected groups: {', '.join(adverse_groups)}"
        )
        is_promotable = False
        if primary_decision == PromotionDecision.APPROVED_FOR_PROMOTION:
            primary_decision = PromotionDecision.REJECTED_FAIRNESS_VIOLATION

    if is_promotable:
        reasons.append(
            f"Challenger satisfies all non-inferiority criteria: FDR delta={fdr_delta:+.2%}, "
            f"F1 ratio={f1_ratio:.2%}, p95 latency={challenger.latency_ms_p95:.1f}ms"
        )

    return ChallengerEvaluationResult(
        decision=primary_decision,
        is_promotable=is_promotable,
        champion_metrics=champion,
        challenger_metrics=challenger,
        fdr_delta=fdr_delta,
        f1_ratio=f1_ratio,
        latency_p95_delta_ms=latency_delta,
        reasons=tuple(reasons),
        fairness_summary=fairness_summary,
    )
