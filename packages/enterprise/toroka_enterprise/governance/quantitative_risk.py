"""Toroka Enterprise — Quantitative Model Risk & Drift Governance Engine.

Implements model risk management standards in compliance with:
- OCC Bulletin 2011-12 / Federal Reserve SR 11-7 (Supervisory Guidance on Model Risk Management)
- Federal Reserve SR 15-18 / OCC 2026 Model Governance Standards
- NIST AI Risk Management Framework (NIST AI RMF 1.0)
- EEOC Uniform Guidelines on Employee Selection Procedures (4/5ths Rule / Disparate Impact)

Provides pure-Python, zero-dependency statistical verification:
1. Population Stability Index (PSI) with decile breakdown and regulatory risk tiering.
2. Kolmogorov-Smirnov (KS-test) 2-sample statistic with asymptotic p-value estimation.
3. 1D Wasserstein-1 Distance (Earth Mover's Distance) for continuous distribution drift.
4. Disparate Impact Ratio (DIR) demographic subgroup fairness analysis.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Sequence


class DriftSeverity(StrEnum):
    STABLE = "STABLE"          # PSI < 0.10: Insignificant distribution shift; model valid.
    MODERATE = "MODERATE"      # 0.10 <= PSI < 0.25: Moderate shift; monitoring & review required.
    SIGNIFICANT = "SIGNIFICANT"# PSI >= 0.25: Critical drift; model degraded, retraining/fail-closed required.


@dataclass(frozen=True)
class PSIBinDetail:
    bin_index: int
    lower_bound: float
    upper_bound: float
    baseline_count: int
    current_count: int
    baseline_fraction: float
    current_fraction: float
    contribution: float  # (current_frac - baseline_frac) * ln(current_frac / baseline_frac)

    def to_dict(self) -> dict[str, Any]:
        return {
            "bin_index": self.bin_index,
            "lower_bound": round(self.lower_bound, 6),
            "upper_bound": round(self.upper_bound, 6),
            "baseline_count": self.baseline_count,
            "current_count": self.current_count,
            "baseline_fraction": round(self.baseline_fraction, 6),
            "current_fraction": round(self.current_fraction, 6),
            "contribution": round(self.contribution, 6),
        }


@dataclass(frozen=True)
class PSISummary:
    score: float
    severity: DriftSeverity
    baseline_sample_size: int
    current_sample_size: int
    num_bins: int
    bin_details: tuple[PSIBinDetail, ...]
    requires_mitigation: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": round(self.score, 6),
            "severity": self.severity.value,
            "baseline_sample_size": self.baseline_sample_size,
            "current_sample_size": self.current_sample_size,
            "num_bins": self.num_bins,
            "requires_mitigation": self.requires_mitigation,
            "bin_details": [b.to_dict() for b in self.bin_details],
        }


@dataclass(frozen=True)
class KSSummary:
    statistic: float  # D statistic in [0, 1]
    p_value: float    # Approximate two-tailed p-value
    is_drift_detected: bool  # True if p_value < alpha (e.g. 0.05)
    baseline_sample_size: int
    current_sample_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "statistic": round(self.statistic, 6),
            "p_value": round(self.p_value, 6),
            "is_drift_detected": self.is_drift_detected,
            "baseline_sample_size": self.baseline_sample_size,
            "current_sample_size": self.current_sample_size,
        }


@dataclass(frozen=True)
class SubgroupFairnessMetric:
    group_name: str
    total_count: int
    favorable_count: int
    selection_rate: float
    disparate_impact_ratio: float
    is_adverse_impact: bool  # True if ratio < 0.80 (EEOC 4/5ths rule)

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_name": self.group_name,
            "total_count": self.total_count,
            "favorable_count": self.favorable_count,
            "selection_rate": round(self.selection_rate, 6),
            "disparate_impact_ratio": round(self.disparate_impact_ratio, 6),
            "is_adverse_impact": self.is_adverse_impact,
        }


@dataclass(frozen=True)
class DisparateImpactSummary:
    reference_group: str
    reference_selection_rate: float
    subgroups: tuple[SubgroupFairnessMetric, ...]
    has_adverse_impact: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "reference_group": self.reference_group,
            "reference_selection_rate": round(self.reference_selection_rate, 6),
            "has_adverse_impact": self.has_adverse_impact,
            "subgroups": [s.to_dict() for s in self.subgroups],
        }


@dataclass(frozen=True)
class QuantitativeRiskAssessment:
    component_id: str
    component_version: str
    evaluation_id: str
    psi: PSISummary
    ks_test: KSSummary
    wasserstein_distance: float
    fairness: DisparateImpactSummary | None
    is_compliant: bool
    governance_findings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "component_id": self.component_id,
            "component_version": self.component_version,
            "evaluation_id": self.evaluation_id,
            "psi": self.psi.to_dict(),
            "ks_test": self.ks_test.to_dict(),
            "wasserstein_distance": round(self.wasserstein_distance, 6),
            "fairness": self.fairness.to_dict() if self.fairness else None,
            "is_compliant": self.is_compliant,
            "governance_findings": list(self.governance_findings),
        }


def _percentile(sorted_data: Sequence[float], p: float) -> float:
    """Calculates the p-th percentile (0 <= p <= 100) using linear interpolation."""
    n = len(sorted_data)
    if n == 0:
        return 0.0
    if n == 1:
        return float(sorted_data[0])
    k = (n - 1) * (p / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return float(sorted_data[int(k)])
    d0 = sorted_data[int(f)] * (c - k)
    d1 = sorted_data[int(c)] * (k - f)
    return float(d0 + d1)


def compute_psi(
    baseline: Sequence[float],
    current: Sequence[float],
    num_bins: int = 10,
    epsilon: float = 1e-4,
) -> PSISummary:
    """Computes the Population Stability Index (PSI) between baseline and current distributions."""
    if not baseline:
        raise ValueError("Baseline dataset cannot be empty for PSI calculation")
    if not current:
        raise ValueError("Current dataset cannot be empty for PSI calculation")
    if num_bins < 2:
        raise ValueError("Number of bins must be at least 2")

    n_base = len(baseline)
    n_curr = len(current)
    sorted_base = sorted(float(x) for x in baseline)

    # 1. Determine bin edges using baseline quantiles
    edges: list[float] = []
    for i in range(num_bins + 1):
        pct = (i / num_bins) * 100.0
        val = _percentile(sorted_base, pct)
        edges.append(val)

    # Ensure strictly non-decreasing edges and unique boundary intervals where possible
    clean_edges: list[float] = [edges[0]]
    for e in edges[1:]:
        if e > clean_edges[-1]:
            clean_edges.append(e)
    if len(clean_edges) < 2:
        # Distribution is constant or degenerate; fallback to standard perturbation
        clean_edges = [sorted_base[0] - 1e-5, sorted_base[0] + 1e-5]

    effective_bins = len(clean_edges) - 1

    # 2. Count observations in bins
    # Bins: [edge[0], edge[1]], (edge[1], edge[2]], ..., (edge[k-1], edge[k]]
    base_counts = [0] * effective_bins
    curr_counts = [0] * effective_bins

    for val in sorted_base:
        placed = False
        for b in range(effective_bins):
            lower = clean_edges[b]
            upper = clean_edges[b + 1]
            if b == 0:
                if lower <= val <= upper:
                    base_counts[b] += 1
                    placed = True
                    break
            else:
                if lower < val <= upper:
                    base_counts[b] += 1
                    placed = True
                    break
        if not placed:
            if val < clean_edges[0]:
                base_counts[0] += 1
            else:
                base_counts[-1] += 1

    for val in current:
        v = float(val)
        placed = False
        for b in range(effective_bins):
            lower = clean_edges[b]
            upper = clean_edges[b + 1]
            if b == 0:
                if lower <= v <= upper:
                    curr_counts[b] += 1
                    placed = True
                    break
            else:
                if lower < v <= upper:
                    curr_counts[b] += 1
                    placed = True
                    break
        if not placed:
            if v < clean_edges[0]:
                curr_counts[0] += 1
            else:
                curr_counts[-1] += 1

    # 3. Compute smoothed fractions and PSI contributions
    details: list[PSIBinDetail] = []
    total_psi = 0.0

    denom_base = n_base + (effective_bins * epsilon)
    denom_curr = n_curr + (effective_bins * epsilon)

    for b in range(effective_bins):
        b_cnt = base_counts[b]
        c_cnt = curr_counts[b]

        p_smoothed = (b_cnt + epsilon) / denom_base
        q_smoothed = (c_cnt + epsilon) / denom_curr

        contrib = (q_smoothed - p_smoothed) * math.log(q_smoothed / p_smoothed)
        # Numerical protection: contrib must be non-negative
        if contrib < 0.0:
            contrib = 0.0
        total_psi += contrib

        details.append(
            PSIBinDetail(
                bin_index=b,
                lower_bound=clean_edges[b],
                upper_bound=clean_edges[b + 1],
                baseline_count=b_cnt,
                current_count=c_cnt,
                baseline_fraction=b_cnt / n_base,
                current_fraction=c_cnt / n_curr,
                contribution=contrib,
            )
        )

    # 4. Regulatory categorization (OCC / Fed SR 11-7 standard)
    if total_psi < 0.10:
        severity = DriftSeverity.STABLE
        requires_mitigation = False
    elif total_psi < 0.25:
        severity = DriftSeverity.MODERATE
        requires_mitigation = False
    else:
        severity = DriftSeverity.SIGNIFICANT
        requires_mitigation = True

    return PSISummary(
        score=total_psi,
        severity=severity,
        baseline_sample_size=n_base,
        current_sample_size=n_curr,
        num_bins=effective_bins,
        bin_details=tuple(details),
        requires_mitigation=requires_mitigation,
    )


def compute_ks_statistic(
    baseline: Sequence[float],
    current: Sequence[float],
    alpha: float = 0.05,
) -> KSSummary:
    """Computes the 2-sample Kolmogorov-Smirnov (KS) test statistic and asymptotic p-value."""
    if not baseline or not current:
        raise ValueError("Datasets cannot be empty for KS-test")

    n1 = len(baseline)
    n2 = len(current)
    s1 = sorted(float(x) for x in baseline)
    s2 = sorted(float(x) for x in current)

    # Merge unique evaluation points
    all_points = sorted(set(s1 + s2))

    max_d = 0.0
    idx1 = 0
    idx2 = 0

    for x in all_points:
        while idx1 < n1 and s1[idx1] <= x:
            idx1 += 1
        while idx2 < n2 and s2[idx2] <= x:
            idx2 += 1
        cdf1 = idx1 / n1
        cdf2 = idx2 / n2
        diff = abs(cdf1 - cdf2)
        if diff > max_d:
            max_d = diff

    if max_d == 0.0:
        return KSSummary(
            statistic=0.0,
            p_value=1.0,
            is_drift_detected=False,
            baseline_sample_size=n1,
            current_sample_size=n2,
        )

    # Asymptotic p-value approximation via Kolmogorov distribution
    # en = sqrt(n1 * n2 / (n1 + n2))
    en = math.sqrt((n1 * n2) / (n1 + n2))
    lam = (en + 0.12 + 0.11 / en) * max_d

    # Sum Kolmogorov series
    p_val = 0.0
    for k in range(1, 101):
        term = 2.0 * ((-1.0) ** (k - 1)) * math.exp(-2.0 * (k ** 2) * (lam ** 2))
        p_val += term
        if abs(term) < 1e-10:
            break

    p_val = max(0.0, min(1.0, p_val))

    return KSSummary(
        statistic=max_d,
        p_value=p_val,
        is_drift_detected=p_val < alpha,
        baseline_sample_size=n1,
        current_sample_size=n2,
    )


def compute_wasserstein_distance(
    baseline: Sequence[float],
    current: Sequence[float],
) -> float:
    """Computes exact 1D Wasserstein-1 (Earth Mover's) distance between empirical distributions."""
    if not baseline or not current:
        raise ValueError("Datasets cannot be empty for Wasserstein distance calculation")

    n1 = len(baseline)
    n2 = len(current)
    s1 = sorted(float(x) for x in baseline)
    s2 = sorted(float(x) for x in current)

    # Distinct sorted evaluation points
    points = sorted(set(s1 + s2))
    if len(points) <= 1:
        return 0.0

    total_w1 = 0.0
    idx1 = 0
    idx2 = 0

    for i in range(len(points) - 1):
        x_curr = points[i]
        x_next = points[i + 1]

        while idx1 < n1 and s1[idx1] <= x_curr:
            idx1 += 1
        while idx2 < n2 and s2[idx2] <= x_curr:
            idx2 += 1

        cdf1 = idx1 / n1
        cdf2 = idx2 / n2

        interval_len = x_next - x_curr
        total_w1 += abs(cdf1 - cdf2) * interval_len

    return total_w1


def compute_disparate_impact(
    subgroup_predictions: dict[str, Sequence[bool | int]],
    reference_group: str | None = None,
    adverse_impact_threshold: float = 0.80,
) -> DisparateImpactSummary:
    """Computes Disparate Impact Ratios (DIR) across protected demographic subgroups (EEOC 4/5ths Rule)."""
    if not subgroup_predictions:
        raise ValueError("Subgroup predictions map cannot be empty")

    rates: dict[str, float] = {}
    counts: dict[str, tuple[int, int]] = {}

    for grp, preds in subgroup_predictions.items():
        total = len(preds)
        if total == 0:
            rates[grp] = 0.0
            counts[grp] = (0, 0)
        else:
            fav = sum(1 for p in preds if bool(p))
            rates[grp] = fav / total
            counts[grp] = (total, fav)

    # Identify reference group (either user-specified or highest selection rate group)
    if reference_group and reference_group in rates:
        ref_grp = reference_group
    else:
        # Pick group with highest selection rate as reference benchmark
        ref_grp = max(rates.items(), key=lambda x: x[1])[0]

    ref_rate = rates.get(ref_grp, 0.0)

    subgroup_metrics: list[SubgroupFairnessMetric] = []
    has_adverse = False

    for grp, rate in rates.items():
        tot, fav = counts[grp]
        if ref_rate > 0.0:
            dir_ratio = rate / ref_rate
        else:
            dir_ratio = 1.0 if rate == 0.0 else 0.0

        is_adverse = dir_ratio < adverse_impact_threshold
        if is_adverse:
            has_adverse = True

        subgroup_metrics.append(
            SubgroupFairnessMetric(
                group_name=grp,
                total_count=tot,
                favorable_count=fav,
                selection_rate=rate,
                disparate_impact_ratio=dir_ratio,
                is_adverse_impact=is_adverse,
            )
        )

    return DisparateImpactSummary(
        reference_group=ref_grp,
        reference_selection_rate=ref_rate,
        subgroups=tuple(subgroup_metrics),
        has_adverse_impact=has_adverse,
    )


def evaluate_model_risk_comprehensive(
    *,
    component_id: str,
    component_version: str,
    evaluation_id: str,
    baseline_scores: Sequence[float],
    current_scores: Sequence[float],
    subgroup_predictions: dict[str, Sequence[bool | int]] | None = None,
) -> QuantitativeRiskAssessment:
    """Executes full OCC SR 11-7 / Fed SR 15-18 quantitative model risk suite."""
    psi = compute_psi(baseline_scores, current_scores)
    ks = compute_ks_statistic(baseline_scores, current_scores)
    wasserstein = compute_wasserstein_distance(baseline_scores, current_scores)

    fairness: DisparateImpactSummary | None = None
    if subgroup_predictions:
        fairness = compute_disparate_impact(subgroup_predictions)

    findings: list[str] = []
    is_compliant = True

    if psi.severity == DriftSeverity.SIGNIFICANT:
        findings.append(
            f"CRITICAL DRIFT: Population Stability Index (PSI={psi.score:.4f}) exceeds regulatory threshold 0.2500"
        )
        is_compliant = False
    elif psi.severity == DriftSeverity.MODERATE:
        findings.append(
            f"MODERATE DRIFT: Population Stability Index (PSI={psi.score:.4f}) indicates mild shift (0.10 <= PSI < 0.25)"
        )

    if ks.is_drift_detected:
        findings.append(
            f"STATISTICAL DRIFT: Two-sample KS test rejected H0 at alpha=0.05 (D={ks.statistic:.4f}, p={ks.p_value:.4e})"
        )

    if fairness and fairness.has_adverse_impact:
        adverse_groups = [s.group_name for s in fairness.subgroups if s.is_adverse_impact]
        findings.append(
            f"FAIRNESS VIOLATION: Disparate Impact Ratio < 0.80 detected for subgroups: {', '.join(adverse_groups)}"
        )
        is_compliant = False

    return QuantitativeRiskAssessment(
        component_id=component_id,
        component_version=component_version,
        evaluation_id=evaluation_id,
        psi=psi,
        ks_test=ks,
        wasserstein_distance=wasserstein,
        fairness=fairness,
        is_compliant=is_compliant,
        governance_findings=tuple(findings),
    )
