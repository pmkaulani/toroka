"""Evaluation and Acceptance Gates for Toroka's Machine Learning System.

Calculates:
- Precision, Recall, F1 (macro and per-category)
- False Positive Rate on legitimate messages (vital for Kenyan business safety)
- False Negative Rate on confirmed scams
- Brier Score & Expected Calibration Error (ECE) for calibrated probabilities
- Confusion Matrix
- Inference Latency (ms)
- Acceptance Criteria Gate for candidate model deployment vs. champion
"""
from __future__ import annotations

import math
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from .classifier import TorokaPatternClassifier
from .schema import DatasetSample


@dataclass
class CategoryMetrics:
    category: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    support: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0

    def compute(self) -> None:
        self.precision = (
            round(self.true_positives / (self.true_positives + self.false_positives), 4)
            if (self.true_positives + self.false_positives) > 0
            else 0.0
        )
        self.recall = (
            round(self.true_positives / (self.true_positives + self.false_negatives), 4)
            if (self.true_positives + self.false_negatives) > 0
            else 0.0
        )
        self.f1_score = (
            round(2 * self.precision * self.recall / (self.precision + self.recall), 4)
            if (self.precision + self.recall) > 0
            else 0.0
        )


@dataclass
class EvaluationReport:
    n_samples: int
    overall_accuracy: float
    macro_f1: float
    legit_false_positive_rate: float
    scam_false_negative_rate: float
    brier_score: float
    expected_calibration_error: float
    mean_latency_ms: float
    per_category: dict[str, dict[str, Any]]
    confusion_matrix: dict[str, dict[str, int]]
    critical_test_regressions: list[str] = field(default_factory=list)
    passed_acceptance_gate: bool = False
    acceptance_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_model(
    model: TorokaPatternClassifier,
    samples: list[DatasetSample],
    critical_regression_cases: list[dict[str, Any]] | None = None,
) -> EvaluationReport:
    """Run thorough evaluation across multi-category predictions and risk calibration."""
    if not samples:
        raise ValueError("Cannot evaluate model on an empty dataset.")

    start_time = time.perf_counter()
    predictions = [model.predict(s.text) for s in samples]
    total_time = (time.perf_counter() - start_time) * 1000.0
    mean_latency = round(total_time / len(samples), 3)

    # Track metrics
    categories = model.categories
    cat_metrics = {c: CategoryMetrics(category=c) for c in categories}
    confusion: dict[str, dict[str, int]] = {c: {c2: 0 for c2 in categories} for c in categories}

    legit_total = 0
    legit_flagged = 0
    scam_total = 0
    scam_missed = 0

    brier_sum = 0.0
    calibration_bins: list[list[tuple[float, float]]] = [[] for _ in range(10)]

    for sample, pred in zip(samples, predictions):
        true_cats = set(sample.categories)
        pred_cat = pred.primary_category

        # Confusion matrix against primary category
        primary_true = sample.categories[0] if sample.categories else "ambiguous_neutral"
        if primary_true in confusion and pred_cat in confusion[primary_true]:
            confusion[primary_true][pred_cat] += 1

        # Per-category multi-label scoring
        for cat in categories:
            is_true = cat in true_cats
            is_pred = cat == pred_cat or any(c == cat and p >= 0.5 for c, p in pred.predicted_categories)
            prob = pred.raw_probabilities.get(cat, 0.0)

            # Brier score calculation: (prob - actual)^2
            brier_sum += (prob - (1.0 if is_true else 0.0)) ** 2

            # Calibration binning
            bin_idx = min(9, int(prob * 10))
            calibration_bins[bin_idx].append((prob, 1.0 if is_true else 0.0))

            if is_true:
                cat_metrics[cat].support += 1
                if is_pred:
                    cat_metrics[cat].true_positives += 1
                else:
                    cat_metrics[cat].false_negatives += 1
            else:
                if is_pred:
                    cat_metrics[cat].false_positives += 1

        # Evaluate risk level false positives / negatives
        is_legit = sample.assessment_label in ("no_known_threats_found", "verified_official")
        is_scam = sample.assessment_label in ("high_risk", "suspicious_verify_first")

        if is_legit:
            legit_total += 1
            if pred.fraud_risk_score >= 0.60:
                legit_flagged += 1
        elif is_scam:
            scam_total += 1
            if pred.fraud_risk_score < 0.40:
                scam_missed += 1

    for cm in cat_metrics.values():
        cm.compute()

    # Macro F1
    valid_f1s = [cm.f1_score for cm in cat_metrics.values() if cm.support > 0]
    macro_f1 = round(sum(valid_f1s) / max(1, len(valid_f1s)), 4)

    # Accuracy on primary category
    correct_primary = sum(
        1 for s, p in zip(samples, predictions) if p.primary_category in s.categories
    )
    overall_accuracy = round(correct_primary / len(samples), 4)

    legit_fpr = round(legit_flagged / max(1, legit_total), 4)
    scam_fnr = round(scam_missed / max(1, scam_total), 4)

    total_prob_evals = len(samples) * len(categories)
    brier_score = round(brier_sum / max(1, total_prob_evals), 4)

    # Expected Calibration Error (ECE)
    ece_sum = 0.0
    for bin_items in calibration_bins:
        if bin_items:
            bin_conf = sum(p for p, y in bin_items) / len(bin_items)
            bin_acc = sum(y for p, y in bin_items) / len(bin_items)
            ece_sum += abs(bin_conf - bin_acc) * (len(bin_items) / total_prob_evals)
    ece = round(ece_sum, 4)

    # Evaluate Critical Regression Cases (Section 14 & 15)
    regressions: list[str] = []
    reg_cases = critical_regression_cases or [
        {
            "id": "reg_betting_neutrality",
            "text": "You have been awarded 5 FREE AVIATOR FREEBETS! REGISTER on Chezagame.com and get your FREEBETS today! STOP*456*9*5#",
            "must_not_be_fraud": True,
            "must_be_category": "unsolicited_betting_promo",
        },
        {
            "id": "reg_advance_fee_high_risk",
            "text": "Your inheritance payout of Ksh 500,000 is approved. Pay tax clearance fee of Ksh 4,800 to release funds.",
            "must_be_fraud": True,
            "must_be_category": "advance_fee",
        },
        {
            "id": "reg_pin_harvesting_high_risk",
            "text": "Safaricom: Your M-PESA is locked. Reply with your M-PESA PIN to unlock it.",
            "must_be_fraud": True,
            "must_be_category": "credential_theft",
        },
        {
            "id": "reg_safaricom_advisory_clean",
            "text": "Safaricom reminder: never share your M-PESA PIN with anyone. We only call from 0722 000 000.",
            "must_not_be_fraud": True,
            "must_be_category": "legitimate_customer_service",
        },
    ]

    for rc in reg_cases:
        p = model.predict(rc["text"])
        if rc.get("must_not_be_fraud") and p.fraud_risk_score >= 0.50:
            regressions.append(
                f"{rc['id']}: Failed neutrality constraint (risk score {p.fraud_risk_score} >= 0.50)"
            )
        if rc.get("must_be_fraud") and p.fraud_risk_score < 0.60:
            regressions.append(
                f"{rc['id']}: Failed detection constraint (risk score {p.fraud_risk_score} < 0.60)"
            )
        if rc.get("must_be_category") and p.primary_category != rc["must_be_category"]:
            regressions.append(
                f"{rc['id']}: Category mismatch (got {p.primary_category}, expected {rc['must_be_category']})"
            )

    # Acceptance Criteria Gate:
    # 1. Zero critical test regressions
    # 2. legit_false_positive_rate <= 0.02 (strict zero-tolerance for false accusations against innocent businesses)
    # 3. scam_false_negative_rate <= 0.15
    # 4. macro_f1 >= 0.80
    acceptance_passed = True
    acceptance_notes: list[str] = []

    if regressions:
        acceptance_passed = False
        acceptance_notes.append(f"FAILED: {len(regressions)} critical regression(s) found.")
    else:
        acceptance_notes.append("PASSED: Zero critical regressions.")

    if legit_fpr > 0.02:
        acceptance_passed = False
        acceptance_notes.append(f"FAILED: Legitimate FPR ({legit_fpr}) exceeds tolerance 0.02.")
    else:
        acceptance_notes.append(f"PASSED: Legitimate FPR ({legit_fpr}) within safety limit.")

    if scam_fnr > 0.15:
        acceptance_passed = False
        acceptance_notes.append(f"FAILED: Scam FNR ({scam_fnr}) exceeds tolerance 0.15.")
    else:
        acceptance_notes.append(f"PASSED: Scam FNR ({scam_fnr}) within tolerance.")

    if macro_f1 < 0.80:
        acceptance_passed = False
        acceptance_notes.append(f"FAILED: Macro F1 ({macro_f1}) below acceptance floor 0.80.")
    else:
        acceptance_notes.append(f"PASSED: Macro F1 ({macro_f1}) meets acceptance threshold.")

    return EvaluationReport(
        n_samples=len(samples),
        overall_accuracy=overall_accuracy,
        macro_f1=macro_f1,
        legit_false_positive_rate=legit_fpr,
        scam_false_negative_rate=scam_fnr,
        brier_score=brier_score,
        expected_calibration_error=ece,
        mean_latency_ms=mean_latency,
        per_category={k: asdict(v) for k, v in cat_metrics.items()},
        confusion_matrix=confusion,
        critical_test_regressions=regressions,
        passed_acceptance_gate=acceptance_passed,
        acceptance_notes=acceptance_notes,
    )
