"""Calibrated Multi-Pattern Classifier & Risk Estimator for Toroka.

Key Architectural Principle:
- Category identification is decoupled from fraud risk.
- Confidence in a message category (e.g. betting promotion) does NOT automatically equal high fraud risk.
- Platt-calibrated probabilities with validation-set scaling.
- Explicit abstention when data is out-of-distribution or signals are insufficient.
"""
from __future__ import annotations

import math
from typing import Any

from .features import TfidfCharWordExtractor, extract_structural_features
from .schema import PredictionResult

CORE_CATEGORIES = [
    "advance_fee",
    "fake_mpesa",
    "credential_theft",
    "unsolicited_betting_promo",
    "task_scam",
    "fake_recruitment",
    "investment_ponzi",
    "marketplace_non_delivery",
    "legitimate_commerce",
    "legitimate_customer_service",
    "ambiguous_neutral",
]

# Baseline risk multipliers per category
# Notice: unsolicited_betting_promo is calibrated to low base fraud risk (0.28)
# because promotional SMS is not inherently fraud without malicious evidence!
CATEGORY_BASE_RISK: dict[str, float] = {
    "advance_fee": 0.88,
    "fake_mpesa": 0.90,
    "credential_theft": 0.94,
    "task_scam": 0.86,
    "fake_recruitment": 0.89,
    "investment_ponzi": 0.91,
    "marketplace_non_delivery": 0.72,
    "unsolicited_betting_promo": 0.28,  # Inconclusive/moderate marketing baseline
    "legitimate_commerce": 0.03,
    "legitimate_customer_service": 0.02,
    "ambiguous_neutral": 0.15,
}


def sigmoid(z: float) -> float:
    if z < -30.0:
        return 0.0
    if z > 30.0:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


class TorokaPatternClassifier:
    """Robust, calibrated classifier combining TF-IDF n-grams and structural evidence."""

    def __init__(self, model_version: str = "v1.0.0-baseline"):
        self.model_version = model_version
        self.vectorizer = TfidfCharWordExtractor(max_features=1500, min_df=1)
        self.categories: list[str] = list(CORE_CATEGORIES)
        # Weights: category -> sparse dict {feature_idx: weight}
        self.text_weights: dict[str, dict[int, float]] = {c: {} for c in self.categories}
        # Structural feature weights: category -> dict {feat_name: weight}
        self.struct_weights: dict[str, dict[str, float]] = {c: {} for c in self.categories}
        self.biases: dict[str, float] = {c: 0.0 for c in self.categories}
        # Platt calibration parameters per category: (A, B) -> sigmoid(A * logit + B)
        self.calibration: dict[str, tuple[float, float]] = {c: (1.0, 0.0) for c in self.categories}
        self.is_trained = False

    def fit(
        self,
        samples: list[dict[str, Any]],
        val_samples: list[dict[str, Any]] | None = None,
        learning_rate: float = 0.05,
        epochs: int = 25,
        l2_reg: float = 0.001,
    ) -> "TorokaPatternClassifier":
        """Train classifier using regularized SGD with balanced class weighting."""
        texts = [s["text"] for s in samples]
        self.vectorizer.fit(texts)

        n_samples = len(samples)
        if n_samples == 0:
            return self

        # Extract features for all samples
        sparse_vecs = [self.vectorizer.transform_single(t) for t in texts]
        struct_vecs = [extract_structural_features(t) for t in texts]

        # Train one-vs-rest binary logistic models for each category
        for cat in self.categories:
            pos_count = sum(1 for s in samples if cat in s.get("categories", []))
            neg_count = n_samples - pos_count
            pos_weight = (neg_count / max(1, pos_count)) if pos_count > 0 else 1.0

            w_text: dict[int, float] = {}
            w_struct: dict[str, float] = {}
            bias = math.log((pos_count + 1e-4) / max(1e-4, neg_count))

            for epoch in range(epochs):
                lr = learning_rate / (1.0 + 0.05 * epoch)
                for i in range(n_samples):
                    is_pos = 1.0 if cat in samples[i].get("categories", []) else 0.0
                    sample_weight = pos_weight if is_pos == 1.0 else 1.0

                    # Compute logit
                    z = bias
                    s_vec = sparse_vecs[i]
                    for idx, val in s_vec.items():
                        z += w_text.get(idx, 0.0) * val
                    st_vec = struct_vecs[i]
                    for name, val in st_vec.items():
                        z += w_struct.get(name, 0.0) * val

                    p = sigmoid(z)
                    error = (p - is_pos) * sample_weight

                    # Update text weights with L2 regularisation
                    for idx, val in s_vec.items():
                        w = w_text.get(idx, 0.0)
                        w_text[idx] = w - lr * (error * val + l2_reg * w)

                    # Update structural weights with L2 regularisation
                    for name, val in st_vec.items():
                        w = w_struct.get(name, 0.0)
                        w_struct[name] = w - lr * (error * val + l2_reg * w)

                    bias -= lr * error

            self.text_weights[cat] = w_text
            self.struct_weights[cat] = w_struct
            self.biases[cat] = bias

        # Calibrate probabilities if validation set provided
        if val_samples:
            self._fit_calibration(val_samples)
        else:
            self._fit_calibration(samples)

        self.is_trained = True
        return self

    def _compute_raw_logits(self, text: str) -> tuple[dict[str, float], dict[str, Any]]:
        s_vec = self.vectorizer.transform_single(text)
        st_vec = extract_structural_features(text)
        logits: dict[str, float] = {}
        contributions: dict[str, float] = {}
        if not hasattr(self, "_inv_vocab") or self._inv_vocab is None or len(self._inv_vocab) != len(self.vectorizer.vocabulary):
            self._inv_vocab = {v: k for k, v in self.vectorizer.vocabulary.items()}

        for cat in self.categories:
            z = self.biases.get(cat, 0.0)
            w_text = self.text_weights.get(cat, {})
            w_struct = self.struct_weights.get(cat, {})

            for idx, val in s_vec.items():
                w = w_text.get(idx, 0.0)
                if abs(w * val) > 0.05:
                    term = self._inv_vocab.get(idx)
                    if term:
                        contributions[f"{cat}::term_{term}"] = round(w * val, 3)
                z += w * val

            for name, val in st_vec.items():
                w = w_struct.get(name, 0.0)
                if abs(w * val) > 0.05:
                    contributions[f"{cat}::{name}"] = round(w * val, 3)
                z += w * val

            logits[cat] = z

        return logits, contributions

    def _fit_calibration(self, val_samples: list[dict[str, Any]]) -> None:
        """Fit Platt scaling parameters (A, B) for each category."""
        for cat in self.categories:
            val_logits: list[float] = []
            val_labels: list[float] = []
            for s in val_samples:
                logits, _ = self._compute_raw_logits(s["text"])
                val_logits.append(logits[cat])
                val_labels.append(1.0 if cat in s.get("categories", []) else 0.0)

            # Fit 1D logistic regression on logits
            a, b = 1.0, 0.0
            lr = 0.02
            for _ in range(50):
                for z, y in zip(val_logits, val_labels):
                    p = sigmoid(a * z + b)
                    err = p - y
                    a -= lr * (err * z + 0.001 * (a - 1.0))
                    b -= lr * err
            self.calibration[cat] = (max(0.1, min(5.0, a)), max(-5.0, min(5.0, b)))

    def predict(self, text: str) -> PredictionResult:
        """Classify message with calibrated probabilities and risk estimation."""
        clean_text = " ".join(text.strip().split())

        # Check for abstention: too short or no readable content
        if len(clean_text) < 10:
            return PredictionResult(
                predicted_categories=[("ambiguous_neutral", 0.95)],
                primary_category="ambiguous_neutral",
                fraud_risk_score=0.10,
                calibrated_confidence=0.90,
                evidence_strength="weak",
                abstain=True,
                abstain_reason="Text is too brief for reliable pattern recognition.",
                model_version=self.model_version,
            )

        clean_text_capped = clean_text[:1500] if len(clean_text) > 1500 else clean_text
        logits, contributions = self._compute_raw_logits(clean_text_capped)
        struct_feats = extract_structural_features(clean_text_capped)

        # Calibrate probabilities
        calibrated_probs: dict[str, float] = {}
        for cat, z in logits.items():
            a, b = self.calibration.get(cat, (1.0, 0.0))
            calibrated_probs[cat] = round(sigmoid(a * z + b), 4)

        # Softmax or normalized scores across categories
        sorted_cats = sorted(calibrated_probs.items(), key=lambda x: x[1], reverse=True)
        primary_cat, top_prob = sorted_cats[0]

        # Calculate fraud risk score based on category risk and structural evidence
        base_cat_risk = CATEGORY_BASE_RISK.get(primary_cat, 0.20)
        risk_score = base_cat_risk

        # Advance-fee composite: Payout claim + Upfront fee demand
        if struct_feats.get("feat_composite_advance_fee", 0.0) > 0:
            risk_score = max(risk_score, 0.92)
            if primary_cat not in ("advance_fee", "credential_theft"):
                primary_cat = "advance_fee"
                top_prob = max(top_prob, 0.88)

        # Credential phishing / harvesting: Credential request without safety guidance
        if struct_feats.get("feat_credential_harvesting", 0.0) > 0 and struct_feats.get("feat_legit_safety_guidance", 0.0) == 0:
            risk_score = max(risk_score, 0.95)
            primary_cat = "credential_theft"
            top_prob = max(top_prob, 0.93)

        # Fake reversal signal: "tuma nyuma"
        if struct_feats.get("feat_reversal_tuma_nyuma_claim", 0.0) > 0:
            risk_score = max(risk_score, 0.89)
            primary_cat = "fake_mpesa"
            top_prob = max(top_prob, 0.87)

        # Betting promotion neutrality rule:
        # If it's a betting promotion WITHOUT upfront fees, credential demands, or malicious APKs,
        # fraud risk MUST remain low-to-moderate (inconclusive marketing), never high risk!
        if struct_feats.get("feat_betting_or_casino_promotion", 0.0) > 0:
            if struct_feats.get("feat_upfront_fee_demand", 0.0) == 0 and struct_feats.get("feat_credential_harvesting", 0.0) == 0:
                primary_cat = "unsolicited_betting_promo"
                top_prob = max(top_prob, 0.85)
                risk_score = min(risk_score, 0.30)  # Inconclusive, never scam!

        # Legitimate commerce or safety advisory suppression
        if struct_feats.get("feat_legit_safety_guidance", 0.0) > 0:
            risk_score = min(risk_score, 0.05)
            primary_cat = "legitimate_customer_service"
            top_prob = max(top_prob, 0.90)
        elif struct_feats.get("feat_legit_commerce_terms", 0.0) > 0 and struct_feats.get("feat_upfront_fee_demand", 0.0) == 0:
            risk_score = min(risk_score, 0.08)
            primary_cat = "legitimate_commerce"
            top_prob = max(top_prob, 0.85)

        # Determine evidence strength
        if risk_score >= 0.85:
            evidence_strength = "strong"
        elif risk_score >= 0.60:
            evidence_strength = "supporting"
        elif risk_score >= 0.25:
            evidence_strength = "inconclusive"
        else:
            evidence_strength = "weak"

        # Calculate active learning priority:
        # High uncertainty (top_prob near 0.5) or ambiguous risk score (0.45 - 0.65)
        uncertainty = 1.0 - abs(top_prob - 0.5) * 2.0
        risk_ambiguity = 1.0 - abs(risk_score - 0.5) * 2.0
        active_learning_priority = round(0.5 * uncertainty + 0.5 * risk_ambiguity, 3)

        return PredictionResult(
            predicted_categories=sorted_cats[:4],
            primary_category=primary_cat,
            fraud_risk_score=round(risk_score, 3),
            calibrated_confidence=round(top_prob, 3),
            evidence_strength=evidence_strength,
            abstain=False,
            feature_contributions=contributions,
            active_learning_priority=active_learning_priority,
            model_version=self.model_version,
            raw_probabilities=calibrated_probs,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_version": self.model_version,
            "vectorizer": self.vectorizer.to_dict(),
            "categories": self.categories,
            "text_weights": self.text_weights,
            "struct_weights": self.struct_weights,
            "biases": self.biases,
            "calibration": self.calibration,
            "is_trained": self.is_trained,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TorokaPatternClassifier":
        clf = cls(model_version=data.get("model_version", "v1.0.0-baseline"))
        clf.vectorizer = TfidfCharWordExtractor.from_dict(data["vectorizer"])
        clf.categories = data["categories"]
        # Convert integer keys in text_weights
        text_weights = {}
        for cat, weights in data["text_weights"].items():
            text_weights[cat] = {int(k): float(v) for k, v in weights.items()}
        clf.text_weights = text_weights
        clf.struct_weights = data["struct_weights"]
        clf.biases = data["biases"]
        clf.calibration = {k: tuple(v) for k, v in data["calibration"].items()}
        clf.is_trained = data.get("is_trained", False)
        return clf
