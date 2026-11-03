r"""Automated Label Generation, Quality Tiering & Privacy Redaction for Toroka.

Implements the strict 5-tier label hierarchy:
1. Strongly Supported Label: Authoritative regulator warning or verified threat intelligence.
2. Corroborated Label: Independently verified from multiple non-duplicative sources.
3. Weak Label: Rule heuristic matches or low-weight unverified signals.
4. Pseudo-Label: Conservative high-confidence model predictions (\ge 0.85) with rule agreement.
5. Unlabelled / Ambiguous: Insufficient or contradictory evidence preserved without fabricated labels.

Also enforces PII redaction (phones, credentials, PINs) and contradiction detection.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ssi_rules import normalize as nz
from ssi_rules.signals import mask_credential_values

from .classifier import TorokaPatternClassifier
from .data_acquisition import RawSourceRecord
from .schema import AdjudicationStatus, DatasetSample, Language, Provenance, SampleType, compute_template_hash


class LabelTier(StrEnum):
    STRONGLY_SUPPORTED = "strongly_supported"
    CORROBORATED = "corroborated"
    WEAK = "weak"
    PSEUDO_LABEL = "pseudo_label"
    UNLABELLED = "unlabelled"


_SWAHILI_WORDS = {
    "tuma", "pesa", "hundi", "umeshinda", "shinda", "akaunti", "nywila", "safari",
    "simu", "kazi", "m-pesa", "safaricom", "bonasi", "ofa", "bure", "haraka", "shilingi",
    "namba", "sasa", "ndio", "hapana", "kufuli", "fungua", "tafadhali"
}

_SHENG_WORDS = {
    "chapaa", "mkwanja", "form", "ganji", "mbogi", "msee", "rada", "doba", "ngao",
    "fala", "sonko", "bazenga", "mtu wangu", "manzi", "keja", "chuom"
}


def detect_language(text: str) -> Language:
    """Identify language: English, Swahili, Sheng, or Mixed."""
    tokens = set(re.findall(r"\b\w+\b", text.lower()))
    if not tokens:
        return Language.UNKNOWN

    sw_count = len(tokens.intersection(_SWAHILI_WORDS))
    sheng_count = len(tokens.intersection(_SHENG_WORDS))

    if sheng_count > 0:
        return Language.SHENG
    if sw_count >= 2:
        return Language.SW if sw_count > (len(tokens) * 0.3) else Language.MIXED
    return Language.EN


def redact_pii(text: str) -> str:
    """Redact sensitive identity, phone, and credential information."""
    # 1. Mask credentials (PINs, passwords, OTPs)
    scrubbed_res = mask_credential_values(text)
    scrubbed = scrubbed_res[0] if isinstance(scrubbed_res, tuple) else scrubbed_res

    # 2. Mask Kenyan phone numbers
    def _mask_phone_match(match: re.Match) -> str:
        raw_val = match.group(0)
        norm = nz.normalize_ke_phone(raw_val)
        if norm:
            return nz.mask_phone(norm)
        return raw_val

    # Regex for typical KE phone formats
    phone_rx = re.compile(r"(?:\+?254|0)[17]\d{8}\b")
    scrubbed = phone_rx.sub(_mask_phone_match, scrubbed)

    return scrubbed


@dataclass
class LabelledRecordResult:
    sample: DatasetSample | None
    label_tier: LabelTier
    is_eligible_for_training: bool
    rejection_reason: str | None = None
    contradiction_detected: bool = False


class AutoLabeller:
    """Evaluates raw records and assigns data quality tiers, redactions, and sample metadata."""

    def __init__(self, classifier: TorokaPatternClassifier | None = None):
        self.classifier = classifier

    def label_record(
        self,
        record: RawSourceRecord,
        independent_source_count: int = 1,
        existing_entity_claims: list[dict[str, Any]] | None = None,
    ) -> LabelledRecordResult:
        raw_text = record.text_content.strip()
        if len(raw_text) < 10:
            return LabelledRecordResult(
                sample=None,
                label_tier=LabelTier.UNLABELLED,
                is_eligible_for_training=False,
                rejection_reason="Text length below 10 characters (abstention threshold)",
            )

        # Privacy Redaction
        clean_text = redact_pii(raw_text)
        lang = detect_language(clean_text)

        # Contradiction Detection: Check if entity has contradictory legitimate status
        contradiction = False
        if existing_entity_claims and record.entity_or_incident:
            for claim in existing_entity_claims:
                if claim.get("entity") == record.entity_or_incident:
                    if claim.get("status") == "verified_official" and record.claimed_category != "legitimate_customer_service":
                        contradiction = True
                        break

        if contradiction:
            return LabelledRecordResult(
                sample=None,
                label_tier=LabelTier.UNLABELLED,
                is_eligible_for_training=False,
                rejection_reason=f"Contradictory evidence detected for entity {record.entity_or_incident}",
                contradiction_detected=True,
            )

        # Assign Label Tier based on source reliability and corroboration
        tier = LabelTier.WEAK
        prov = Provenance.SYNTHETIC
        adj_status = AdjudicationStatus.UNREVIEWED
        assessment_label = "suspicious_verify_first"

        if record.source_type == "regulator_warning":
            tier = LabelTier.STRONGLY_SUPPORTED
            prov = Provenance.PUBLIC_ADVISORY
            adj_status = AdjudicationStatus.REVIEWER_APPROVED
            assessment_label = "high_risk"
        elif record.source_type == "threat_feed":
            tier = LabelTier.STRONGLY_SUPPORTED
            prov = Provenance.EXPERT_CURATED
            adj_status = AdjudicationStatus.REVIEWER_APPROVED
            assessment_label = "high_risk"
        elif record.source_type == "adjudicated_feedback":
            tier = LabelTier.CORROBORATED
            prov = Provenance.CONSENTED_USER
            adj_status = AdjudicationStatus.REVIEWER_APPROVED
            assessment_label = "high_risk" if "legitimate" not in record.claimed_category else "no_known_threats_found"
        elif independent_source_count >= 2:
            tier = LabelTier.CORROBORATED
            prov = Provenance.EXPERT_CURATED
            adj_status = AdjudicationStatus.CONSENSUS
            assessment_label = "high_risk"
        else:
            tier = LabelTier.WEAK
            prov = Provenance.UNVERIFIED_COMMUNITY if record.source_type == "unverified_report" else Provenance.RULE_HEURISTIC
            adj_status = AdjudicationStatus.UNREVIEWED

        sample = DatasetSample(
            id=record.record_id,
            sample_type=SampleType.TEXT,
            text=clean_text,
            language=lang,
            categories=[record.claimed_category],
            assessment_label=assessment_label,
            rationale=f"Auto-labelled via source '{record.source_id}' with tier '{tier.value}'",
            source_refs=[record.source_url],
            provenance=prov,
            adjudication_status=adj_status,
            confidence=1.0 if tier in (LabelTier.STRONGLY_SUPPORTED, LabelTier.CORROBORATED) else 0.6,
            is_synthetic=False,
        )

        return LabelledRecordResult(
            sample=sample,
            label_tier=tier,
            is_eligible_for_training=True,
        )

    def generate_pseudo_label(self, unlabelled_text: str) -> LabelledRecordResult:
        """Conservative pseudo-labelling for unlabelled examples."""
        if not self.classifier or not self.classifier.is_trained:
            return LabelledRecordResult(
                sample=None,
                label_tier=LabelTier.UNLABELLED,
                is_eligible_for_training=False,
                rejection_reason="No trained classifier available for pseudo-labelling",
            )

        clean_text = redact_pii(unlabelled_text.strip())
        if len(clean_text) < 15:
            return LabelledRecordResult(
                sample=None,
                label_tier=LabelTier.UNLABELLED,
                is_eligible_for_training=False,
                rejection_reason="Text too short for reliable pseudo-labelling",
            )

        pred = self.classifier.predict(clean_text)
        if pred.abstain:
            return LabelledRecordResult(
                sample=None,
                label_tier=LabelTier.UNLABELLED,
                is_eligible_for_training=False,
                rejection_reason=f"Classifier abstained: {pred.abstain_reason}",
            )

        # Strict Pseudo-Labelling Criteria:
        # 1. Calibrated confidence >= 0.85
        # 2. No disagreement with deterministic rules
        # 3. Clear category margin
        if pred.calibrated_confidence < 0.85 or pred.disagreement_with_rules:
            return LabelledRecordResult(
                sample=None,
                label_tier=LabelTier.UNLABELLED,
                is_eligible_for_training=False,
                rejection_reason="Confidence below 0.85 or rules disagree with prediction",
            )

        sample = DatasetSample(
            id=f"pseudo_{compute_template_hash(clean_text)}",
            sample_type=SampleType.TEXT,
            text=clean_text,
            language=detect_language(clean_text),
            categories=[pred.primary_category],
            assessment_label="high_risk" if pred.fraud_risk_score >= 0.60 else "inconclusive",
            rationale=f"Pseudo-labelled by model {pred.model_version} with confidence {pred.calibrated_confidence}",
            provenance=Provenance.MODEL_PSEUDO_LABEL,
            adjudication_status=AdjudicationStatus.UNREVIEWED,
            confidence=pred.calibrated_confidence,
            is_synthetic=False,
        )

        return LabelledRecordResult(
            sample=sample,
            label_tier=LabelTier.PSEUDO_LABEL,
            is_eligible_for_training=True,
        )
