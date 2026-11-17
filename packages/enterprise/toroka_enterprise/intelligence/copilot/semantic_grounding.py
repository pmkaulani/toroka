"""Semantic Claim-Level Entailment & Anti-Hallucination Grounding.

Goes beyond lexical substring quote matching to evaluate semantic entailment,
polarity contradictions, and hallucinated financial figures in investigation copilot claims.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .contracts import (
    ClaimKind,
    EvidenceContext,
    EvidenceItem,
    EvidenceQuote,
    GroundedClaim,
)


class EntailmentStatus(StrEnum):
    ENTAILMENT = "ENTAILMENT"
    CONTRADICTION = "CONTRADICTION"
    NUMERIC_MISMATCH = "NUMERIC_MISMATCH"
    UNGROUNDED = "UNGROUNDED"


POSITIVE_POLARITY_TERMS = {
    "authorized", "authorises", "authorizes", "authorised",
    "confirmed", "confirms", "verified", "verifies",
    "approved", "approves", "legitimate", "valid",
    "acknowledged", "acknowledges", "successful", "completed",
    "cleared", "normal", "genuine", "received", "credited",
    "settled", "paid"
}

NEGATIVE_POLARITY_TERMS = {
    "unauthorized", "unauthorised", "denied", "denies",
    "rejected", "rejects", "failed", "fails",
    "declined", "declines", "fraudulent", "fraud",
    "disputed", "disputes", "scam", "mule", "stolen",
    "never", "not", "refused", "refuses", "compromised"
}


@dataclass(frozen=True)
class ClaimSemanticEvaluation:
    claim_id: str
    status: EntailmentStatus
    claim_text: str
    polarity: str  # POSITIVE, NEGATIVE, NEUTRAL
    evidence_polarity: str  # POSITIVE, NEGATIVE, NEUTRAL
    extracted_claim_numbers: tuple[str, ...]
    extracted_evidence_numbers: tuple[str, ...]
    reason: str
    cited_evidence_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "claim_id": self.claim_id,
            "status": self.status.value,
            "claim_text": self.claim_text,
            "polarity": self.polarity,
            "evidence_polarity": self.evidence_polarity,
            "extracted_claim_numbers": list(self.extracted_claim_numbers),
            "extracted_evidence_numbers": list(self.extracted_evidence_numbers),
            "reason": self.reason,
            "cited_evidence_ids": list(self.cited_evidence_ids),
        }


@dataclass(frozen=True)
class SemanticGroundingReport:
    is_valid: bool
    total_claims: int
    entailed_claims: int
    contradicted_claims: int
    numeric_mismatches: int
    ungrounded_claims: int
    evaluations: tuple[ClaimSemanticEvaluation, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "total_claims": self.total_claims,
            "entailed_claims": self.entailed_claims,
            "contradicted_claims": self.contradicted_claims,
            "numeric_mismatches": self.numeric_mismatches,
            "ungrounded_claims": self.ungrounded_claims,
            "evaluations": [e.to_dict() for e in self.evaluations],
        }


def extract_numbers_and_amounts(text: str) -> list[str]:
    """Extracts numeric quantities, currency sums, and integers from text."""
    # Matches numbers with optional commas and decimals (e.g. 50,000, 1500.50, 254712345678)
    matches = re.findall(r"\b\d+(?:,\d{3})*(?:\.\d+)?\b", text)
    # Normalize by removing commas
    return [m.replace(",", "") for m in matches]


def determine_polarity(text: str) -> str:
    """Classifies the semantic polarity of a text snippet."""
    tokens = set(re.findall(r"\b[A-Za-z_-]+\b", text.lower()))
    has_pos = bool(tokens & POSITIVE_POLARITY_TERMS)
    has_neg = bool(tokens & NEGATIVE_POLARITY_TERMS)

    if has_neg and not has_pos:
        return "NEGATIVE"
    if has_pos and not has_neg:
        return "POSITIVE"
    if has_neg and has_pos:
        # Prioritize negative if negation particles are present
        return "NEGATIVE"
    return "NEUTRAL"


def evaluate_claim_semantics(
    claim: GroundedClaim,
    evidence_context: EvidenceContext,
) -> ClaimSemanticEvaluation:
    """Evaluates semantic entailment, polarity match, and numerical grounding for a single claim."""
    # Find matching evidence excerpts
    items_by_id = {item.evidence_id: item for item in evidence_context.items}
    for item in evidence_context.items:
        if item.source_record_id:
            items_by_id[item.source_record_id] = item
        if item.evidence_id.startswith("ev:event:"):
            items_by_id[item.evidence_id[len("ev:event:"):]] = item

    cited_items = [items_by_id[eid] for eid in claim.evidence_ids if eid in items_by_id]

    if not cited_items and claim.kind == ClaimKind.FACT:
        return ClaimSemanticEvaluation(
            claim_id=claim.claim_id,
            status=EntailmentStatus.UNGROUNDED,
            claim_text=claim.statement,
            polarity="NEUTRAL",
            evidence_polarity="NEUTRAL",
            extracted_claim_numbers=(),
            extracted_evidence_numbers=(),
            reason="Factual claim lacks cited evidence records in context",
            cited_evidence_ids=claim.evidence_ids,
        )

    # Aggregate cited evidence text
    evidence_text = " ".join(item.excerpt for item in cited_items)

    claim_polarity = determine_polarity(claim.statement)
    evidence_polarity = determine_polarity(evidence_text)

    claim_numbers = extract_numbers_and_amounts(claim.statement)
    evidence_numbers = extract_numbers_and_amounts(evidence_text)

    # 1. Polarity Contradiction Check
    if claim_polarity == "POSITIVE" and evidence_polarity == "NEGATIVE":
        return ClaimSemanticEvaluation(
            claim_id=claim.claim_id,
            status=EntailmentStatus.CONTRADICTION,
            claim_text=claim.statement,
            polarity=claim_polarity,
            evidence_polarity=evidence_polarity,
            extracted_claim_numbers=tuple(claim_numbers),
            extracted_evidence_numbers=tuple(evidence_numbers),
            reason=f"Claim asserts positive authorization/action, but cited evidence asserts negative/fraud denial",
            cited_evidence_ids=claim.evidence_ids,
        )

    if claim_polarity == "NEGATIVE" and evidence_polarity == "POSITIVE":
        return ClaimSemanticEvaluation(
            claim_id=claim.claim_id,
            status=EntailmentStatus.CONTRADICTION,
            claim_text=claim.statement,
            polarity=claim_polarity,
            evidence_polarity=evidence_polarity,
            extracted_claim_numbers=tuple(claim_numbers),
            extracted_evidence_numbers=tuple(evidence_numbers),
            reason=f"Claim asserts negative/fraudulent status, but cited evidence asserts legitimate/authorized completion",
            cited_evidence_ids=claim.evidence_ids,
        )

    # 2. Financial Amount & Numeric Hallucination Check
    evidence_num_set = set(evidence_numbers)
    # Check if any significant financial amount (>100) in claim is absent in evidence
    missing_numbers = [num for num in claim_numbers if float(num) >= 100.0 and num not in evidence_num_set]
    if missing_numbers:
        return ClaimSemanticEvaluation(
            claim_id=claim.claim_id,
            status=EntailmentStatus.NUMERIC_MISMATCH,
            claim_text=claim.statement,
            polarity=claim_polarity,
            evidence_polarity=evidence_polarity,
            extracted_claim_numbers=tuple(claim_numbers),
            extracted_evidence_numbers=tuple(evidence_numbers),
            reason=f"Claim introduces ungrounded financial figures not found in cited evidence: {missing_numbers}",
            cited_evidence_ids=claim.evidence_ids,
        )

    # 3. Successful Entailment
    return ClaimSemanticEvaluation(
        claim_id=claim.claim_id,
        status=EntailmentStatus.ENTAILMENT,
        claim_text=claim.statement,
        polarity=claim_polarity,
        evidence_polarity=evidence_polarity,
        extracted_claim_numbers=tuple(claim_numbers),
        extracted_evidence_numbers=tuple(evidence_numbers),
        reason="Claim is semantically entailed by evidence without contradiction or numeric hallucination",
        cited_evidence_ids=claim.evidence_ids,
    )


def verify_report_semantics(
    claims: tuple[GroundedClaim, ...] | list[GroundedClaim],
    evidence_context: EvidenceContext,
) -> SemanticGroundingReport:
    """Verifies an entire investigation copilot claim set against semantic entailment rules."""
    evals = [evaluate_claim_semantics(c, evidence_context) for c in claims]

    entailed = sum(1 for e in evals if e.status == EntailmentStatus.ENTAILMENT)
    contradicted = sum(1 for e in evals if e.status == EntailmentStatus.CONTRADICTION)
    numeric_mismatches = sum(1 for e in evals if e.status == EntailmentStatus.NUMERIC_MISMATCH)
    ungrounded = sum(1 for e in evals if e.status == EntailmentStatus.UNGROUNDED)

    is_valid = contradicted == 0 and numeric_mismatches == 0 and ungrounded == 0

    return SemanticGroundingReport(
        is_valid=is_valid,
        total_claims=len(evals),
        entailed_claims=entailed,
        contradicted_claims=contradicted,
        numeric_mismatches=numeric_mismatches,
        ungrounded_claims=ungrounded,
        evaluations=tuple(evals),
    )
