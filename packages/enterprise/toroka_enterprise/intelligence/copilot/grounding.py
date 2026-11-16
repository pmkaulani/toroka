from __future__ import annotations

import re
from dataclasses import dataclass
from .contracts import (
    ClaimKind,
    EvidenceContext,
    EvidenceQuote,
    GroundedClaim,
    InvestigationCopilotResponse,
)


class GroundingError(Exception):
    """Raised when an evidence citation or claim fails grounding validation."""
    pass


def normalize_text(value: str) -> str:
    """Normalize text by collapsing whitespace and stripping edges."""
    return re.sub(r"\s+", " ", value).strip()


def text_contains_quote(excerpt: str, quote: str) -> bool:
    """Checks whether quote appears in excerpt after whitespace and case normalization."""
    norm_excerpt = normalize_text(excerpt).lower()
    norm_quote = normalize_text(quote).lower()
    if not norm_quote:
        return False
    return norm_quote in norm_excerpt


@dataclass(frozen=True)
class GroundingReport:
    valid: bool
    verified_claims: int
    rejected_claims: tuple[str, ...]
    rejection_reasons: tuple[str, ...]

    @property
    def total_claims(self) -> int:
        return self.verified_claims + len(self.rejected_claims)


def validate_claim(
    claim: GroundedClaim,
    evidence_context: EvidenceContext,
) -> None:
    """Validates that a claim meets grounding rules against the supplied evidence context.
    
    Raises:
        GroundingError: If citations are missing, IDs unknown, quotes mismatched,
                        or mandatory limitations/basis omitted.
    """
    available_items = {item.evidence_id: item for item in evidence_context.items}

    # 1. Check all referenced evidence IDs exist in current context
    for ev_id in claim.evidence_ids:
        if ev_id not in available_items:
            raise GroundingError(
                f"Claim '{claim.claim_id}' references unknown evidence ID '{ev_id}'. "
                "Evidence IDs must originate from the authorized evidence context."
            )

    # 2. Kind-specific validation
    if claim.kind == ClaimKind.FACT:
        if not claim.evidence_ids:
            raise GroundingError(
                f"Factual claim '{claim.claim_id}' must cite at least one supporting evidence record."
            )
        if not claim.quotes:
            raise GroundingError(
                f"Factual claim '{claim.claim_id}' must provide an exact supporting quote from evidence."
            )

        for quote in claim.quotes:
            if quote.evidence_id not in available_items:
                raise GroundingError(
                    f"Quote in claim '{claim.claim_id}' references missing evidence ID '{quote.evidence_id}'"
                )
            if quote.evidence_id not in claim.evidence_ids:
                raise GroundingError(
                    f"Quote evidence ID '{quote.evidence_id}' is not in claim's cited evidence IDs"
                )

            item = available_items[quote.evidence_id]
            if not text_contains_quote(item.excerpt, quote.quoted_text):
                raise GroundingError(
                    f"Quoted text '{quote.quoted_text[:80]}...' in claim '{claim.claim_id}' "
                    f"was not found in excerpt of evidence item '{quote.evidence_id}'."
                )

    elif claim.kind == ClaimKind.INFERENCE:
        if not claim.evidence_ids:
            raise GroundingError(
                f"Inference claim '{claim.claim_id}' must cite supporting evidence IDs."
            )
        if not claim.limitations or len(claim.limitations.strip()) < 5:
            raise GroundingError(
                f"Inference claim '{claim.claim_id}' must explicitly document its investigative limitations."
            )

    elif claim.kind == ClaimKind.RECOMMENDATION:
        if not claim.investigative_basis or len(claim.investigative_basis.strip()) < 5:
            raise GroundingError(
                f"Recommendation '{claim.claim_id}' must state its investigative basis "
                "(why it helps and what uncertainty it resolves)."
            )

    elif claim.kind == ClaimKind.UNKNOWN:
        if not claim.statement or len(claim.statement.strip()) < 5:
            raise GroundingError(
                f"Unknown statement '{claim.claim_id}' must clearly identify the missing information."
            )


def validate_response(
    response: InvestigationCopilotResponse,
    evidence_context: EvidenceContext,
) -> GroundingReport:
    """Evaluates all claims in a response against the provided evidence context."""
    verified_count = 0
    rejected_claims: list[str] = []
    rejection_reasons: list[str] = []

    for claim in response.claims:
        try:
            validate_claim(claim, evidence_context)
            verified_count += 1
        except GroundingError as exc:
            rejected_claims.append(claim.claim_id)
            rejection_reasons.append(str(exc))

    is_valid = len(rejected_claims) == 0
    return GroundingReport(
        valid=is_valid,
        verified_claims=verified_count,
        rejected_claims=tuple(rejected_claims),
        rejection_reasons=tuple(rejection_reasons),
    )


def filter_unsupported_claims(
    response: InvestigationCopilotResponse,
    evidence_context: EvidenceContext,
) -> InvestigationCopilotResponse:
    """Filters out ungrounded or invalid claims, returning a sanitized response."""
    valid_claims: list[GroundedClaim] = []
    rejected_claims: list[str] = []
    rejection_reasons: list[str] = []

    for claim in response.claims:
        try:
            validate_claim(claim, evidence_context)
            valid_claims.append(claim)
        except GroundingError as exc:
            rejected_claims.append(claim.claim_id)
            rejection_reasons.append(str(exc))

    report = GroundingReport(
        valid=len(rejected_claims) == 0,
        verified_claims=len(valid_claims),
        rejected_claims=tuple(rejected_claims),
        rejection_reasons=tuple(rejection_reasons),
    )

    # Return updated response with valid claims only
    from dataclasses import replace
    return replace(
        response,
        claims=tuple(valid_claims),
        grounding_report=report,
    )
