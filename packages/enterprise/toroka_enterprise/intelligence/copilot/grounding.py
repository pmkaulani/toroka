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
    summary_valid: bool = True
    report_valid: bool = True
    summary_modifications: tuple[str, ...] = ()
    report_modifications: tuple[str, ...] = ()

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


def validate_summary_and_report_grounding(
    summary: str,
    report_markdown: str | None,
    valid_claims: list[GroundedClaim],
    evidence_context: EvidenceContext,
) -> tuple[str, str | None, bool, bool, list[str], list[str]]:
    """Strictly validates that executive summaries and drafted report texts do not make
    speculative assertions exceeding the verified claims and evidence context.
    
    If ungrounded fraud narratives (e.g. account takeover, unauthorized parameter change)
    are present without supporting factual claims with cited evidence IDs, they are
    neutralized to evidence-grounded statements.
    """
    summary_mods: list[str] = []
    report_mods: list[str] = []
    summary_valid = True
    report_valid = True

    # Identify concepts grounded in verified facts or inferences
    grounded_topics: set[str] = set()
    for c in valid_claims:
        low = c.statement.lower()
        if "takeover" in low or "compromise" in low:
            grounded_topics.add("takeover")
        if "transfer" in low or "fund movement" in low or "payment" in low:
            grounded_topics.add("transfer")
        if "parameter" in low or "beneficiary" in low:
            grounded_topics.add("beneficiary")
        if "credential" in low or "login" in low or "session" in low:
            grounded_topics.add("credential")

    clean_summary = summary
    summary_low = summary.lower()

    # Speculative ungrounded patterns
    speculative_checks = [
        ("account takeover", "takeover", "Potential account takeover asserted without verified evidence citations"),
        ("parameter adjustment", "beneficiary", "Parameter or beneficiary modification asserted without supporting evidence"),
        ("funds movement", "transfer", "Funds movement asserted without verified payment or transfer records"),
        ("credential stuffing", "credential", "Credential stuffing asserted without authentication telemetry evidence"),
    ]

    for phrase, required_topic, reason in speculative_checks:
        if phrase in summary_low and required_topic not in grounded_topics:
            summary_valid = False
            summary_mods.append(reason)

    if not summary_valid:
        # Neutralize speculative summary to strictly bounded facts
        ev_count = len(evidence_context.items)
        systems = sorted({item.source_system for item in evidence_context.items})
        sys_str = ", ".join(systems) if systems else "banking systems"
        clean_summary = (
            f"Synthesized evidence-grounded review of {ev_count} verified records across [{sys_str}]. "
            "Available records establish recorded event timestamps and system actions; they do not, on their own, "
            "establish unauthorized account takeover or fraudulent intent without independent customer authorization verification."
        )

    clean_report = report_markdown
    if report_markdown:
        report_low = report_markdown.lower()
        # Verify citation references in report markdown
        available_ids = {item.evidence_id for item in evidence_context.items}
        cited_in_report = re.findall(r"\[Cites:\s*([^\]]+)\]", report_markdown)
        for cite_group in cited_in_report:
            for ev_id in [c.strip() for c in cite_group.split(",") if c.strip()]:
                if ev_id not in available_ids:
                    report_valid = False
                    report_mods.append(f"Report cites unknown evidence ID '{ev_id}'")

        for phrase, required_topic, reason in speculative_checks:
            if phrase in report_low and required_topic not in grounded_topics:
                report_valid = False
                report_mods.append(f"Report text: {reason}")

        if not report_valid and clean_report:
            # Append strict disclaimer to draft report
            clean_report += "\n\n> [!CAUTION]\n> **Grounding Integrity Warning:** Unconfirmed speculative inferences in draft text have been flagged. All conclusions require verified customer service tickets before adjudication."

    return clean_summary, clean_report, summary_valid, report_valid, summary_mods, report_mods


def filter_unsupported_claims(
    response: InvestigationCopilotResponse,
    evidence_context: EvidenceContext,
) -> InvestigationCopilotResponse:
    """Filters out ungrounded claims, validates executive summary and report text,
    returning an evidence-grounded response with complete lineage.
    """
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

    # Validate executive summary and report draft grounding
    report_md = response.report_draft.content_markdown if response.report_draft else None
    clean_summary, clean_report_md, sum_valid, rep_valid, sum_mods, rep_mods = (
        validate_summary_and_report_grounding(
            response.summary,
            report_md,
            valid_claims,
            evidence_context,
        )
    )

    report = GroundingReport(
        valid=(len(rejected_claims) == 0 and sum_valid and rep_valid),
        verified_claims=len(valid_claims),
        rejected_claims=tuple(rejected_claims),
        rejection_reasons=tuple(rejection_reasons),
        summary_valid=sum_valid,
        report_valid=rep_valid,
        summary_modifications=tuple(sum_mods),
        report_modifications=tuple(rep_mods),
    )

    from dataclasses import replace
    updated_draft = response.report_draft
    if updated_draft and clean_report_md != updated_draft.content_markdown:
        updated_draft = replace(updated_draft, content_markdown=clean_report_md or "")

    return replace(
        response,
        summary=clean_summary,
        claims=tuple(valid_claims),
        report_draft=updated_draft,
        grounding_report=report,
        summary_grounded=sum_valid,
        report_grounded=rep_valid,
    )

