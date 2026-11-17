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
    available_items: dict[str, Any] = {}
    for item in evidence_context.items:
        available_items[item.evidence_id] = item
        if item.source_record_id:
            available_items[item.source_record_id] = item
        if item.evidence_id.startswith("ev:event:"):
            available_items[item.evidence_id[len("ev:event:"):]] = item
        if item.evidence_id.startswith("ev:case:"):
            available_items[item.evidence_id[len("ev:case:"):]] = item
        available_items[f"ev:event:{item.evidence_id}"] = item

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


def validate_report_markdown(
    report_markdown: str,
    evidence_context: EvidenceContext,
) -> tuple[str, bool, dict[str, Any]]:
    """Validates structural grounding, citations, and quotes in report markdown against evidence context.
    
    Enforces that:
    1. All [Cites: ev_id] references exist in the supplied evidence context.
    2. Unknown or removed evidence IDs are rejected.
    3. Empty citation blocks or empty markdown are rejected.
    4. Exact quoted excerpts match evidence excerpts.
    5. Speculative assertions without cited evidence are flagged.
    """
    clean_text = report_markdown.strip() if report_markdown else ""
    if not clean_text:
        return "", False, {"valid": False, "flags": ["Report text is empty"], "citations_count": 0}

    available_items: dict[str, Any] = {}
    for item in evidence_context.items:
        available_items[item.evidence_id] = item
        if item.source_record_id:
            available_items[item.source_record_id] = item
        if item.evidence_id.startswith("ev:event:"):
            available_items[item.evidence_id[len("ev:event:"):]] = item
        if item.evidence_id.startswith("ev:case:"):
            available_items[item.evidence_id[len("ev:case:"):]] = item
        available_items[f"ev:event:{item.evidence_id}"] = item
    flags: list[str] = []
    unknown_ids: list[str] = []
    all_cites: list[str] = []

    # 1. Parse citations
    citation_matches = list(re.finditer(r"\[(?:Cites:|ev:)\s*([^\]]+)\]", clean_text))
    if not citation_matches:
        flags.append("Report lacks mandatory evidence citations [Cites: ev_id]")

    for match in citation_matches:
        cite_str = match.group(1).strip()
        ids = [i.strip() for i in cite_str.split(",") if i.strip()]
        if not ids:
            flags.append("Empty citation block [Cites: ] found")
        for ev_id in ids:
            all_cites.append(ev_id)
            if ev_id not in available_items:
                unknown_ids.append(ev_id)
                flags.append(f"Report cites unknown or unauthorized evidence ID '{ev_id}'")

    # 2. Check quotes adjacent or preceding citation
    quote_matches = re.findall(r'["“]([^"”]{5,})["”]\s*\[(?:Cites:|ev:)\s*([^\]]+)\]', clean_text)
    for quote_str, cite_str in quote_matches:
        cited_ids = [i.strip() for i in cite_str.split(",") if i.strip()]
        found_in_any = False
        for cid in cited_ids:
            if cid in available_items and text_contains_quote(available_items[cid].excerpt, quote_str):
                found_in_any = True
                break
        if not found_in_any:
            flags.append(f"Quoted excerpt '{quote_str[:60]}...' does not match cited evidence records")

    # 3. Speculative phrases without supporting evidence
    low = clean_text.lower()
    if "account takeover" in low and not any("takeover" in item.excerpt.lower() for item in available_items.values()):
        flags.append("Potential account takeover asserted without verified evidence record mentioning account compromise")

    is_valid = len(flags) == 0
    grounding_details = {
        "valid": is_valid,
        "flags": flags,
        "citations_count": len(all_cites),
        "unknown_evidence_ids": sorted(set(unknown_ids)),
        "available_evidence_count": len(available_items),
    }
    return clean_text, is_valid, grounding_details


def evidence_context_from_snapshot(snapshot: dict[str, Any]) -> EvidenceContext:
    """Rebuilds an exact immutable EvidenceContext from a persisted dictionary snapshot."""
    from .contracts import EvidenceItem
    items_data = snapshot.get("items", [])
    items: list[EvidenceItem] = []
    inst_id = str(snapshot.get("installation_id", "toroka-default-installation"))
    case_id = str(snapshot.get("case_id", ""))
    for d in items_data:
        if isinstance(d, dict):
            items.append(
                EvidenceItem.create(
                    evidence_id=str(d.get("evidence_id", "")),
                    installation_id=inst_id,
                    case_id=case_id,
                    source_system=str(d.get("source_system", "")),
                    source_record_id=str(d.get("source_record_id", "")),
                    excerpt=str(d.get("excerpt", "")),
                    title=str(d.get("title", "")),
                    record_type=str(d.get("event_type", "event")),
                )
            )
    return EvidenceContext(
        installation_id=inst_id,
        case_id=case_id,
        items=tuple(items),
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

