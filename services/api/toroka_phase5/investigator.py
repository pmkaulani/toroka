from __future__ import annotations

from typing import Any, Callable
from datetime import datetime, timezone
import re

from .conversation_analysis import ConversationMessage, analyze_conversation
from .fusion import fuse_evidence
from .models import ArtifactInput, EvidenceSignal, InvestigationSummary
from .model_shadow import ModelPrediction, run_shadow_model
from .receipt_analysis import analyze_receipt_text
from .privacy import safe_excerpt


def _safe_timestamp(value: Any) -> str:
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass
    return datetime.now(timezone.utc).isoformat()


def _bounded_confidence(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number or number in {float("inf"), float("-inf")}:
        return None
    return max(0.0, min(1.0, number))


def _phase4_dict(value: Any) -> dict | None:
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    if hasattr(value, "to_dict"):
        result = value.to_dict()
        return result if isinstance(result, dict) else None
    raise TypeError("phase4_results must be dictionaries or objects with to_dict()")


class Phase5Investigator:
    """Orchestrates already-extracted artifacts and optional Phase 4 outputs.

    OCR/image parsing and external provider calls remain host-application adapters.
    This class never stores the supplied artifact text.
    """

    def investigate(self, *, case_ref: str, artifacts: list[ArtifactInput],
                    phase4_results: list[Any] | None = None,
                    phase3_relationships: list[dict[str, Any]] | None = None,
                    expected_payment: dict[str, Any] | None = None,
                    conversation: list[ConversationMessage] | None = None,
                    shadow_predictor: Callable[[dict[str, Any]], ModelPrediction] | None = None) -> InvestigationSummary:
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,80}", case_ref or "") or re.fullmatch(r"0?7\d{8}", case_ref or "") or re.fullmatch(r"2547\d{8}", case_ref or ""):
            raise ValueError("case_ref must be an opaque identifier, not a phone number")
        if not artifacts or len(artifacts) > 30:
            raise ValueError("provide 1-30 artifacts")
        if len({a.artifact_ref for a in artifacts}) != len(artifacts):
            raise ValueError("artifact_ref values must be unique")

        signals: list[EvidenceSignal] = []
        artifact_summaries: list[dict[str, Any]] = []
        known_refs = {a.artifact_ref for a in artifacts}
        limitations = [
            "Phase 5 consumes text extracted by the existing OCR/vision pipeline; it does not itself authenticate screenshots or receipts.",
            "Multiple analyses of the same artifact share one provenance reference and must not be counted as independent evidence.",
            "The final Toroka verdict remains owned by the existing Phase 2 assessor and human-review policy.",
        ]

        for artifact in artifacts:
            summary: dict[str, Any] = {
                "artifact_ref": artifact.artifact_ref,
                "artifact_type": artifact.artifact_type,
                "source_group": artifact.source_group,
                "language": artifact.language,
                "extracted_text_analyzed": True,
                "raw_text_returned": False,
            }
            if artifact.artifact_type == "mpesa_receipt_ocr":
                expected = expected_payment or {}
                receipt = analyze_receipt_text(
                    artifact.extracted_text, evidence_ref=artifact.artifact_ref,
                    source_group=artifact.source_group,
                    expected_amount=expected.get("amount"),
                    expected_recipient_identifier=expected.get("recipient_identifier"),
                    expected_recipient_name=expected.get("recipient_name"),
                )
                signals.extend(receipt.signals)
                summary["receipt_analysis"] = receipt.to_dict()
            else:
                # Phase 4 is the transparent phrase/threat/campaign layer. If its result
                # is supplied, it is adapted below; Phase 5 avoids duplicate phrase rules.
                summary["excerpt"] = safe_excerpt(artifact.extracted_text, limit=120)
            artifact_summaries.append(summary)

        for item in phase4_results or []:
            payload = _phase4_dict(item)
            if payload is None:
                continue
            content = payload.get("content_analysis", {}) or {}
            if not isinstance(content, dict):
                limitations.append("A malformed Phase 4 content result was ignored.")
                continue
            # The caller should set artifact_ref on an adapter payload so provenance is exact.
            ref = payload.get("artifact_ref")
            if not isinstance(ref, str) or ref not in known_refs:
                limitations.append("A Phase 4 result without a matching artifact_ref was not fused into risk indicators.")
                continue
            raw_signals = content.get("signals", [])
            if not isinstance(raw_signals, list):
                raw_signals = []
                limitations.append("Malformed Phase 4 signals were ignored.")
            for signal in raw_signals:
                if not isinstance(signal, dict):
                    continue
                sev = signal.get("severity", "context")
                pol = signal.get("polarity", "context")
                if sev not in {"critical", "high", "medium", "low", "context"} or pol not in {"risk", "context", "reassuring"}:
                    continue
                confidence = _bounded_confidence(signal.get("confidence", 0.5))
                category = str(signal.get("category", "phase4_signal"))[:80].lower()
                if confidence is None:
                    limitations.append("A Phase 4 signal with invalid confidence was ignored.")
                    continue
                if not re.fullmatch(r"[a-z0-9_:-]{1,80}", category):
                    limitations.append("A Phase 4 signal with an invalid category identifier was ignored.")
                    continue
                artifact = next(a for a in artifacts if a.artifact_ref == ref)
                raw_limits = signal.get("limitations", [])
                if not isinstance(raw_limits, list):
                    raw_limits = []
                signals.append(EvidenceSignal(
                    evidence_ref=ref, source_group=artifact.source_group,
                    category=category, severity=sev,
                    summary=safe_excerpt(str(signal.get("summary", "Phase 4 signal")), limit=300),
                    explanation=safe_excerpt(str(signal.get("reason", "Transparent rule signal from Phase 4.")), limit=800),
                    confidence=confidence,
                    excerpt=safe_excerpt(str(signal.get("excerpt", "")), limit=240), polarity=pol,
                    limitations=tuple(safe_excerpt(str(x), limit=240) for x in raw_limits[:8]),
                    observed_at=_safe_timestamp(content.get("analyzed_at")),
                ))
            raw_matches = payload.get("threat_matches", [])
            if not isinstance(raw_matches, list):
                raw_matches = []
                limitations.append("Malformed Phase 4 threat matches were ignored.")
            for match in raw_matches:
                if not isinstance(match, dict):
                    continue
                status = match.get("status")
                if status != "active":
                    continue
                # Threat feed is a separate provider family only when the Phase 4
                # integration supplies a registered provider source_group.
                # Preserve the provider's Phase 4 source family so the Phase 2 bridge
                # deduplicates the same feed observation instead of counting it twice.
                raw_provider_group = match.get("source_group")
                if isinstance(raw_provider_group, str) and re.fullmatch(r"[a-z0-9_-]{1,48}", raw_provider_group.lower()):
                    provider_group = "feed:" + raw_provider_group.lower()
                else:
                    provider_group = "threat_feed"
                provider_confidence = _bounded_confidence(match.get("confidence", 0.7))
                if provider_confidence is None:
                    limitations.append("A Phase 4 threat match with invalid confidence was ignored.")
                    continue
                signals.append(EvidenceSignal(
                    evidence_ref=ref, source_group=provider_group,
                    category="active_threat_feed_match", severity="high", polarity="risk",
                    summary="An active threat-feed indicator matched an artifact-derived domain.",
                    explanation="The indicator applies to the matched domain. It does not prove ownership or wrongdoing by a related shop or social profile.",
                    confidence=provider_confidence,
                    excerpt=safe_excerpt(str(match.get("indicator", "")), limit=120),
                    limitations=("Feed accuracy and freshness are provider-dependent.", "Domain association does not establish seller ownership."),
                    observed_at=_safe_timestamp(match.get("observed_at")),
                ))

        for link in phase3_relationships or []:
            if not isinstance(link, dict):
                limitations.append("A malformed Phase 3 relationship was ignored.")
                continue
            ref = link.get("artifact_ref")
            if not isinstance(ref, str) or ref not in known_refs:
                limitations.append("A Phase 3 relationship without a matching artifact_ref was not attached to this case.")
                continue
            relationship = str(link.get("relationship", "other"))[:64].lower()
            basis = str(link.get("basis", "unknown"))[:64].lower()
            status = str(link.get("status", "unverified"))[:32].lower()
            if not re.fullmatch(r"[a-z0-9_:-]{1,64}", relationship):
                relationship = "other"
            if not re.fullmatch(r"[a-z0-9_:-]{1,64}", basis):
                basis = "unknown"
            if not re.fullmatch(r"[a-z0-9_:-]{1,32}", status):
                status = "unverified"
            source_label = safe_excerpt(str(link.get("source_label", "Phase 3 entity graph")), limit=120)
            source_url_host = safe_excerpt(str(link.get("source_url", "")), limit=100)
            confidence = _bounded_confidence(link.get("match_confidence", 0.4))
            if confidence is None:
                confidence = 0.4
            verified_basis = status == "verified" and basis == "official_record_operator_checked"
            authenticated_basis = status == "verified" and basis == "authenticated_merchant_callback"
            provenance = "official_record" if verified_basis else ("other_trusted_source" if authenticated_basis else "user_submitted_artifact")
            link_limits = link.get("limitations", [])
            if not isinstance(link_limits, list):
                link_limits = []
            signals.append(EvidenceSignal(
                evidence_ref=ref, source_group=provenance,
                category="phase3_relationship_context", severity="context", polarity="context",
                summary="A Phase 3 relationship assertion connects identifiers associated with this investigation.",
                explanation=(f"Relationship type: {relationship}; basis: {basis}; assertion status: {status}. "
                             "This describes a relationship claim, not proof that the entities share ownership or that either is fraudulent."),
                confidence=confidence,
                excerpt=" · ".join(x for x in (source_label, source_url_host) if x),
                limitations=tuple(safe_excerpt(str(x), limit=240) for x in link_limits[:8]) +
                             ("Phase 3 relationship assertions never transfer a seller verdict automatically.",),
                observed_at=_safe_timestamp(link.get("observed_at")),
            ))

        if conversation:
            transcript_refs = {a.artifact_ref for a in artifacts if a.artifact_type == "chat_transcript"}
            if transcript_refs:
                ref = sorted(transcript_refs)[0]
                artifact = next(a for a in artifacts if a.artifact_ref == ref)
                convo = analyze_conversation(conversation, evidence_ref=ref, source_group=artifact.source_group)
                for row in convo["signals"]:
                    signals.append(EvidenceSignal(
                        evidence_ref=ref, source_group=artifact.source_group,
                        category=row["category"], severity=row["severity"], summary=row["summary"],
                        explanation=row["explanation"], confidence=row["confidence"],
                        excerpt=row["excerpt"], polarity=row["polarity"],
                        limitations=tuple(row["limitations"]), observed_at=row["observed_at"],
                    ))
                artifact_summaries.append({"artifact_ref": ref, "conversation_timeline": convo["timeline"],
                                           "message_count": convo["message_count"], "raw_messages_returned": False})
            else:
                limitations.append("Conversation analysis was skipped because no chat_transcript artifact was supplied.")

        fused = fuse_evidence(signals)
        model_result = None
        if shadow_predictor:
            safe_features = {
                "indicator_band": fused["indicator_band"],
                "evidence_strength": fused["evidence_strength"],
                "signal_categories": sorted({s.category for s in signals}),
                "signal_severities": sorted({s.severity for s in signals}),
                "source_group_count": fused["independent_source_groups"],
                "artifact_types": sorted({a.artifact_type for a in artifacts}),
            }
            model_result = run_shadow_model(shadow_predictor, safe_case_features=safe_features,
                                            known_evidence_refs=known_refs).to_dict()

        actions = []
        categories = {s.category for s in signals}
        if "receipt_amount_mismatch" in categories or "receipt_recipient_mismatch" in categories:
            actions.append("Pause any further payment. Compare the original receipt and order details, then verify through an independently sourced business contact or authorized payment-provider process.")
        if "conversation_credential_request" in categories or any(s.category == "credential_or_otp_request" for s in signals):
            actions.append("Never share an M-PESA PIN, password or OTP. Contact the organization through an independently verified official channel.")
        if fused["indicator_band"] in {"review_recommended", "elevated_signals"}:
            actions.append("Review the cited evidence and independently verify the seller, payment recipient and delivery terms before proceeding.")
        if not actions:
            actions.append("No decisive conclusion can be made from the supplied artifacts. Verify the seller and payment recipient independently before sending money.")

        limitations.extend(fused["limitations"])
        if model_result:
            limitations.append("The machine-learning result is shadow-only and cannot change the user-facing verdict.")
        return InvestigationSummary(
            case_ref=case_ref, indicator_band=fused["indicator_band"],
            evidence_strength=fused["evidence_strength"],
            independent_source_groups=fused["independent_source_groups"],
            evidence_count=fused["deduplicated_signal_count"], signals=signals,
            artifact_summaries=artifact_summaries, model_shadow=model_result,
            recommended_actions=actions, limitations=limitations,
        )
