from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
import re

from .campaign import CampaignCase, CampaignCorrelator
from .content_analysis import ContentAnalysis, analyze_content
from .intel import ThreatIntelStore, ThreatMatch


@dataclass(slots=True)
class Phase4Result:
    case_ref: str
    content_analysis: ContentAnalysis
    threat_matches: list[ThreatMatch]
    campaign_links: list[dict[str, Any]]
    recommended_actions: list[str]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_ref": self.case_ref,
            "content_analysis": self.content_analysis.to_dict(),
            "threat_matches": [m.to_dict() for m in self.threat_matches],
            "campaign_links": self.campaign_links,
            "recommended_actions": self.recommended_actions,
            "limitations": self.limitations,
            "verdict_policy": "Phase 4 adds sourced signals and contextual correlations; it does not independently issue a final seller verdict.",
        }

    def to_phase2_evidence(self):
        """Convert eligible Phase 4 observations into Phase 2 Evidence objects, if installed."""
        try:
            from toroka_evidence.models import Evidence
        except ImportError as exc:
            raise RuntimeError("Install the Phase 2 toroka_evidence package before using this adapter") from exc
        evidence = []
        for signal in self.content_analysis.signals:
            polarity = "risk" if signal.polarity == "risk" else "context"
            strength = {"critical": 3, "high": 3, "medium": 2, "low": 1, "context": 1}.get(signal.severity, 1)
            evidence.append(Evidence(
                source="Toroka Phase 4 transparent content rules",
                source_group="toroka-content-patterns-v1",
                category=signal.category, polarity=polarity,
                summary=signal.summary,
                why_it_matters=signal.reason,
                strength=strength, reliability=0.58, confidence=signal.confidence,
                subject=self.case_ref,
                verified=False,
                limitations=list(signal.limitations) + ["Phrase-pattern match is not independent sender authentication."],
                metadata={"severity": signal.severity, "excerpt": signal.excerpt, "phase": 4},
            ))
        for match in self.threat_matches:
            active = match.status == "active"
            observed_at = datetime.fromisoformat(match.observed_at.replace("Z", "+00:00"))
            expires_at = (datetime.fromisoformat(match.expires_at.replace("Z", "+00:00"))
                          if match.expires_at else None)
            evidence.append(Evidence(
                source=match.source_name, source_group=match.source_group,
                category="external_threat_indicator_match",
                polarity="risk" if active and match.confidence >= 0.75 else "context",
                summary=f"A {match.indicator_type} threat indicator matched in {match.source_name} ({match.status}).",
                why_it_matters="A threat-feed match applies to the matched indicator, not automatically to every business or social profile associated with it.",
                strength=4 if active else 1, reliability=0.8, confidence=match.confidence,
                subject=match.indicator, source_url=match.reference_url or match.terms_url,
                observed_at=observed_at, expires_at=expires_at, verified=False,
                limitations=list(match.limitations) + [
                    "A current feed record is not independent authentication of the sender, seller or ownership."
                ],
                metadata={"phase": 4, "attribution": match.attribution, "match_status": match.status},
            ))
        for link in self.campaign_links:
            evidence.append(Evidence(
                source="Toroka Phase 4 campaign similarity analysis",
                source_group="toroka-campaign-correlation-v1",
                category="campaign_similarity_context", polarity="context",
                summary="This case resembles another Toroka investigation based on shared indicators or message structure.",
                why_it_matters="Campaign similarity can help identify coordinated activity, but copied templates and shared payment intermediaries can also occur in legitimate contexts.",
                strength=1, reliability=0.5, confidence=min(0.7, max(0.2, link.get("text_similarity", 0.4))),
                subject=self.case_ref, verified=False,
                limitations=[link.get("warning", "Similarity is not proof of common ownership or wrongdoing."),
                             "Related reports are not independent corroboration until separately reviewed."],
                metadata={"related_case_ref": link.get("related_case_ref"), "relation_basis": link.get("relation_basis"), "phase": 4},
            ))
        return evidence


_PHONE_RE = re.compile(r"(?<!\w)(?:\+?254\s?7\d{2}[\s-]?\d{3}[\s-]?\d{3}|0?7\d{2}[\s-]?\d{3}[\s-]?\d{3})(?!\w)")


def _normalize_ke_phone(raw: str) -> str:
    digits = re.sub(r"\D", "", raw)
    if digits.startswith("254") and len(digits) == 12:
        return "+" + digits
    if digits.startswith("0") and len(digits) == 10:
        return "+254" + digits[1:]
    if len(digits) == 9 and digits.startswith("7"):
        return "+254" + digits
    return digits


class Phase4Investigator:
    def __init__(self, *, intel_store: ThreatIntelStore | None = None,
                 campaign_correlator: CampaignCorrelator | None = None):
        self.intel_store = intel_store
        self.campaign_correlator = campaign_correlator

    def investigate_content(self, *, case_id: str, content: str, channel: str = "message",
                            source_group: str = "user-submitted", moderation_state: str = "pending") -> Phase4Result:
        analysis = analyze_content(content, channel=channel)
        matches: list[ThreatMatch] = []
        if self.intel_store:
            for domain in analysis.extracted_domains:
                matches.extend(self.intel_store.lookup_domain(domain))
        links: list[dict[str, Any]] = []
        case_ref = "case-local"
        if self.campaign_correlator:
            indicators: dict[str, list[str]] = {"domain": analysis.extracted_domains}
            indicators["phone"] = [_normalize_ke_phone(p) for p in _PHONE_RE.findall(content)]
            tactics = [s.category for s in analysis.signals if s.polarity == "risk"]
            related = self.campaign_correlator.add_case(CampaignCase(
                case_id=case_id, extracted_text=content, indicators=indicators,
                tactics=tactics, source_group=source_group, moderation_state=moderation_state,
            ))
            case_ref = "case-" + self.campaign_correlator._hash("case", case_id)[:10]
            links = [r.to_dict() for r in related]
        actions: list[str] = []
        categories = {s.category for s in analysis.signals}
        if "credential_or_otp_request" in categories:
            actions.append("Do not share an M-PESA PIN, password or OTP. Contact the organization through its independently verified official channel.")
        if categories & {"advance_fee_for_benefit", "job_or_recruitment_fee", "government_or_grant_fee"}:
            actions.append("Do not pay an upfront fee to release a prize, grant, public benefit or job opportunity before independently verifying the programme and recipient.")
        if "prize_or_betting_bait" in categories:
            actions.append("Treat unsolicited winnings, free-bet and bonus messages cautiously; do not open shortened links or pay a claim fee.")
        if matches and any(m.status == "active" for m in matches):
            actions.append("Avoid opening or paying through the matched domain until the threat-feed record and current domain state have been independently reviewed.")
        if not actions:
            actions.append("No decisive fraud conclusion can be made from the extracted message alone. Verify the sender, domain and payment recipient independently.")
        limitations = list(analysis.limitations)
        limitations.append("Campaign links are contextual and do not transfer another case's verdict to this case.")
        if any(m.status != "active" for m in matches):
            limitations.append("One or more matching threat indicators were expired or from stale feed snapshots; they are not current confirmed matches.")
        return Phase4Result(case_ref, analysis, matches, links, actions, limitations)
