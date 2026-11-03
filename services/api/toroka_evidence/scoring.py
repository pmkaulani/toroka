from __future__ import annotations
from datetime import datetime, timezone
from collections import defaultdict
from .models import Evidence, Verdict

# Freshness windows reflect how quickly each class of evidence can go stale.
FRESHNESS_DAYS = {
    "threat_intelligence": 14,
    "phishing_report": 30,
    "business_listing": 180,
    "domain_registration": 3650,
    "user_report": 90,
    "official_registry": 365,
    "website_behavior": 30,
    "payment_claim": 30,
}


def _effective_weight(item: Evidence, now: datetime) -> float:
    age_days = max(0.0, (now - item.observed_at).total_seconds() / 86400)
    if item.expires_at and now > item.expires_at:
        return 0.0
    window = FRESHNESS_DAYS.get(item.category, 180)
    decay = 0.5 ** (age_days / max(window, 1))
    return item.strength * item.reliability * item.confidence * decay


def _independent_totals(items: list[Evidence], polarity: str, now: datetime) -> tuple[float, set[str]]:
    grouped: dict[str, list[float]] = defaultdict(list)
    for item in items:
        if item.polarity == polarity:
            grouped[item.source_group].append(_effective_weight(item, now))
    # Count only the strongest item from a shared source family, preventing copied reports
    # or mirrors of one feed from being counted as independent corroboration.
    return sum(max(v) for v in grouped.values() if v), set(grouped)


def assess(items: list[Evidence], now: datetime | None = None) -> tuple[Verdict, int | None, str, str]:
    now = now or datetime.now(timezone.utc)
    risk, risk_groups = _independent_totals(items, "risk", now)
    support, support_groups = _independent_totals(items, "support", now)
    usable = [e for e in items if _effective_weight(e, now) > 0]
    if not usable:
        return "insufficient_evidence", None, "low", "Toroka could not obtain enough current, attributable evidence to assess this target. This is not a finding that the seller is safe."

    # This index is deliberately not called a probability or a calibrated fraud likelihood.
    index = round(100 * risk / (risk + support + 1.5)) if risk + support else None
    critical_confirmed = any(
        e.polarity == "risk" and e.verified and e.strength >= 4
        and e.reliability >= 0.85 and e.confidence >= 0.80
        and _effective_weight(e, now) > 0
        for e in usable
    )

    if critical_confirmed or (len(risk_groups) >= 2 and risk >= 4.0 and risk > support * 1.25):
        verdict: Verdict = "high_risk"
        confidence = "high" if critical_confirmed or len(risk_groups) >= 3 else "moderate"
        conclusion = "Strong, attributable risk evidence was found. Do not send money or credentials until the specific findings are resolved."
    elif risk >= 1.6 and risk > support * 1.2:
        verdict = "suspicious"
        confidence = "moderate" if len(risk_groups) >= 2 else "low"
        conclusion = "One or more meaningful risk indicators were found, but the available evidence does not establish every aspect of the seller's identity or intent."
    elif risk >= 0.8 and support >= 0.8:
        verdict = "mixed_signals"
        confidence = "moderate" if len(risk_groups | support_groups) >= 3 else "low"
        conclusion = "The available evidence conflicts. Treat the identity and payment route as unverified until the conflict is resolved."
    elif support >= 2.5 and risk < 0.8 and len(support_groups) >= 2:
        verdict = "lower_observed_risk"
        confidence = "high" if len(support_groups) >= 3 else "moderate"
        conclusion = "Multiple independent signals support the claimed identity, and no material risk signal was found in the checks completed. This is not a guarantee of legitimacy or delivery."
    else:
        verdict = "insufficient_evidence"
        confidence = "low"
        conclusion = "The checks did not produce enough independent evidence for a reliable conclusion. Absence of reports or threat-feed hits must not be treated as proof of legitimacy."

    return verdict, index, confidence, conclusion
