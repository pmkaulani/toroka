from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping
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

# Default (shopper-facing) conclusion text. A different product supplies its own via ScoringPolicy.conclusions.
DEFAULT_CONCLUSIONS: dict[str, str] = {
    "no_usable_evidence": "Toroka could not obtain enough current, attributable evidence to assess this target. This is not a finding that the seller is safe.",
    "high_risk": "Strong, attributable risk evidence was found. Do not send money or credentials until the specific findings are resolved.",
    "suspicious": "One or more meaningful risk indicators were found, but the available evidence does not establish every aspect of the seller's identity or intent.",
    "mixed_signals": "The available evidence conflicts. Treat the identity and payment route as unverified until the conflict is resolved.",
    "lower_observed_risk": "Multiple independent signals support the claimed identity, and no material risk signal was found in the checks completed. This is not a guarantee of legitimacy or delivery.",
    "insufficient_evidence": "The checks did not produce enough independent evidence for a reliable conclusion. Absence of reports or threat-feed hits must not be treated as proof of legitimacy.",
}


@dataclass(frozen=True, slots=True)
class ScoringPolicy:
    """Everything that was previously a hard-coded constant in assess().

    Defaults reproduce the original behaviour exactly. A product with different evidence
    (for example, case evidence about past events that must not decay) injects its own policy.
    """
    freshness_days: Mapping[str, int] = field(default_factory=lambda: FRESHNESS_DAYS)
    default_window_days: int = 180
    index_prior: float = 1.5
    critical_min_strength: int = 4
    critical_min_reliability: float = 0.85
    critical_min_confidence: float = 0.80
    high_risk_min_groups: int = 2
    high_risk_min_total: float = 4.0
    high_risk_dominance: float = 1.25
    suspicious_min_total: float = 1.6
    suspicious_dominance: float = 1.2
    mixed_min_each: float = 0.8
    lower_risk_min_support: float = 2.5
    lower_risk_max_risk: float = 0.8
    lower_risk_min_groups: int = 2
    conclusions: Mapping[str, str] = field(default_factory=lambda: DEFAULT_CONCLUSIONS)


DEFAULT_POLICY = ScoringPolicy()


def _effective_weight(item: Evidence, now: datetime, policy: ScoringPolicy = DEFAULT_POLICY) -> float:
    obs = item.observed_at
    if obs.tzinfo is None:
        obs = obs.replace(tzinfo=timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    age_days = max(0.0, (now - obs).total_seconds() / 86400)
    if item.expires_at:
        exp = item.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if now > exp:
            return 0.0
    window = policy.freshness_days.get(item.category, policy.default_window_days)
    decay = 0.5 ** (age_days / max(window, 1))
    return item.strength * item.reliability * item.confidence * decay


def _independent_totals(items: list[Evidence], polarity: str, now: datetime, policy: ScoringPolicy = DEFAULT_POLICY) -> tuple[float, set[str]]:
    grouped: dict[str, list[float]] = defaultdict(list)
    for item in items:
        if item.polarity == polarity:
            grouped[item.source_group].append(_effective_weight(item, now, policy))
    # Count only the strongest item from a shared source family, preventing copied reports
    # or mirrors of one feed from being counted as independent corroboration.
    return sum(max(v) for v in grouped.values() if v), set(grouped)


def assess(items: list[Evidence], now: datetime | None = None, policy: ScoringPolicy = DEFAULT_POLICY) -> tuple[Verdict, int | None, str, str]:
    now = now or datetime.now(timezone.utc)
    say = policy.conclusions
    risk, risk_groups = _independent_totals(items, "risk", now, policy)
    support, support_groups = _independent_totals(items, "support", now, policy)
    usable = [e for e in items if _effective_weight(e, now, policy) > 0]
    if not usable:
        return "insufficient_evidence", None, "low", say["no_usable_evidence"]

    # This index is deliberately not called a probability or a calibrated fraud likelihood.
    index = round(100 * risk / (risk + support + policy.index_prior)) if risk + support else None
    critical_confirmed = any(
        e.polarity == "risk" and e.verified and e.strength >= policy.critical_min_strength
        and e.reliability >= policy.critical_min_reliability and e.confidence >= policy.critical_min_confidence
        and _effective_weight(e, now, policy) > 0
        for e in usable
    )

    if critical_confirmed or (len(risk_groups) >= policy.high_risk_min_groups and risk >= policy.high_risk_min_total
                              and risk > support * policy.high_risk_dominance):
        verdict: Verdict = "high_risk"
        confidence = "high" if critical_confirmed or len(risk_groups) >= 3 else "moderate"
        conclusion = say["high_risk"]
    elif risk >= policy.suspicious_min_total and risk > support * policy.suspicious_dominance:
        verdict = "suspicious"
        confidence = "moderate" if len(risk_groups) >= 2 else "low"
        conclusion = say["suspicious"]
    elif risk >= policy.mixed_min_each and support >= policy.mixed_min_each:
        verdict = "mixed_signals"
        confidence = "moderate" if len(risk_groups | support_groups) >= 3 else "low"
        conclusion = say["mixed_signals"]
    elif (support >= policy.lower_risk_min_support and risk < policy.lower_risk_max_risk
          and len(support_groups) >= policy.lower_risk_min_groups):
        verdict = "lower_observed_risk"
        confidence = "high" if len(support_groups) >= 3 else "moderate"
        conclusion = say["lower_observed_risk"]
    else:
        verdict = "insufficient_evidence"
        confidence = "low"
        conclusion = say["insufficient_evidence"]

    return verdict, index, confidence, conclusion
