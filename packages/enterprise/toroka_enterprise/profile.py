"""The insider-investigation profile: scoring policy, wording and actions. Plugs into toroka_core's EvidenceEngine."""
from __future__ import annotations

from toroka_core.evidence.models import Evidence
from toroka_core.evidence.profile import EngineProfile
from toroka_core.evidence.scoring import DEFAULT_POLICY, ScoringPolicy

# Evidence about PAST events must not decay: a March posting is as relevant in November as in March.
PAST_EVENT_CATEGORIES = ("bank_audit_log", "customer_instruction", "payment_record", "service_record",
                         "ledger_record", "iam_record", "hr_record", "customer_master")

INSIDER_POLICY = ScoringPolicy(
    freshness_days={c: 36500 for c in PAST_EVENT_CATEGORIES},
    # Strength never exceeds 5, so no single rule hit can take the "critical confirmed" shortcut to high confidence.
    # A priority review must rest on corroboration across independent record sources.
    critical_min_strength=6,
    conclusions={**DEFAULT_POLICY.conclusions,
                 "no_usable_evidence": "No usable records were available. This is not a finding that activity was legitimate.",
                 "high_risk": "Independent records point to an unexplained sequence. Open a case for authorised review.",
                 "suspicious": "Some records are unexplained. Review the cited items before deciding whether to open a case.",
                 "mixed_signals": "Records conflict. Resolve the conflict before any escalation.",
                 "lower_observed_risk": "Independent records explain the activity. No anomaly found in the feeds checked.",
                 "insufficient_evidence": "The available feeds do not support a reliable conclusion either way."})


def insider_actions(verdict: str, evidence: list[Evidence], locations: list) -> list[str]:
    if verdict in {"high_risk", "suspicious"}:
        return ["Open a case for authorised investigators and preserve the cited records (audit log, instructions, payments, ledger).",
                "Verify with the customer through previously registered contact details, not details changed in the flagged sequence.",
                "Keep the staff identifier pseudonymised until a second authoriser approves revealing it.",
                "Record the alternative explanations considered before any referral."]
    if verdict == "mixed_signals":
        return ["Check that the supporting record is complete and authentic before escalating."]
    if verdict == "insufficient_evidence":
        return ["Obtain the feeds listed under 'could not check' before drawing a conclusion."]
    return []


INSIDER_PROFILE = EngineProfile(
    name="insider-investigation", scoring=INSIDER_POLICY,
    base_limitations=("This output is an investigative lead for authorised reviewers, not a finding of misconduct by any person.",
                      "Missing records can mean an integration or data-quality gap rather than a missing action.",
                      "Confirm each cited item against the original source system before acting."),
    risk_index_note="Triage signal index for ordering review work; not a probability and not an assessment of any individual.",
    confidence_note="Qualitative confidence in the independence and completeness of the records; not statistically calibrated.",
    action_builder=insider_actions)

LABELS = {"high_risk": "PRIORITY REVIEW", "suspicious": "REVIEW", "mixed_signals": "CONFLICTING RECORDS",
          "lower_observed_risk": "NO ANOMALY FOUND", "insufficient_evidence": "INSUFFICIENT RECORDS"}
SURFACED = ("PRIORITY REVIEW", "REVIEW", "CONFLICTING RECORDS")
