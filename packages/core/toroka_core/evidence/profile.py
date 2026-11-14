"""Engine profiles: everything product-specific that used to be hard-coded inside EvidenceEngine.

SHOPPER_PROFILE reproduces the original behaviour byte-for-byte. Another product (for example an
enterprise insider-risk investigation) supplies its own profile instead of forking the engine.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable
from .models import Evidence, LocationMatch
from .scoring import DEFAULT_POLICY, ScoringPolicy

ActionBuilder = Callable[[str, "list[Evidence]", "list[LocationMatch]"], "list[str]"]

SHOPPER_LIMITATIONS: tuple[str, ...] = (
    "Automated checks evaluate public signals; they cannot guarantee that goods will be delivered or that a payment recipient is honest.",
    "Do not treat missing complaints, a clean threat-feed result, an old domain, or a map pin as proof of legitimacy.",
    "A social-media platform URL is not evidence that the account owner controls a separate website or physical shop.",
)
SHOPPER_RISK_INDEX_NOTE = "Evidence-weighted signal index, not a probability that the seller is fraudulent."
SHOPPER_CONFIDENCE_NOTE = "Qualitative confidence in the available evidence assessment; not a statistically calibrated probability."


def shopper_actions(verdict: str, evidence: list[Evidence], locations: list[LocationMatch]) -> list[str]:
    actions: list[str] = []
    if verdict in {"high_risk", "suspicious", "mixed_signals", "insufficient_evidence"}:
        actions.extend([
            "Do not pay a personal number or unfamiliar till/paybill solely because the seller sent it; independently verify the recipient and business relationship.",
            "Ask for a live video showing the item, current date, shop identity, and dispatch process; reverse-search product photos independently.",
            "Use a payment method with a dispute path, and avoid deposits or fees to unlock a prize, job, grant, refund, or delivery.",
        ])
    if not locations:
        actions.append("No matching physical shop location was verified in the checks completed. Ask the seller for a precise location and independently confirm it before visiting or paying.")
    elif locations:
        actions.append("Treat map results as candidate listings only. Confirm the phone number, website, exact premises, and seller identity independently.")
    if not evidence:
        actions.append("Provide the seller's own website, phone number, payment recipient, or a screenshot of the offer so additional checks can be run.")
    return actions


@dataclass(frozen=True, slots=True)
class EngineProfile:
    name: str = "shopper"
    scoring: ScoringPolicy = DEFAULT_POLICY
    base_limitations: tuple[str, ...] = SHOPPER_LIMITATIONS
    risk_index_note: str = SHOPPER_RISK_INDEX_NOTE
    confidence_note: str = SHOPPER_CONFIDENCE_NOTE
    action_builder: ActionBuilder = shopper_actions


SHOPPER_PROFILE = EngineProfile()
