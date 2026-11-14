"""Policy/profile injection for the evidence engine. Defaults must not change behaviour."""
import unittest
from datetime import datetime, timedelta, timezone

from toroka_evidence.engine import EvidenceEngine
from toroka_evidence.models import Evidence, InvestigationRequest
from toroka_evidence.profile import EngineProfile, SHOPPER_PROFILE, SHOPPER_LIMITATIONS
from toroka_evidence.scoring import DEFAULT_POLICY, ScoringPolicy, assess

NOW = datetime(2026, 11, 12, tzinfo=timezone.utc)


def _risk(category: str, days_old: int) -> Evidence:
    return Evidence(source="s", source_group="g", category=category, polarity="risk", summary="x",
                    strength=3, reliability=0.9, confidence=0.8, observed_at=NOW - timedelta(days=days_old))


class ScoringPolicyTests(unittest.TestCase):
    def test_explicit_default_policy_equals_implicit(self):
        items = [_risk("threat_intelligence", 1)]
        self.assertEqual(assess(items, NOW), assess(items, NOW, DEFAULT_POLICY))

    def test_old_case_evidence_decays_under_default_but_not_under_long_window(self):
        # 255-day-old event: default 180-day window halves it past one half-life and falls below the 'suspicious' floor.
        items = [_risk("bank_audit_log", 255)]
        self.assertEqual(assess(items, NOW)[0], "insufficient_evidence")
        policy = ScoringPolicy(freshness_days={"bank_audit_log": 36500})
        self.assertEqual(assess(items, NOW, policy)[0], "suspicious")

    def test_custom_conclusion_text_is_used(self):
        policy = ScoringPolicy(conclusions={**DEFAULT_POLICY.conclusions, "suspicious": "Investigative lead, not a finding."})
        verdict, _, _, conclusion = assess([_risk("bank_audit_log", 0)], NOW, policy)
        self.assertEqual(verdict, "suspicious")
        self.assertEqual(conclusion, "Investigative lead, not a finding.")

    def test_thresholds_are_injectable(self):
        strict = ScoringPolicy(suspicious_min_total=5.0)
        self.assertEqual(assess([_risk("user_report", 0)], NOW)[0], "suspicious")
        self.assertEqual(assess([_risk("user_report", 0)], NOW, strict)[0], "insufficient_evidence")


class EngineProfileTests(unittest.TestCase):
    def test_default_engine_keeps_shopper_wording(self):
        result = EvidenceEngine().investigate(InvestigationRequest(target="https://shop.example")).to_dict()
        self.assertEqual(result["limitations"][:3], list(SHOPPER_LIMITATIONS))
        self.assertIn("seller", result["risk_index_note"])
        self.assertTrue(any("live video" in a for a in result["recommended_actions"]))

    def test_custom_profile_replaces_limitations_actions_and_notes(self):
        profile = EngineProfile(
            name="insider", base_limitations=("An alert is a lead for authorised investigators, not proof.",),
            risk_index_note="Signal index for triage; not an assessment of any person.",
            action_builder=lambda verdict, evidence, locations: [f"open_case:{verdict}"],
        )
        result = EvidenceEngine(profile=profile).investigate(InvestigationRequest(target="CASE-1")).to_dict()
        self.assertEqual(result["limitations"], ["An alert is a lead for authorised investigators, not proof."])
        self.assertEqual(result["recommended_actions"], ["open_case:insufficient_evidence"])
        self.assertNotIn("seller", result["risk_index_note"])

    def test_profile_scoring_policy_reaches_the_engine(self):
        class P:
            name = "p"; is_configured = True
            def investigate(self, request):
                return [_risk("bank_audit_log", 255)]
        default = EvidenceEngine(providers=[P()]).investigate(InvestigationRequest(target="t"))
        longer = EvidenceEngine(providers=[P()], profile=EngineProfile(
            scoring=ScoringPolicy(freshness_days={"bank_audit_log": 36500}))).investigate(InvestigationRequest(target="t"))
        self.assertEqual(default.verdict, "insufficient_evidence")
        self.assertEqual(longer.verdict, "suspicious")

    def test_shopper_profile_is_the_default(self):
        self.assertIs(EvidenceEngine().profile, SHOPPER_PROFILE)


if __name__ == "__main__":
    unittest.main()
