import json
import os
import sqlite3
import tempfile
import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "toroka-phase-3"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "toroka-phase-2-inspect" / "toroka-phase-2"))
from datetime import datetime, timedelta, timezone

try:
    from toroka_phase3.identity_graph import EntityLinkGraph as _Phase3EntityLinkGraph
    PHASE3_AVAILABLE = True
except ImportError:
    _Phase3EntityLinkGraph = None
    PHASE3_AVAILABLE = False

try:
    from toroka_evidence.models import Evidence as _Phase2Evidence
    PHASE2_AVAILABLE = True
except ImportError:
    _Phase2Evidence = None
    PHASE2_AVAILABLE = False

from toroka_phase4 import (
    analyze_content, CampaignCase, CampaignCorrelator, FeedPolicy, IndicatorRecord,
    ThreatIntelStore, default_feed_policies, parse_stix21_bundle, refresh_feed,
    FeedbackLedger, EvaluationCase, evaluate, split_by_campaign, model_release_gate,
    Phase4Investigator,
)

SECRET = "phase4-test-secret-at-least-32-bytes"


class ContentAnalysisTests(unittest.TestCase):
    def test_unsolicited_free_bet_detected(self):
        result = analyze_content("Congratulations! You have won 5 FREE AVIATOR FREEBETS. Claim your prize now.")
        self.assertIn("prize_or_betting_bait", {s.category for s in result.signals})
        self.assertEqual(result.highest_severity, "medium")

    def test_grant_and_fee_combination_escalates_to_high(self):
        result = analyze_content("Government grant approved. Pay processing fee to receive your funds.")
        signals = {s.category: s for s in result.signals}
        self.assertEqual(signals["government_or_grant_fee"].severity, "high")
        self.assertIn("advance_fee_for_benefit", signals)

    def test_job_application_fee_detected(self):
        result = analyze_content("You are shortlisted. Pay the job application fee today.")
        self.assertIn("job_or_recruitment_fee", {s.category for s in result.signals})

    def test_account_pressure_is_detected(self):
        result = analyze_content("Your account will be suspended. Verify now or access will be blocked.")
        self.assertIn("account_pressure", {s.category for s in result.signals})

    def test_guaranteed_investment_return_detected(self):
        result = analyze_content("Earn guaranteed profits and double your money every week.")
        self.assertIn("guaranteed_investment_return", {s.category for s in result.signals})

    def test_delivery_customs_fee_detected(self):
        result = analyze_content("Your parcel is held. Pay customs fee to get delivery.")
        self.assertIn("delivery_or_customs_fee", {s.category for s in result.signals})

    def test_otp_request_is_critical(self):
        result = analyze_content("Reply with your M-PESA PIN and OTP to confirm the refund.")
        signal = next(s for s in result.signals if s.category == "credential_or_otp_request")
        self.assertEqual(signal.severity, "critical")

    def test_swahili_advance_fee_detected(self):
        result = analyze_content("Umeshinda zawadi. Lipa ada ya kutoa ili upate pesa.")
        categories = {s.category for s in result.signals}
        self.assertIn("advance_fee_for_benefit", categories)
        self.assertEqual(result.language_hint, "sw")

    def test_payment_instruction_alone_is_context_not_risk(self):
        result = analyze_content("Please pay the invoice using M-PESA Till 123456.")
        self.assertTrue(any(s.category == "payment_instruction_present" for s in result.signals))
        self.assertFalse(any(s.polarity == "risk" for s in result.signals))

    def test_brand_mention_is_not_impersonation_finding(self):
        result = analyze_content("Safaricom has announced a new service.")
        brand = next(s for s in result.signals if s.category == "brand_or_public_service_mentioned")
        self.assertEqual(brand.polarity, "context")

    def test_domain_extraction_strips_path_and_query(self):
        result = analyze_content("Visit https://shop.example.co.ke/reset/token-123?session=secret now")
        self.assertEqual(result.extracted_domains, ["shop.example.co.ke"])
        self.assertNotIn("token-123", json.dumps(result.to_dict()))
        self.assertNotIn("session=secret", json.dumps(result.to_dict()))
        excerpt = next(s.excerpt for s in result.signals if s.category == "advance_fee_for_benefit") if any(s.category == "advance_fee_for_benefit" for s in result.signals) else ""
        self.assertNotIn("token-123", excerpt)

    def test_phone_numbers_are_masked(self):
        result = analyze_content("Call 0712 345 678 for more information.")
        self.assertTrue(result.extracted_phones_masked)
        self.assertNotIn("0712", json.dumps(result.to_dict()))

    def test_excerpt_redacts_identifiers_and_receipt_numbers(self):
        result = analyze_content("Reply with your OTP 123456. National ID: 12345678. Receipt: QWERTY12345.")
        serialized = json.dumps(result.to_dict())
        self.assertNotIn("12345678", serialized)
        self.assertNotIn("QWERTY12345", serialized)

    def test_otp_codes_are_redacted_from_evidence_excerpt(self):
        result = analyze_content("Reply with your OTP 123456 to confirm your account.")
        self.assertNotIn("123456", json.dumps(result.to_dict()))
        self.assertIn("secret redacted", json.dumps(result.to_dict()))

    def test_raw_content_is_not_returned_or_stored(self):
        text = "private-user-message-should-not-appear-998877"
        result = analyze_content(text)
        self.assertFalse(result.raw_content_stored)
        self.assertNotIn(text, json.dumps(result.to_dict()))

    def test_unknown_channel_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_content("hello", channel="Kaulani phone")

    def test_oversized_input_is_capped(self):
        result = analyze_content("A" * 50_000, max_chars=100)
        self.assertFalse(result.raw_content_stored)


class ThreatIntelTests(unittest.TestCase):
    def setUp(self):
        self.store = ThreatIntelStore(commercial_mode=True)
        self.policy = FeedPolicy(
            name="TestFeed", source_group="testfeed", terms_url="https://example.test/terms",
            commercial_use_allowed=True, permission_confirmed=True, display_allowed=True,
            attribution="TestFeed attribution", freshness_ttl_hours=24,
        )
        self.store.register_feed(self.policy)

    def tearDown(self):
        self.store.close()

    def test_feed_without_registered_permission_is_rejected(self):
        policy = FeedPolicy("Unapproved", "x", "https://example.test", True, False, True, "x")
        with self.assertRaises(PermissionError):
            self.store.register_feed(policy)

    def test_noncommercial_feed_rejected_in_commercial_mode(self):
        policy = FeedPolicy("FreeOnly", "x", "https://example.test", False, True, True, "x")
        with self.assertRaises(PermissionError):
            self.store.register_feed(policy)

    def test_invalid_domain_indicator_rejected(self):
        with self.assertRaises(ValueError):
            self.store.upsert(IndicatorRecord("domain", "localhost", "TestFeed"))

    def test_url_indicator_strips_query(self):
        from toroka_phase4 import normalize_indicator
        normalized = normalize_indicator("url", "https://bad.example/reset/token-foo?otp=123")
        self.assertEqual(normalized, "https://bad.example/")
        self.assertNotIn("otp", normalized)

    def test_active_indicator_requires_fresh_feed_refresh(self):
        self.store.upsert(IndicatorRecord("domain", "bad.example", "TestFeed", confidence=0.91))
        match = self.store.lookup_domain("bad.example")[0]
        self.assertEqual(match.status, "stale_feed")
        self.store.mark_refresh("TestFeed", success=True)
        match = self.store.lookup_domain("bad.example")[0]
        self.assertEqual(match.status, "active")

    def test_feed_record_is_expired_when_valid_until_passed(self):
        expired = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        self.store.mark_refresh("TestFeed", success=True)
        self.store.upsert(IndicatorRecord("domain", "expired.example", "TestFeed", valid_until=expired))
        self.assertEqual(self.store.lookup_domain("expired.example")[0].status, "expired")

    def test_exact_domain_match_only_by_default(self):
        self.store.mark_refresh("TestFeed", success=True)
        self.store.upsert(IndicatorRecord("domain", "bad.example", "TestFeed"))
        self.assertEqual(self.store.lookup_domain("sub.bad.example"), [])

    def test_subdomain_match_is_explicit(self):
        self.store.mark_refresh("TestFeed", success=True)
        self.store.upsert(IndicatorRecord("domain", "bad.example", "TestFeed", include_subdomains=True))
        self.assertEqual(len(self.store.lookup_domain("sub.bad.example")), 1)

    def test_feed_refresh_not_due_returns_without_fetch(self):
        self.store.mark_refresh("TestFeed", success=True)
        result = refresh_feed(self.store, "TestFeed", lambda: (_ for _ in ()).throw(AssertionError("should not fetch")))
        self.assertEqual(result["status"], "not_due")

    def test_reference_url_tokens_are_removed(self):
        self.store.mark_refresh("TestFeed", success=True)
        self.store.upsert(IndicatorRecord("domain", "bad.example", "TestFeed",
                                           reference_url="https://feed.example/detail/123?token=secret"))
        result = self.store.lookup_domain("bad.example")[0]
        self.assertEqual(result.reference_url, "https://feed.example/")
        self.assertNotIn("secret", result.reference_url)

    def test_refresh_fetcher_imports_records(self):
        outcome = refresh_feed(self.store, "TestFeed", lambda: [IndicatorRecord("domain", "ioc.example", "TestFeed")])
        self.assertEqual(outcome["status"], "refreshed")
        self.assertEqual(outcome["imported"], 1)

    def test_failed_snapshot_validation_is_atomic(self):
        with self.assertRaises(ValueError):
            self.store.import_records([
                IndicatorRecord("domain", "good.example", "TestFeed"),
                IndicatorRecord("domain", "localhost", "TestFeed"),
            ], "TestFeed")
        self.assertEqual(self.store.lookup_domain("good.example"), [])

    def test_refresh_failure_does_not_delete_existing_indicators(self):
        self.store.upsert(IndicatorRecord("domain", "ioc.example", "TestFeed"))
        result = refresh_feed(self.store, "TestFeed", lambda: (_ for _ in ()).throw(TimeoutError()))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(self.store.lookup_domain("ioc.example")), 1)

    def test_stix21_bundle_parser_supports_domain_and_url(self):
        bundle = {"type": "bundle", "objects": [
            {"type": "indicator", "pattern": "[domain-name:value = 'bad.example']", "confidence": 90, "valid_from": "2026-01-01T00:00:00Z"},
            {"type": "indicator", "pattern": "[url:value = 'https://evil.example/login']", "confidence": 80},
            {"type": "indicator", "revoked": True, "pattern": "[domain-name:value = 'revoked.example']"},
        ]}
        records = parse_stix21_bundle(bundle, source_name="TestFeed")
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].confidence, 0.9)

    def test_stix_parser_rejects_non_bundle(self):
        with self.assertRaises(ValueError):
            parse_stix21_bundle({"type": "indicator"}, source_name="TestFeed")

    def test_phishtank_policy_is_only_enabled_after_operator_confirmation(self):
        policies = default_feed_policies(phishtank_permission_confirmed=True)
        policy = next(p for p in policies if p.name == "PhishTank")
        self.assertTrue(policy.commercial_use_allowed)
        self.assertTrue(policy.permission_confirmed)

    def test_urlhaus_commercial_policy_requires_confirmed_permission(self):
        policy = next(p for p in default_feed_policies() if p.name == "URLhaus")
        with self.assertRaises(PermissionError):
            self.store.register_feed(policy)
        approved = next(p for p in default_feed_policies(urlhaus_commercial_permission_confirmed=True) if p.name == "URLhaus")
        self.store.register_feed(approved)

    def test_default_policy_does_not_enable_vt_public_api(self):
        vt = next(p for p in default_feed_policies() if p.name == "VirusTotal Public API")
        with self.assertRaises(PermissionError):
            self.store.register_feed(vt)


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.tmp.close()
        self.corr = CampaignCorrelator(self.tmp.name, secret=SECRET)

    def tearDown(self):
        self.corr.close()
        os.unlink(self.tmp.name)

    def test_shared_domain_creates_contextual_link(self):
        self.corr.add_case(CampaignCase("case-1", "Claim your prize now. You won today.",
                                        {"domain": ["promo.example"]}, ["prize_or_betting_bait"], "sms"))
        links = self.corr.add_case(CampaignCase("case-2", "You have won. Claim your prize now.",
                                               {"domain": ["promo.example"]}, ["prize_or_betting_bait"], "whatsapp"))
        self.assertTrue(links)
        self.assertIn("shared_domain", links[0].relation_basis)

    def test_similar_templates_are_detected_without_same_domain(self):
        self.corr.add_case(CampaignCase("case-1", "Congratulations you have won claim your prize today now", {}, ["prize_or_betting_bait"], "sms"))
        links = self.corr.add_case(CampaignCase("case-2", "Congratulations you have won claim your prize today now", {}, ["prize_or_betting_bait"], "sms"))
        self.assertIn("similar_message_template", links[0].relation_basis)

    @unittest.skipUnless(PHASE3_AVAILABLE, "Phase 3 package is needed for cross-phase HMAC compatibility test")
    def test_phase3_domain_and_phone_digests_are_compatible(self):
        graph = _Phase3EntityLinkGraph(db_path=":memory:", secret=SECRET)
        self.assertEqual(self.corr.identifier_digest("domain", "https://Example.com/path"),
                         graph.identifier_digest("domain", "example.com"))
        self.assertEqual(self.corr.identifier_digest("phone", "0712 345 678"),
                         graph.identifier_digest("phone", "+254712345678"))

    def test_stored_case_content_and_identifiers_are_hashed(self):
        self.corr.add_case(CampaignCase("case-secret", "private text phrase should be hashed", {"phone": ["+254712345678"]}, [], "sms"))
        conn = sqlite3.connect(self.tmp.name)
        try:
            raw = conn.execute("SELECT * FROM campaign_cases").fetchone()
        finally:
            conn.close()
        serialized = json.dumps(raw)
        self.assertNotIn("private text phrase", serialized)
        self.assertNotIn("+254712345678", serialized)
        self.assertNotIn("case-secret", serialized)

    def test_pending_case_link_is_never_called_corroborated_by_default(self):
        self.corr.add_case(CampaignCase("case-1", "message that repeats a lot today", {"domain": ["a.example"]}, [], "sms", "pending"))
        links = self.corr.add_case(CampaignCase("case-2", "message that repeats a lot today", {"domain": ["a.example"]}, [], "whatsapp", "pending"))
        self.assertEqual(links[0].moderation_state, "pending")
        self.assertIn("not proof", links[0].warning)

    def test_duplicate_case_update_does_not_duplicate_rows(self):
        case = CampaignCase("same-id", "a b c d e f", {}, [], "sms")
        self.corr.add_case(case)
        self.corr.add_case(case)
        self.assertEqual(self.corr.case_count(), 1)

    def test_expired_cases_are_purged_after_matching_window(self):
        old = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
        self.corr.add_case(CampaignCase("old-case", "old campaign text has these tokens", {}, [], "sms", observed_at=old))
        self.assertEqual(self.corr.purge_expired(), 1)

    def test_arbitrary_tactic_and_source_text_are_rejected(self):
        with self.assertRaises(ValueError):
            self.corr.add_case(CampaignCase("case", "some words", {}, ["John Doe"], "sms"))
        with self.assertRaises(ValueError):
            self.corr.add_case(CampaignCase("case2", "some words", {}, [], "Peter's phone"))

    def test_case_can_be_purged(self):
        self.corr.add_case(CampaignCase("to-delete", "sample words should be hashed", {}, [], "sms"))
        self.assertTrue(self.corr.purge_case("to-delete"))
        self.assertEqual(self.corr.case_count(), 0)


class FeedbackTests(unittest.TestCase):
    def setUp(self):
        self.ledger = FeedbackLedger(secret=SECRET)

    def tearDown(self):
        self.ledger.close()

    def test_report_id_must_be_opaque_uuid(self):
        with self.assertRaises(ValueError):
            self.ledger.submit(case_id="1", claim_type="suspected_scam", features={}, opt_in_to_training=True,
                               campaign_id="c1", report_id="peter@example.com")

    def test_unreviewed_feedback_never_enters_training(self):
        fid = self.ledger.submit(case_id="1", claim_type="suspected_scam", features={"tactics": ["prize"]},
                                 opt_in_to_training=True, campaign_id="campaign-1")
        self.assertEqual(self.ledger.training_rows(minimum_campaigns=1), [])

    def test_user_claim_cannot_become_a_training_label_without_moderator_label(self):
        fid = self.ledger.submit(case_id="1", claim_type="suspected_scam", features={},
                                 opt_in_to_training=True, campaign_id="c1")
        with self.assertRaises(ValueError):
            self.ledger.review(fid, state="approved", reviewer_id="moderator", reviewer_authorized=True)

    def test_unauthorized_review_rejected(self):
        fid = self.ledger.submit(case_id="1", claim_type="suspected_scam", features={}, opt_in_to_training=True, campaign_id="c1")
        with self.assertRaises(PermissionError):
            self.ledger.review(fid, state="approved", reviewer_id="x", reviewer_authorized=False)

    def test_no_training_without_explicit_opt_in(self):
        fid = self.ledger.submit(case_id="1", claim_type="suspected_scam", features={"tactics": ["otp"]},
                                 opt_in_to_training=False, campaign_id="campaign-1")
        self.ledger.review(fid, state="approved", reviewer_id="moderator", reviewer_authorized=True,
                           reviewed_label="scam_confirmed")
        self.assertEqual(self.ledger.training_rows(minimum_campaigns=1), [])

    def test_approved_opted_in_data_can_be_read_after_min_campaign_threshold(self):
        for i in range(3):
            fid = self.ledger.submit(case_id=str(i), claim_type="suspected_scam" if i < 2 else "looks_legitimate",
                                     features={"tactics": ["prize"], "raw_phone": "0712345678"},
                                     opt_in_to_training=True, campaign_id=f"campaign-{i}")
            self.ledger.review(fid, state="approved", reviewer_id="moderator", reviewer_authorized=True,
                               reviewed_label="scam_confirmed" if i < 2 else "legitimate")
        rows = self.ledger.training_rows(minimum_campaigns=3)
        self.assertEqual(len(rows), 3)
        self.assertNotIn("raw_phone", json.dumps(rows))

    def test_features_reject_free_text_and_unknown_values(self):
        fid = self.ledger.submit(case_id="1", claim_type="suspected_scam",
                                 features={"channel": "Peter's phone", "language": "Kikuyu-ish personal note", "url_count": 1, "phone_count": "0712345678"},
                                 opt_in_to_training=True, campaign_id="c1")
        self.ledger.review(fid, state="approved", reviewer_id="moderator", reviewer_authorized=True,
                           reviewed_label="inconclusive")
        self.assertEqual(self.ledger.training_rows(minimum_campaigns=1), [])

    def test_inconclusive_records_are_excluded_from_training(self):
        fid = self.ledger.submit(case_id="1", claim_type="other", features={}, opt_in_to_training=True, campaign_id="c1")
        self.ledger.review(fid, state="approved", reviewer_id="moderator", reviewer_authorized=True,
                           reviewed_label="inconclusive")
        self.assertEqual(self.ledger.training_rows(minimum_campaigns=1), [])

    def test_feedback_review_is_audited(self):
        fid = self.ledger.submit(case_id="1", claim_type="looks_legitimate", features={}, opt_in_to_training=True, campaign_id="c1")
        self.ledger.review(fid, state="rejected", reviewer_id="moderator", reviewer_authorized=True, reason_code="insufficient_provenance")
        self.assertEqual(self.ledger.event_count(fid), 2)

    def test_review_cannot_be_overwritten(self):
        fid = self.ledger.submit(case_id="1", claim_type="looks_legitimate", features={}, opt_in_to_training=True, campaign_id="c1")
        self.ledger.review(fid, state="approved", reviewer_id="moderator", reviewer_authorized=True,
                           reviewed_label="legitimate")
        with self.assertRaises(ValueError):
            self.ledger.review(fid, state="rejected", reviewer_id="moderator", reviewer_authorized=True)


class EvaluationTests(unittest.TestCase):
    def test_confusion_metrics(self):
        rows = [
            EvaluationCase("1", "a", True, True), EvaluationCase("2", "b", False, True),
            EvaluationCase("3", "c", False, False), EvaluationCase("4", "d", True, False),
        ]
        report = evaluate(rows)
        self.assertEqual(report.true_positive, 1)
        self.assertEqual(report.false_positive, 1)
        self.assertEqual(report.true_negative, 1)
        self.assertEqual(report.false_negative, 1)
        self.assertEqual(report.precision, 0.5)
        self.assertEqual(report.recall, 0.5)

    def test_campaign_split_prevents_campaign_leakage(self):
        rows = [EvaluationCase(str(i), f"campaign-{i // 2}", bool(i % 2), bool(i % 3 == 0)) for i in range(40)]
        train, test = split_by_campaign(rows, test_fraction=0.25)
        self.assertFalse({r.campaign_id for r in train} & {r.campaign_id for r in test})

    def test_release_gate_requires_enough_samples_and_campaigns(self):
        report = evaluate([EvaluationCase("1", "campaign1", True, True)])
        gate = model_release_gate(report)
        self.assertFalse(gate["eligible_for_shadow_evaluation"])


class OrchestrationTests(unittest.TestCase):
    @unittest.skipUnless(PHASE2_AVAILABLE, "Phase 2 package is needed for adapter integration test")
    def test_phase4_evidence_adapter_creates_phase2_models_when_installed(self):
        Evidence = _Phase2Evidence
        store = ThreatIntelStore(commercial_mode=True)
        policy = FeedPolicy("TestFeed", "testfeed", "https://example.test/terms", True, True, True, "TestFeed", 24)
        store.register_feed(policy)
        store.mark_refresh("TestFeed", success=True)
        store.upsert(IndicatorRecord("domain", "bad.example", "TestFeed", confidence=0.95))
        investigator = Phase4Investigator(intel_store=store)
        result = investigator.investigate_content(case_id="phase2-adapter", content="You won a prize. Pay processing fee. Visit https://bad.example")
        evidence = result.to_phase2_evidence()
        self.assertTrue(evidence)
        self.assertTrue(all(isinstance(item, Evidence) for item in evidence))
        matched = next(item for item in evidence if item.category == "external_threat_indicator_match")
        self.assertEqual(matched.polarity, "risk")
        self.assertFalse(matched.verified)
        self.assertIn("not independent authentication", " ".join(matched.limitations))
        store.close()

    def test_phase4_returns_actions_and_campaign_context(self):
        corr = CampaignCorrelator(secret=SECRET)
        investigator = Phase4Investigator(campaign_correlator=corr)
        result = investigator.investigate_content(case_id="one", content="You won a prize. Pay processing fee now.")
        self.assertTrue(result.recommended_actions)
        self.assertIn("case-", result.case_ref)
        self.assertFalse(result.content_analysis.raw_content_stored)
        corr.close()

    def test_phase4_never_declares_final_verdict(self):
        investigator = Phase4Investigator()
        result = investigator.investigate_content(case_id="x", content="Hello there.")
        self.assertIn("does not independently issue", result.to_dict()["verdict_policy"])


if __name__ == "__main__":
    unittest.main()
