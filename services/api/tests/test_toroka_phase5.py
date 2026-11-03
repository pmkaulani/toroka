import unittest
from datetime import datetime, timezone

from toroka_phase5 import (
    ArtifactInput, ConversationMessage, EvidenceSignal, LabelledCase,
    ModelPrediction, Phase5Investigator, analyze_conversation,
    analyze_receipt_text, assess_drift, evaluate, fuse_evidence,
    keyed_fingerprint, normalize_ke_phone, release_gate, run_shadow_model,
    safe_excerpt, temporal_campaign_split,
)


class PrivacyTests(unittest.TestCase):
    def test_ke_phone_normalization(self):
        self.assertEqual(normalize_ke_phone("0712 345 678"), "+254712345678")
        self.assertEqual(normalize_ke_phone("+254 712-345-678"), "+254712345678")
        self.assertIsNone(normalize_ke_phone("1234567"))

    def test_excerpt_masks_phone_email_pin_and_url_path(self):
        excerpt = safe_excerpt("Pay to 0712345678, email a@b.co, M-PESA PIN 1234 https://shop.example/claim?token=secret")
        self.assertNotIn("0712345678", excerpt)
        self.assertNotIn("a@b.co", excerpt)
        self.assertNotIn("1234", excerpt)
        self.assertNotIn("/claim", excerpt)
        self.assertNotIn("token=secret", excerpt)
        self.assertIn("shop.example", excerpt)

    def test_excerpt_masks_recipient_names(self):
        excerpt = safe_excerpt("Sent to: JOHN DOE Amount: Ksh 400")
        self.assertNotIn("JOHN DOE", excerpt)

    def test_excerpt_masks_mpesa_transaction_reference(self):
        excerpt = safe_excerpt("Transaction ID: QAB12CD34E Amount: Ksh 100")
        self.assertNotIn("QAB12CD34E", excerpt)
        self.assertIn("[redacted]", excerpt)

    def test_hmac_fingerprint_stable_and_scoped(self):
        secret = b"x" * 32
        a = keyed_fingerprint("Shop.Example", secret=secret, namespace="domain")
        b = keyed_fingerprint("shop.example", secret=secret, namespace="domain")
        c = keyed_fingerprint("shop.example", secret=secret, namespace="phone")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_hmac_requires_long_secret(self):
        with self.assertRaises(ValueError):
            keyed_fingerprint("foo", secret=b"short", namespace="domain")


class SchemaTests(unittest.TestCase):
    def test_artifact_rejects_nonopaque_ref(self):
        with self.assertRaises(ValueError):
            ArtifactInput("john@example.com", "sms", "hello")

    def test_artifact_rejects_phone_number_as_ref(self):
        with self.assertRaises(ValueError):
            ArtifactInput("0712345678", "sms", "hello")

    def test_artifact_rejects_unknown_type(self):
        with self.assertRaises(ValueError):
            ArtifactInput("artifact_123", "binary", "hello")

    def test_artifact_rejects_untrusted_source_group(self):
        with self.assertRaises(ValueError):
            ArtifactInput("artifact_123", "sms", "hello", source_group="random_sender")

    def test_artifact_rejects_oversized_text(self):
        with self.assertRaises(ValueError):
            ArtifactInput("artifact_123", "sms", "x" * 50_001)

    def test_evidence_rejects_out_of_range_confidence(self):
        with self.assertRaises(ValueError):
            EvidenceSignal("artifact_123", "user_sms", "x", "high", "s", "e", confidence=1.1)

    def test_evidence_rejects_nonopaque_reference(self):
        with self.assertRaises(ValueError):
            EvidenceSignal("0712345678", "user_sms", "x", "high", "s", "e")


class ReceiptTests(unittest.TestCase):
    SAMPLE = "M-PESA Confirmed. Transaction ID: QAB12CD34E. Amount sent: Ksh 1,500.00. Paid to: ACME STORES. Till number: 123456."

    def test_receipt_amount_parsed(self):
        r = analyze_receipt_text(self.SAMPLE, evidence_ref="receipt_123", expected_amount="1500.00")
        self.assertEqual(r.parsed_amount, "1500.00")
        self.assertTrue(r.amount_match)

    def test_receipt_amount_mismatch_emits_signal(self):
        r = analyze_receipt_text(self.SAMPLE, evidence_ref="receipt_123", expected_amount="2000")
        self.assertFalse(r.amount_match)
        self.assertIn("receipt_amount_mismatch", {s.category for s in r.signals})

    def test_receipt_recipient_mismatch_emits_signal(self):
        r = analyze_receipt_text(self.SAMPLE, evidence_ref="receipt_123", expected_recipient_identifier="654321")
        self.assertFalse(r.recipient_identifier_match)
        self.assertIn("receipt_recipient_mismatch", {s.category for s in r.signals})

    def test_receipt_recipient_match(self):
        r = analyze_receipt_text(self.SAMPLE, evidence_ref="receipt_123", expected_recipient_identifier="123456")
        self.assertTrue(r.recipient_identifier_match)
        self.assertEqual(r.signals, [])

    def test_mobile_number_recipient_is_parsed(self):
        text = "M-PESA. Amount sent: Ksh 250. Mobile number: 0712345678. Transaction ID: QAB12CD34E."
        r = analyze_receipt_text(text, evidence_ref="receipt_123", expected_recipient_identifier="+254712345678")
        self.assertTrue(r.recipient_identifier_match)

    def test_receipt_not_verified_even_when_fields_match(self):
        r = analyze_receipt_text(self.SAMPLE, evidence_ref="receipt_123", expected_amount="1500", expected_recipient_identifier="123456")
        self.assertFalse(r.to_dict()["payment_verified"])

    def test_receipt_does_not_return_raw_reference_or_name(self):
        r = analyze_receipt_text(self.SAMPLE, evidence_ref="receipt_123")
        payload = str(r.to_dict())
        self.assertNotIn("QAB12CD34E", payload)
        self.assertNotIn("ACME STORES", payload)

    def test_receipt_underspecified(self):
        r = analyze_receipt_text("Payment successful", evidence_ref="receipt_123")
        self.assertEqual(r.status, "insufficient_receipt_fields")

    def test_receipt_rejects_oversized_text(self):
        with self.assertRaises(ValueError):
            analyze_receipt_text("x" * 20_001, evidence_ref="receipt_123")


class ConversationTests(unittest.TestCase):
    def test_detects_otp_request(self):
        r = analyze_conversation([ConversationMessage("seller", "Send me your M-PESA PIN 1234")], evidence_ref="chat_123")
        self.assertIn("conversation_credential_request", {s["category"] for s in r["signals"]})

    def test_detects_payment_destination_change(self):
        r = analyze_conversation([ConversationMessage("seller", "Use this new number instead")], evidence_ref="chat_123")
        self.assertIn("conversation_payment_destination_change", {s["category"] for s in r["signals"]})

    def test_detects_additional_fee(self):
        r = analyze_conversation([ConversationMessage("seller", "Another fee is required")], evidence_ref="chat_123")
        self.assertIn("conversation_additional_fee_after_payment", {s["category"] for s in r["signals"]})

    def test_detects_urgency(self):
        r = analyze_conversation([ConversationMessage("seller", "Pay now or lose this deal")], evidence_ref="chat_123")
        self.assertIn("conversation_urgency_pressure", {s["category"] for s in r["signals"]})

    def test_buyer_credential_text_does_not_trigger_seller_signal(self):
        r = analyze_conversation([ConversationMessage("buyer", "Can you send me your PIN? I am quoting a previous scam message")], evidence_ref="chat_123")
        self.assertEqual(r["signals"], [])

    def test_unknown_role_is_context_not_seller_risk(self):
        r = analyze_conversation([ConversationMessage("unknown", "Send me your M-PESA PIN")], evidence_ref="chat_123")
        self.assertEqual(r["signals"][0]["polarity"], "context")
        self.assertEqual(r["signals"][0]["severity"], "context")

    def test_seller_match_takes_priority_over_unknown_message(self):
        r = analyze_conversation([
            ConversationMessage("unknown", "Send me your M-PESA PIN"),
            ConversationMessage("seller", "Send me your M-PESA PIN"),
        ], evidence_ref="chat_123")
        self.assertEqual(r["signals"][0]["polarity"], "risk")
        self.assertEqual(r["signals"][0]["severity"], "critical")

    def test_buyer_quote_not_added_to_timeline(self):
        r = analyze_conversation([
            ConversationMessage("seller", "Pay now or lose the deal"),
            ConversationMessage("buyer", "The seller said: Pay now or lose the deal"),
        ], evidence_ref="chat_123")
        self.assertEqual([x["role"] for x in r["timeline"]], ["seller"])

    def test_timeline_has_no_message_body(self):
        r = analyze_conversation([ConversationMessage("seller", "Pay now or lose the deal", "2026-10-01T12:00:00Z")], evidence_ref="chat_123")
        self.assertNotIn("Pay now", str(r["timeline"]))
        self.assertEqual(r["timeline"][0]["message_index"], 0)

    def test_rejects_empty_conversation(self):
        with self.assertRaises(ValueError):
            analyze_conversation([], evidence_ref="chat_123")


class FusionTests(unittest.TestCase):
    def sig(self, ref, source, cat="x", severity="high", polarity="risk"):
        return EvidenceSignal(ref, source, cat, severity, "summary", "why", polarity=polarity)

    def test_context_only_is_insufficient(self):
        r = fuse_evidence([self.sig("artif_123", "user_sms", severity="context", polarity="context")])
        self.assertEqual(r["indicator_band"], "insufficient_evidence")

    def test_one_high_source_is_review_not_elevated(self):
        r = fuse_evidence([self.sig("artif_123", "user_sms")])
        self.assertEqual(r["indicator_band"], "review_recommended")

    def test_multiple_upload_types_are_not_independent_source_families(self):
        r = fuse_evidence([self.sig("artif_123", "user_sms"), self.sig("artif_456", "user_receipt")])
        self.assertEqual(r["independent_source_groups"], 1)
        self.assertEqual(r["indicator_band"], "review_recommended")

    def test_distinct_trusted_source_groups_can_raise_band(self):
        r = fuse_evidence([self.sig("artif_123", "user_submitted_artifact"), self.sig("artif_456", "threat_feed")])
        self.assertEqual(r["indicator_band"], "elevated_signals")

    def test_duplicate_signal_deduplicated(self):
        s = self.sig("artif_123", "user_sms")
        r = fuse_evidence([s, s])
        self.assertEqual(r["deduplicated_signal_count"], 1)

    def test_reassuring_signal_does_not_reduce_risk_band(self):
        risk = self.sig("artif_123", "user_sms")
        reassurance = self.sig("artif_456", "official_record", severity="low", polarity="reassuring")
        r = fuse_evidence([risk, reassurance])
        self.assertEqual(r["indicator_band"], "review_recommended")


class ModelShadowTests(unittest.TestCase):
    def test_shadow_model_completed_but_not_verdict(self):
        def predictor(_):
            return ModelPrediction("model-v1", {"scam": 0.8, "legitimate": 0.1, "suspicious": 0.05, "inconclusive": 0.05}, ("artifact_123",))
        r = run_shadow_model(predictor, safe_case_features={"x": 1}, known_evidence_refs={"artifact_123"})
        self.assertEqual(r.status, "completed")
        self.assertFalse(r.affects_user_verdict)
        self.assertEqual(r.mode, "shadow_only")

    def test_shadow_rejects_unknown_evidence_reference(self):
        def predictor(_):
            return ModelPrediction("model-v1", {"scam": 1.0}, ("unknown_123",))
        r = run_shadow_model(predictor, safe_case_features={}, known_evidence_refs=set())
        self.assertEqual(r.error_code, "unknown_evidence_reference")

    def test_shadow_provider_failure_is_sanitized(self):
        def predictor(_):
            raise RuntimeError("secret token and private URL")
        r = run_shadow_model(predictor, safe_case_features={}, known_evidence_refs=set())
        self.assertEqual(r.error_code, "model_provider_error")
        self.assertNotIn("secret", str(r.to_dict()))

    def test_prediction_probabilities_must_sum_to_one(self):
        with self.assertRaises(ValueError):
            ModelPrediction("model-v1", {"scam": 0.4}, ())

    def test_invalid_probabilities_rejected(self):
        with self.assertRaises(ValueError):
            ModelPrediction("model-v1", {"scam": 1.2}, ())


class DriftTests(unittest.TestCase):
    def test_stable_distribution_has_zero_psi(self):
        r = assess_drift({"en": 70, "sw": 30}, {"en": 70, "sw": 30}, min_samples=10)
        self.assertEqual(r.psi, 0.0)
        self.assertFalse(r.alert)

    def test_changed_distribution_alerts(self):
        r = assess_drift({"en": 90, "sw": 10}, {"en": 10, "sw": 90}, min_samples=10)
        self.assertTrue(r.alert)

    def test_small_windows_are_insufficient(self):
        r = assess_drift({"en": 5}, {"en": 8}, min_samples=10)
        self.assertEqual(r.status, "insufficient_samples")

    def test_negative_counts_rejected(self):
        from toroka_phase5 import population_stability_index
        with self.assertRaises(ValueError):
            population_stability_index({"en": -1}, {"en": 1})


class EvaluationTests(unittest.TestCase):
    def make_rows(self):
        return [
            LabelledCase(f"case_{i:03}", f"camp_{i:03}", f"2026-10-{(i%20)+1:02}T12:00:00+00:00",
                         "scam" if i % 2 == 0 else "legitimate",
                         "scam" if i % 2 == 0 else "legitimate",
                         language="sw" if i % 3 == 0 else "en")
            for i in range(60)
        ]

    def test_evaluation_metrics(self):
        r = evaluate(self.make_rows())
        self.assertEqual(r["samples"], 60)
        self.assertEqual(r["precision"], 1.0)
        self.assertEqual(r["recall"], 1.0)

    def test_duplicate_case_refs_rejected(self):
        rows = self.make_rows()[:2]
        duplicate = LabelledCase(rows[0].case_ref, "other", rows[0].observed_at, "scam", "scam")
        with self.assertRaises(ValueError):
            evaluate([rows[0], duplicate])

    def test_temporal_campaign_split(self):
        rows = self.make_rows()
        train, test = temporal_campaign_split(rows, cutoff_iso="2026-10-15T00:00:00+00:00")
        self.assertTrue(all(r.observed_at < "2026-10-15T00:00:00+00:00" for r in train))
        self.assertTrue(all(r.observed_at >= "2026-10-15T00:00:00+00:00" for r in test))

    def test_temporal_split_rejects_campaign_leakage(self):
        a = LabelledCase("case_001", "same_campaign", "2026-10-01T00:00:00+00:00", "scam", "scam")
        b = LabelledCase("case_002", "same_campaign", "2026-11-01T00:00:00+00:00", "scam", "scam")
        with self.assertRaises(ValueError):
            temporal_campaign_split([a, b], cutoff_iso="2026-10-15T00:00:00+00:00")

    def test_suspicious_prediction_counts_as_risk_positive(self):
        rows = [
            LabelledCase("case_a_001", "camp_a", "2026-10-01T00:00:00+00:00", "scam", "suspicious"),
            LabelledCase("case_b_001", "camp_b", "2026-10-02T00:00:00+00:00", "legitimate", "legitimate"),
        ]
        r = evaluate(rows)
        self.assertEqual(r["true_positive"] if "true_positive" in r else r["tp"], 1)

    def test_release_gate_never_authorizes_deployment(self):
        r = release_gate({"samples": 1000, "campaigns": 100, "precision": 1.0, "recall": 1.0,
                          "false_positive_rate": 0.0, "by_language": {"en": {"samples": 500, "recall": 1.0, "false_positive_rate": 0.0}}})
        self.assertTrue(r["eligible_for_shadow_canary"])
        self.assertFalse(r["deployment_authorized"])

    def test_release_gate_blocks_low_subgroup_count(self):
        r = release_gate({"samples": 1000, "campaigns": 100, "precision": 1.0, "recall": 1.0,
                          "false_positive_rate": 0.0, "by_language": {"en": {"samples": 500, "recall": 1.0, "false_positive_rate": 0.0}, "sw": {"samples": 10, "recall": 1.0, "false_positive_rate": 0.0}}})
        self.assertFalse(r["checks"]["language_subgroups_have_minimum_samples"])

    def test_release_gate_blocks_bad_language_subgroup_fpr(self):
        r = release_gate({"samples": 1000, "campaigns": 100, "precision": 1.0, "recall": 1.0,
                          "false_positive_rate": 0.0, "by_language": {"en": {"samples": 500, "recall": 1.0, "false_positive_rate": 0.0}, "sw": {"samples": 500, "recall": 0.9, "false_positive_rate": 0.2}}})
        self.assertFalse(r["checks"]["language_subgroup_false_positive_rate_within_bound"])


class InvestigatorTests(unittest.TestCase):
    def test_receipt_case_is_orchestrated(self):
        artifact = ArtifactInput("receipt_123", "mpesa_receipt_ocr",
            "M-PESA Confirmed. Transaction ID: QAB12CD34E. Amount sent: Ksh 500.00. Paid to: ACME STORES. Till number: 123456.",
            source_group="user_receipt")
        r = Phase5Investigator().investigate(case_ref="case_ref_123", artifacts=[artifact], expected_payment={"amount": "900"})
        self.assertEqual(r.indicator_band, "review_recommended")
        self.assertFalse(r.to_dict()["raw_artifact_content_stored"])
        self.assertIn("receipt_amount_mismatch", {s.category for s in r.signals})

    def test_phase4_result_requires_matching_artifact_ref(self):
        artifact = ArtifactInput("artifact_123", "sms", "you have won a prize")
        payload = {"case_ref": "case_other_123", "content_analysis": {"signals": [{"category": "bait", "severity": "high", "polarity": "risk", "summary": "bait", "reason": "rule", "confidence": 0.8}]}}
        r = Phase5Investigator().investigate(case_ref="case_ref_123", artifacts=[artifact], phase4_results=[payload])
        self.assertEqual(len(r.signals), 0)
        self.assertTrue(any("matching artifact_ref" in x for x in r.limitations))

    def test_phase4_case_ref_is_not_accepted_as_artifact_ref(self):
        artifact = ArtifactInput("artifact_123", "sms", "message")
        payload = {"case_ref": "artifact_123", "content_analysis": {"signals": [{"category": "x", "severity": "high", "polarity": "risk", "summary": "x", "reason": "x", "confidence": 0.9}]}}
        r = Phase5Investigator().investigate(case_ref="case_ref_123", artifacts=[artifact], phase4_results=[payload])
        self.assertEqual(r.signals, [])

    def test_phase4_adapter_with_artifact_ref(self):
        artifact = ArtifactInput("artifact_123", "sms", "you have won a prize")
        payload = {"artifact_ref": "artifact_123", "content_analysis": {"signals": [{"category": "prize_bait", "severity": "high", "polarity": "risk", "summary": "Unsolicited prize", "reason": "phrase match", "confidence": 0.8, "excerpt": "you won", "limitations": []}]}}
        r = Phase5Investigator().investigate(case_ref="case_ref_123", artifacts=[artifact], phase4_results=[payload])
        self.assertEqual(r.indicator_band, "review_recommended")
        self.assertEqual(r.signals[0].category, "prize_bait")

    def test_active_phase4_feed_is_separate_source_family(self):
        artifact = ArtifactInput("artifact_123", "sms", "suspicious shop link")
        payload = {
            "artifact_ref": "artifact_123",
            "content_analysis": {"signals": [{"category": "phishing_language", "severity": "high", "polarity": "risk", "summary": "Suspicious message wording", "reason": "rule match", "confidence": 0.8}]},
            "threat_matches": [{"status": "active", "confidence": 0.9, "source_group": "phishtank", "indicator": "example.invalid"}],
        }
        r = Phase5Investigator().investigate(case_ref="case_ref_123", artifacts=[artifact], phase4_results=[payload])
        self.assertEqual(r.independent_source_groups, 2)
        # The registered Phase 4 feed is a distinct source family from the user artefact.
        self.assertIn("active_threat_feed_match", {s.category for s in r.signals})
        self.assertIn("feed:phishtank", {s.source_group for s in r.signals})
        self.assertEqual(r.indicator_band, "elevated_signals")

    def test_malformed_phase4_confidence_is_ignored_without_crashing(self):
        artifact = ArtifactInput("artifact_123", "sms", "message")
        payload = {"artifact_ref": "artifact_123", "content_analysis": {"signals": [{"category": "x", "severity": "high", "polarity": "risk", "confidence": "not-a-number"}]}}
        r = Phase5Investigator().investigate(case_ref="case_ref_123", artifacts=[artifact], phase4_results=[payload])
        self.assertEqual(r.signals, [])
        self.assertTrue(any("invalid confidence" in x for x in r.limitations))

    def test_campaign_link_is_not_risk_signal(self):
        artifact = ArtifactInput("artifact_123", "sms", "normal payment instruction")
        payload = {"artifact_ref": "artifact_123", "campaign_links": [{"related_case_ref": "case_x", "text_similarity": 0.99}]}
        r = Phase5Investigator().investigate(case_ref="case_ref_123", artifacts=[artifact], phase4_results=[payload])
        self.assertEqual(r.indicator_band, "insufficient_evidence")

    def test_phase3_relationship_is_context_only(self):
        artifact = ArtifactInput("artifact_123", "sms", "normal payment instruction")
        link = {"artifact_ref": "artifact_123", "relationship": "uses_contact", "basis": "public_listing", "status": "corroborated", "source_label": "Public profile", "match_confidence": 0.9, "risk_propagation": "never_automatic"}
        r = Phase5Investigator().investigate(case_ref="case_ref_123", artifacts=[artifact], phase3_relationships=[link])
        self.assertEqual(r.indicator_band, "insufficient_evidence")
        self.assertEqual(r.signals[0].polarity, "context")
        self.assertEqual(r.signals[0].severity, "context")

    def test_phase3_relationship_requires_matching_artifact_ref(self):
        artifact = ArtifactInput("artifact_123", "sms", "normal message")
        r = Phase5Investigator().investigate(case_ref="case_ref_123", artifacts=[artifact], phase3_relationships=[{"artifact_ref": "other_ref_123", "relationship": "uses_contact"}])
        self.assertEqual(r.signals, [])
        self.assertTrue(any("Phase 3 relationship" in x for x in r.limitations))

    def test_phase3_observation_timestamp_is_preserved_in_utc(self):
        artifact = ArtifactInput("artifact_123", "sms", "normal message")
        link = {"artifact_ref": "artifact_123", "relationship": "uses_contact", "basis": "public_listing", "status": "unverified", "observed_at": "2024-02-03T12:00:00+03:00"}
        r = Phase5Investigator().investigate(case_ref="case_ref_123", artifacts=[artifact], phase3_relationships=[link])
        self.assertEqual(r.signals[0].observed_at, "2024-02-03T09:00:00+00:00")

    def test_shadow_model_does_not_change_indicator_band(self):
        artifact = ArtifactInput("artifact_123", "sms", "normal payment instruction")
        def model(_):
            return ModelPrediction("m1", {"scam": .9, "legitimate": .1}, ("artifact_123",))
        r = Phase5Investigator().investigate(case_ref="case_ref_123", artifacts=[artifact], shadow_predictor=model)
        self.assertEqual(r.indicator_band, "insufficient_evidence")
        self.assertEqual(r.model_shadow["suggested_label"], "scam")
        self.assertFalse(r.model_shadow["affects_user_verdict"])

    def test_conversation_integrated_only_for_chat_artifact(self):
        artifact = ArtifactInput("chat_12345", "chat_transcript", "message history")
        conversation = [ConversationMessage("seller", "Send your M-PESA PIN")]
        r = Phase5Investigator().investigate(case_ref="case_ref_123", artifacts=[artifact], conversation=conversation)
        self.assertIn("conversation_credential_request", {s.category for s in r.signals})

    def test_no_raw_artifact_text_in_summary(self):
        secret = "my private unique message phrase 998877"
        artifact = ArtifactInput("artifact_123", "sms", secret)
        r = Phase5Investigator().investigate(case_ref="case_ref_123", artifacts=[artifact])
        self.assertNotIn(secret, str(r.to_dict()))

    def test_duplicate_artifact_refs_rejected(self):
        a = ArtifactInput("artifact_123", "sms", "one")
        b = ArtifactInput("artifact_123", "screenshot_ocr", "two")
        with self.assertRaises(ValueError):
            Phase5Investigator().investigate(case_ref="case_ref_123", artifacts=[a, b])

    def test_phase2_adapter_behaves_with_or_without_phase2_installed(self):
        artifact = ArtifactInput("artifact_123", "mpesa_receipt_ocr", "Amount: Ksh 50")
        summary = Phase5Investigator().investigate(case_ref="case_ref_123", artifacts=[artifact], expected_payment={"amount": "99"})
        try:
            import toroka_evidence  # noqa: F401
        except ImportError:
            with self.assertRaisesRegex(RuntimeError, "Phase 2"):
                summary.to_phase2_evidence()
        else:
            evidence = summary.to_phase2_evidence()
            self.assertTrue(evidence)
            self.assertTrue(all(item.verified is False for item in evidence))
            self.assertEqual(len({item.source_group for item in evidence}), 1)
            self.assertEqual(evidence[0].source_group, "toroka-content-patterns-v1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
