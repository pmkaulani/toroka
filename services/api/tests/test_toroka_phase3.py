import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from toroka_phase3.identity_graph import EntityLinkGraph
from toroka_phase3.payment_review import PaymentClaim, review_payment_claim
from toroka_phase3.patterns import SellerFootprint, detect_shared_infrastructure
from toroka_phase3.timeline import build_case_timeline

SECRET = "phase-three-test-secret-at-least-32-bytes"


class IdentityGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "graph.sqlite3")
        self.graph = EntityLinkGraph(self.db, secret=SECRET)

    def tearDown(self):
        self.tmp.cleanup()

    def test_persists_only_hashed_identifiers(self):
        self.graph.add_link(
            ("seller", "@sample_shop"), ("phone", "+254712345678"),
            relationship="uses_contact", basis="public_listing", source_label="Public seller page",
            match_confidence=.82, source_url="https://example.com/shop?token=secret#fragment",
        )
        conn = sqlite3.connect(self.db)
        try:
            raw = " ".join(str(row) for row in conn.execute("SELECT * FROM graph_nodes").fetchall())
            links = " ".join(str(row) for row in conn.execute("SELECT * FROM link_assertions").fetchall())
        finally:
            conn.close()
        self.assertNotIn("sample_shop", raw + links)
        self.assertNotIn("254712345678", raw + links)
        self.assertNotIn("token=secret", raw + links)

    def test_safe_url_strips_query_and_fragment(self):
        self.graph.add_link(
            ("seller", "shop-a"), ("domain", "shop-a.example"), relationship="claims_website",
            basis="seller_claim", source_label="Seller profile", match_confidence=.7,
            source_url="https://example.org/profile?session=secret#top",
        )
        links = self.graph.get_links(("seller", "shop-a"))
        self.assertEqual(links[0]["source_url"], "https://example.org/profile")

    def test_token_like_path_is_removed_from_source_url(self):
        self.graph.add_link(
            ("seller", "shop-a"), ("domain", "shop-a.example"), relationship="claims_website",
            basis="seller_claim", source_label="Seller profile", match_confidence=.7,
            source_url="https://example.org/reset/password-token-123456789012345678901234567890",
        )
        links = self.graph.get_links(("seller", "shop-a"))
        self.assertEqual(links[0]["source_url"], "https://example.org/")

    def test_private_source_url_is_rejected(self):
        self.graph.add_link(
            ("seller", "shop-a"), ("domain", "shop-a.example"), relationship="claims_website",
            basis="seller_claim", source_label="Seller profile", match_confidence=.7,
            source_url="http://127.0.0.1/admin",
        )
        self.assertIsNone(self.graph.get_links(("seller", "shop-a"))[0]["source_url"])

    def test_kenyan_phone_formats_normalize_to_the_same_link(self):
        self.graph.add_link(
            ("seller", "shop-a"), ("phone", "0712 345 678"), relationship="uses_contact",
            basis="public_listing", source_label="Listing", match_confidence=.8,
        )
        self.assertEqual(len(self.graph.get_links(("phone", "+254 712-345-678"))), 1)

    def test_same_normalized_handle_maps_to_same_pseudonymous_node(self):
        self.graph.add_link(("social_handle", "@MyShop/"), ("domain", "myshop.example"), relationship="claims_website", basis="seller_claim", source_label="claim", match_confidence=.7)
        links = self.graph.get_links(("social_handle", "myshop"))
        self.assertEqual(len(links), 1)

    def test_public_digest_supports_privacy_safe_pattern_analysis(self):
        digest_a = self.graph.identifier_digest("phone", "0712 345 678")
        digest_b = self.graph.identifier_digest("phone", "+254712345678")
        self.assertEqual(digest_a, digest_b)
        self.assertNotIn("254712345678", digest_a)

    def test_verified_status_requires_authoritative_operator_source(self):
        with self.assertRaises(ValueError):
            self.graph.add_link(("seller", "shop-a"), ("business_registration", "BN123"), relationship="claims_registration", basis="official_document_user_supplied", source_label="Uploaded certificate", match_confidence=.99, status="verified")

    def test_verified_operator_checked_record_allowed(self):
        self.graph.add_link(("seller", "shop-a"), ("business_registration", "BN123"), relationship="claims_registration", basis="official_record_operator_checked", source_label="BRS official search", match_confidence=1.0, status="verified")
        self.assertEqual(self.graph.get_links(("seller", "shop-a"))[0]["status"], "verified")

    def test_relationship_does_not_propagate_risk(self):
        self.graph.add_link(("seller", "shop-a"), ("phone", "+254700000001"), relationship="uses_contact", basis="public_listing", source_label="Listing", match_confidence=.8)
        self.assertEqual(self.graph.get_links(("seller", "shop-a"))[0]["risk_propagation"], "never_automatic")

    def test_no_automatic_entity_merge(self):
        self.graph.add_link(("seller", "shop-a"), ("phone", "+254700000001"), relationship="uses_contact", basis="public_listing", source_label="Listing A", match_confidence=.8)
        self.graph.add_link(("seller", "shop-b"), ("phone", "+254700000001"), relationship="uses_contact", basis="public_listing", source_label="Listing B", match_confidence=.8)
        links_a = self.graph.get_links(("seller", "shop-a"))
        links_b = self.graph.get_links(("seller", "shop-b"))
        self.assertEqual(len(links_a), 1)
        self.assertEqual(len(links_b), 1)
        self.assertEqual(links_a[0]["connected_identifier_type"], "phone")
        self.assertEqual(links_b[0]["connected_identifier_type"], "phone")

    def test_rejects_empty_and_unknown_identifiers(self):
        with self.assertRaises(ValueError):
            self.graph.add_link(("seller", ""), ("domain", "example.com"), relationship="claims_website", basis="seller_claim", source_label="x", match_confidence=.5)
        with self.assertRaises(ValueError):
            self.graph.get_links(("national_id", "123"))

    def test_deletion_removes_assertions_for_identifier(self):
        self.graph.add_link(("seller", "shop-a"), ("domain", "shop-a.example"), relationship="claims_website", basis="seller_claim", source_label="claim", match_confidence=.5)
        self.assertEqual(self.graph.delete_links_for_identifier(("seller", "shop-a")), 1)
        self.assertEqual(self.graph.get_links(("seller", "shop-a")), [])


class PaymentReviewTests(unittest.TestCase):
    def test_exact_fields_match_but_are_not_payment_verification(self):
        result = review_payment_claim(PaymentClaim(
            expected_amount="KSh 1,200.00", observed_amount="1200",
            expected_recipient_name="Sample Shop", observed_recipient_name=" sample   shop ",
            expected_business_number="123456", observed_business_number="123 456",
            expected_account_reference="ORDER-88", observed_account_reference="order-88",
            transaction_reference_present=True,
        ))
        self.assertEqual(result.status, "details_match_user_claims")
        self.assertFalse(result.payment_confirmed)
        self.assertEqual(result.source_classification, "user_supplied_receipt_not_independently_verified")

    def test_amount_mismatch_flagged(self):
        result = review_payment_claim(PaymentClaim(expected_amount="1500", observed_amount="1000"))
        self.assertEqual(result.status, "mismatch_detected")
        self.assertIn("amount", result.mismatches)

    def test_destination_and_account_reference_mismatch_flagged(self):
        result = review_payment_claim(PaymentClaim(
            expected_business_number="123456", observed_business_number="654321",
            expected_account_reference="INV-1", observed_account_reference="INV-2",
        ))
        self.assertIn("business_number", result.mismatches)
        self.assertIn("account_reference", result.mismatches)

    def test_missing_fields_are_not_treated_as_matches(self):
        result = review_payment_claim(PaymentClaim(expected_amount="100"))
        self.assertEqual(result.status, "insufficient_details")
        self.assertIsNone(result.checks["amount_match"])

    def test_reference_presence_does_not_verify_receipt(self):
        result = review_payment_claim(PaymentClaim(transaction_reference_present=True))
        self.assertTrue(result.transaction_reference_present)
        self.assertFalse(result.payment_confirmed)

    def test_invalid_amount_is_not_a_match(self):
        result = review_payment_claim(PaymentClaim(expected_amount="NaN", observed_amount="NaN"))
        self.assertIsNone(result.checks["amount_match"])


class PatternTests(unittest.TestCase):
    def test_shared_identifier_alone_is_context_not_fraud_finding(self):
        sellers = [
            SellerFootprint("seller-a", {"phone": "digest-1"}),
            SellerFootprint("seller-b", {"phone": "digest-1"}),
        ]
        patterns = detect_shared_infrastructure(sellers)
        self.assertEqual(len(patterns), 1)
        self.assertEqual(patterns[0].evidence_level, "shared_identifier_only")
        self.assertEqual(patterns[0].risk_propagation, "never_automatic")

    def test_pending_reports_do_not_raise_evidence_level(self):
        sellers = [
            SellerFootprint("seller-a", {"mpesa_paybill": "digest-2"}, pending_reports=10),
            SellerFootprint("seller-b", {"mpesa_paybill": "digest-2"}, pending_reports=20),
        ]
        patterns = detect_shared_infrastructure(sellers)
        self.assertEqual(patterns[0].evidence_level, "shared_identifier_only")
        self.assertIn("Pending reports (30)", " ".join(patterns[0].limitations))

    def test_corroborated_report_context_is_explained_without_guilt_by_association(self):
        sellers = [
            SellerFootprint("seller-a", {"domain": "digest-3"}, corroborated_reports=1),
            SellerFootprint("seller-b", {"domain": "digest-3"}, corroborated_reports=1),
        ]
        pattern = detect_shared_infrastructure(sellers)[0]
        self.assertEqual(pattern.evidence_level, "shared_identifier_with_corroborated_reports")
        self.assertIn("do not prove", pattern.interpretation)

    def test_independent_risk_and_corroboration_get_distinct_pattern_label(self):
        sellers = [
            SellerFootprint("seller-a", {"phone": "digest-4"}, corroborated_reports=1, independently_sourced_risk_items=1),
            SellerFootprint("seller-b", {"phone": "digest-4"}),
        ]
        self.assertEqual(detect_shared_infrastructure(sellers)[0].evidence_level, "shared_identifier_with_independent_risk_and_corroborated_reports")

    def test_different_identifiers_do_not_link(self):
        sellers = [SellerFootprint("seller-a", {"phone": "digest-a"}), SellerFootprint("seller-b", {"phone": "digest-b"})]
        self.assertEqual(detect_shared_infrastructure(sellers), [])


class TimelineTests(unittest.TestCase):
    def test_timeline_orders_events_newest_first(self):
        old = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        new = datetime.now(timezone.utc).isoformat()
        result = build_case_timeline([
            {"source": "old feed", "summary": "old", "observed_at": old, "evidence_id": "1"},
            {"source": "new feed", "summary": "new", "observed_at": new, "evidence_id": "2"},
        ])
        self.assertEqual(result["events"][0]["title"], "new feed")

    def test_report_counts_remain_moderation_separated(self):
        result = build_case_timeline([], report_counts={"pending": 3, "corroborated": 1})
        self.assertEqual(result["community_report_counts"]["pending"], 3)
        self.assertEqual(result["community_report_counts"]["corroborated"], 1)
        self.assertIn("not confirmed facts", result["report_interpretation"])

    def test_missing_event_timestamps_are_skipped(self):
        result = build_case_timeline([{"source": "undated", "summary": "cannot order"}])
        self.assertEqual(result["event_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
