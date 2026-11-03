import unittest
from datetime import datetime, timedelta, timezone
from toroka_evidence.models import Evidence
from toroka_evidence.scoring import assess
from toroka_evidence.normalize import normalize_domain, normalize_phone


class NormalizationTests(unittest.TestCase):
    def test_domain_extracts_host(self):
        self.assertEqual(normalize_domain("https://www.example.co.ke/shop?a=1"), "www.example.co.ke")

    def test_rejects_localhost(self):
        self.assertIsNone(normalize_domain("http://localhost:8000"))

    def test_rejects_private_ip_and_non_http_schemes(self):
        self.assertIsNone(normalize_domain("http://127.0.0.1/admin"))
        self.assertIsNone(normalize_domain("http://192.168.1.20"))
        self.assertIsNone(normalize_domain("file:///etc/passwd"))

    def test_normalizes_idn_and_ignores_userinfo(self):
        self.assertEqual(normalize_domain("https://user:secret@bücher.example/path"), "xn--bcher-kva.example")

    def test_kenyan_phone_normalization(self):
        self.assertEqual(normalize_phone("0712 345 678"), "+254712345678")
        self.assertEqual(normalize_phone("+254 712 345 678"), "+254712345678")


class ScoringTests(unittest.TestCase):
    def test_no_evidence_is_not_safe(self):
        verdict, index, confidence, _ = assess([])
        self.assertEqual(verdict, "insufficient_evidence")
        self.assertIsNone(index)

    def test_one_weak_report_does_not_become_high_risk(self):
        evidence = [Evidence(source="community", source_group="community", category="user_report", polarity="risk", summary="One complaint", strength=2, reliability=.45, confidence=.5)]
        verdict, _, _, _ = assess(evidence)
        self.assertNotEqual(verdict, "high_risk")

    def test_independent_verified_threat_hit_is_high_risk(self):
        evidence = [Evidence(source="VT", source_group="vt", category="threat_intelligence", polarity="risk", summary="Confirmed malicious", strength=5, reliability=.9, confidence=.9, verified=True)]
        verdict, _, confidence, _ = assess(evidence)
        self.assertEqual(verdict, "high_risk")
        self.assertEqual(confidence, "high")

    def test_mirrored_reports_from_one_source_family_are_not_double_counted(self):
        evidence = [
            Evidence(source="feed-a", source_group="shared-feed-family", category="threat_intelligence", polarity="risk", summary="Hit A", strength=3, reliability=.9, confidence=.9),
            Evidence(source="feed-b", source_group="shared-feed-family", category="threat_intelligence", polarity="risk", summary="Mirrored hit", strength=3, reliability=.9, confidence=.9),
        ]
        verdict, _, _, _ = assess(evidence)
        self.assertEqual(verdict, "suspicious")

    def test_expired_evidence_is_ignored(self):
        old = datetime.now(timezone.utc) - timedelta(days=10)
        evidence = [Evidence(source="old", source_group="old", category="threat_intelligence", polarity="risk", summary="Expired", strength=5, reliability=1, confidence=1, verified=True, observed_at=old, expires_at=datetime.now(timezone.utc)-timedelta(days=1))]
        verdict, index, _, _ = assess(evidence)
        self.assertEqual(verdict, "insufficient_evidence")
        self.assertIsNone(index)


class MemoryTests(unittest.TestCase):
    def test_identifiers_are_hashed_and_reports_are_pending(self):
        import tempfile, os
        from toroka_evidence.memory import EvidenceMemory
        with tempfile.TemporaryDirectory() as tmp:
            db = os.path.join(tmp, "evidence.sqlite3")
            memory = EvidenceMemory(db, secret="a-very-long-test-secret-value-123456")
            report_id = memory.submit_community_report(
                identifiers=[("social_handle", "@sample_shop")],
                reporter_token="ephemeral-session-1",
                category="non_delivery",
                description="Paid for an item but the agreed delivery never arrived.",
                source_url="https://example.com/report?id=private-token#fragment",
            )
            snapshot = memory.get_entity_memory([("social_handle", "@sample_shop")])
            self.assertTrue(snapshot["found"])
            self.assertEqual(snapshot["report_counts"]["pending"], 1)
            self.assertEqual(snapshot["community_reports"][0]["report_id"], report_id)
            self.assertNotIn("description", snapshot["community_reports"][0])
            self.assertNotIn("source_url", snapshot["community_reports"][0])
            self.assertEqual(snapshot["evidence"], [])
            moderation_record = memory.get_report_for_moderation(report_id)
            self.assertEqual(moderation_record["source_url"], "https://example.com/report")
            self.assertNotIn("0712345678", moderation_record["description"])
            memory.moderate_report(report_id, "reviewed_unverified", "Need independent proof")
            snapshot = memory.get_entity_memory([("social_handle", "@sample_shop")])
            self.assertEqual(snapshot["report_counts"]["reviewed_unverified"], 1)

    def test_memory_requires_hash_secret(self):
        import tempfile
        from toroka_evidence.memory import EvidenceMemory
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                EvidenceMemory(tmp + "/x.db", secret="short")

class ProviderSafetyTests(unittest.TestCase):
    def test_map_candidate_alone_does_not_make_a_seller_lower_risk(self):
        from toroka_evidence.engine import EvidenceEngine
        from toroka_evidence.models import InvestigationRequest, LocationMatch

        class CandidateLocationProvider:
            name = "Test map provider"
            is_configured = True
            def is_applicable(self, request):
                return True
            def find_locations(self, request):
                return [LocationMatch(name="Sample Shop", address="Westlands, Nairobi", source=self.name)]

        result = EvidenceEngine(location_providers=[CandidateLocationProvider()]).investigate(
            InvestigationRequest(target="@sample_shop", business_name="Sample Shop", search_location="Westlands, Nairobi")
        )
        self.assertEqual(result.verdict, "insufficient_evidence")
        self.assertEqual(result.locations[0].status, "third_party_listing_unverified")
        self.assertEqual(result.locations[0].to_dict()["checked_at"].endswith("+00:00"), True)

    def test_provider_failure_is_reported_as_unavailable_not_clean(self):
        from toroka_evidence.engine import EvidenceEngine
        from toroka_evidence.models import InvestigationRequest

        class BrokenProvider:
            name = "Test provider"
            is_configured = True
            def is_applicable(self, request):
                return True
            def investigate(self, request):
                raise TimeoutError("simulated timeout")

        result = EvidenceEngine(providers=[BrokenProvider()]).investigate(
            InvestigationRequest(target="https://shop.example")
        )
        self.assertEqual(result.verdict, "insufficient_evidence")
        self.assertIn("Test provider", result.unavailable_checks)
        self.assertNotIn("Test provider", result.completed_checks)

    def test_social_platform_domain_is_not_scored_as_the_seller_domain(self):
        from toroka_evidence.normalize import investigation_domain
        self.assertIsNone(investigation_domain("https://www.instagram.com/base_menswear/"))
        self.assertEqual(investigation_domain("https://www.instagram.com/base_menswear/", "https://basemenswear.co.ke"), "basemenswear.co.ke")

    def test_phishtank_strips_tokens_and_ignores_social_platform_hosts(self):
        from toroka_evidence.providers.phishtank import PhishTankProvider
        self.assertEqual(PhishTankProvider._lookup_url("https://bad.example/reset/secret-token?token=secret#frag"), "https://bad.example/")
        self.assertEqual(PhishTankProvider._lookup_url("https://user:secret@bad.example/path"), "https://bad.example/")
        self.assertIsNone(PhishTankProvider._lookup_url("https://instagram.com/base_menswear"))
        self.assertIsNone(PhishTankProvider._lookup_url("javascript:alert(1)"))


class EvidenceMemoryPrivacyTests(unittest.TestCase):
    def test_evidence_subject_and_urls_are_sanitized_before_storage(self):
        import tempfile, os
        from toroka_evidence.memory import EvidenceMemory
        from toroka_evidence.models import Evidence
        with tempfile.TemporaryDirectory() as tmp:
            memory = EvidenceMemory(os.path.join(tmp, "evidence.sqlite3"), secret="a-very-long-test-secret-value-123456")
            item = Evidence(source="test", source_group="test", category="user_report", polarity="context", summary="Contact 0712345678 or mail me@example.com", subject="https://shop.example/path?token=secret", source_url="https://source.example/report?access=private", metadata={"url": "https://shop.example/?session=secret"})
            memory.add_evidence([("social_handle", "@sample_shop")], item)
            stored = memory.get_entity_memory([("social_handle", "@sample_shop")])["evidence"][0]
            self.assertNotIn("token=secret", stored["subject"])
            self.assertNotIn("access=private", stored["source_url"])
            self.assertNotIn("session=secret", stored["metadata"]["url"])
            self.assertNotIn("0712345678", stored["summary"])


def test_v2_investigations_endpoint(env):
    from unittest.mock import patch
    from toroka_evidence.models import InvestigationResult
    mock_res = InvestigationResult(
        target="https://suspicious-store.example.co.ke",
        verdict="suspicious",
        risk_index=65.0,
        confidence="medium",
        conclusion="Suspicious signals detected",
        recommended_actions=["Verify seller phone"],
        limitations=["Checks are automated"],
    )
    with patch("toroka_evidence.api_contract.engine.investigate", return_value=mock_res):
        payload = {
            "target": "https://suspicious-store.example.co.ke",
            "business_name": "Suspicious Store",
            "search_location": "Nairobi",
        }
        response = env.client.post("/v2/investigations", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "suspicious"
    assert data["target"] == "https://suspicious-store.example.co.ke"
    assert "Verify seller phone" in data["recommended_actions"]


if __name__ == "__main__":
    unittest.main()
