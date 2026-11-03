import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from toroka_phase6 import (
    Phase6Investigator, validate_target_url, validate_redirect_chain,
    parse_social_profile_url, inspect_social_observation,
    exact_file_hash, dhash_from_grayscale, hamming_distance,
    compare_fingerprints, keyed_ocr_fingerprint, interpret_content_credentials,
    analyze_call_transcript, compare_business_records, normalize_ke_phone, haversine_km,
)
from toroka_phase6.image_intelligence import keyed_ocr_fingerprint


class WebsiteForensicsTests(unittest.TestCase):
    def test_https_public_domain_allowed_but_no_dns_claim(self):
        result = validate_target_url("https://example.org/login?token=secret")
        self.assertTrue(result.allowed)
        self.assertEqual(result.host, "example.org")
        self.assertTrue(any("DNS" in w for w in result.warnings))
        self.assertNotIn("token", str(result))

    def test_http_is_warning_not_scam_proof(self):
        result = validate_target_url("http://example.org")
        self.assertTrue(result.allowed)
        self.assertIn("unencrypted", result.warnings[0])

    def test_rejects_non_http(self):
        self.assertFalse(validate_target_url("file:///etc/passwd").allowed)
        self.assertFalse(validate_target_url("ftp://example.org").allowed)

    def test_rejects_url_credentials(self):
        self.assertFalse(validate_target_url("https://user:pass@example.org").allowed)

    def test_rejects_custom_port(self):
        self.assertFalse(validate_target_url("https://example.org:8443").allowed)

    def test_rejects_malformed_dns_labels(self):
        self.assertFalse(validate_target_url("https://exa mple.org").allowed)
        self.assertFalse(validate_target_url("https://bad_label.example.org").allowed)

    def test_rejects_localhost_and_local_domains(self):
        for url in ["https://localhost", "http://printer.local", "https://x.internal"]:
            self.assertFalse(validate_target_url(url).allowed)

    def test_rejects_private_and_loopback_ips(self):
        for url in ["http://127.0.0.1", "http://10.0.0.2", "http://169.254.169.254", "http://[::1]"]:
            self.assertFalse(validate_target_url(url).allowed)

    def test_rejects_private_dns_answer_even_with_public_host(self):
        self.assertFalse(validate_target_url("https://attacker.example", ["127.0.0.1"]).allowed)
        self.assertFalse(validate_target_url("https://attacker.example", ["8.8.8.8", "192.168.1.1"]).allowed)

    def test_accepts_public_dns_answer(self):
        self.assertTrue(validate_target_url("https://example.org", ["93.184.216.34"]).allowed)

    def test_redirects_validated_individually(self):
        rows = validate_redirect_chain(["https://example.org", "http://127.0.0.1"], [[], []])
        self.assertTrue(rows[0].allowed)
        self.assertFalse(rows[1].allowed)

    def test_redirect_dns_array_length_required(self):
        with self.assertRaises(ValueError):
            validate_redirect_chain(["https://example.org"], []) if False else validate_redirect_chain(["https://example.org"], [["8.8.8.8"], []])

    def test_snapshot_findings_are_bounded_and_contextual(self):
        from toroka_phase6.web_forensics import analyze_site_snapshot
        rows = analyze_site_snapshot({"domain_age_days": 3, "redirect_hosts": ["a", "b", "c"],
                                      "security_headers": {"x-frame-options": "DENY"}})
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(r["polarity"] == "context" for r in rows))


class SocialIntelligenceTests(unittest.TestCase):
    def test_parse_instagram_profile(self):
        row = parse_social_profile_url("https://www.instagram.com/Example.Shop/?igsh=secret")
        self.assertEqual(row["platform"], "instagram")
        self.assertEqual(row["handle"], "example.shop")
        self.assertNotIn("igsh", row["canonical_url"])

    def test_parse_tiktok_profile(self):
        row = parse_social_profile_url("https://www.tiktok.com/@seller.ke")
        self.assertEqual(row["platform"], "tiktok")
        self.assertEqual(row["handle"], "seller.ke")
        self.assertEqual(row["canonical_url"], "https://www.tiktok.com/@seller.ke")

    def test_rejects_fake_domain_and_content_url(self):
        for url in ["https://instagram.com.evil.test/shop", "https://instagram.com/p/ABC", "http://instagram.com/shop"]:
            with self.assertRaises(ValueError):
                parse_social_profile_url(url)

    def test_rejects_unauthorized_scraping(self):
        with self.assertRaises(ValueError):
            inspect_social_observation({"collection_mode": "headless_browser_scrape", "profile_url": "https://instagram.com/shop"})

    def test_authorized_profile_fields_are_allowlisted(self):
        row = inspect_social_observation({"collection_mode": "platform_authorized_api", "profile_url": "https://instagram.com/shop",
                                          "public_fields": {"display_name": "Shop", "is_platform_verified": True, "password": "x"}})
        self.assertNotIn("password", row["public_fields"])
        self.assertEqual(row["source_group"], "public_web_observation")

    def test_profile_bio_masks_contact_details_and_is_bounded(self):
        row = inspect_social_observation({"collection_mode": "user_supplied_capture", "profile_url": "https://instagram.com/shop",
                                          "public_fields": {"bio": "Call 0712345678 or x@example.com " + "z" * 700}})
        self.assertNotIn("0712345678", row["public_fields"]["bio"])
        self.assertNotIn("x@example.com", row["public_fields"]["bio"])
        self.assertLessEqual(len(row["public_fields"]["bio"]), 500)

    def test_user_capture_stays_user_submitted_source(self):
        row = inspect_social_observation({"collection_mode": "user_supplied_capture", "profile_url": "https://instagram.com/shop"})
        self.assertEqual(row["source_group"], "user_submitted_artifact")


class ImageIntelligenceTests(unittest.TestCase):
    def test_exact_file_hash(self):
        self.assertEqual(exact_file_hash(b"same"), exact_file_hash(b"same"))
        self.assertNotEqual(exact_file_hash(b"same"), exact_file_hash(b"different"))

    def test_size_limit(self):
        with self.assertRaises(ValueError):
            exact_file_hash(b"x" * (20 * 1024 * 1024 + 1))

    def test_empty_image_rejected(self):
        with self.assertRaises(ValueError):
            exact_file_hash(b"")

    def test_dhash_and_distance(self):
        matrix = [[i for i in range(9)] for _ in range(8)]
        digest = dhash_from_grayscale(matrix)
        self.assertEqual(len(digest), 16)
        self.assertEqual(hamming_distance(digest, digest), 0)

    def test_dhash_rejects_wrong_dimensions(self):
        with self.assertRaises(ValueError):
            dhash_from_grayscale([[0] * 8 for _ in range(8)])

    def test_dhash_rejects_invalid_pixels(self):
        with self.assertRaises(ValueError):
            dhash_from_grayscale([[300] * 9 for _ in range(8)])

    def test_exact_reuse_match(self):
        digest = "a" * 64
        row = compare_fingerprints({"exact_sha256": digest}, {"exact_sha256": digest})
        self.assertEqual(row["match"], "exact")

    def test_invalid_exact_hash_is_not_trusted(self):
        row = compare_fingerprints({"exact_sha256": "a"}, {"exact_sha256": "a"})
        self.assertEqual(row["match"], "no_match_found")

    def test_perceptual_reuse_match(self):
        a = "0000000000000000"
        b = "0000000000000001"
        self.assertEqual(compare_fingerprints({"dhash": a}, {"dhash": b})["match"], "likely_visual_reuse")

    def test_ocr_fingerprint_keyed_and_never_plaintext(self):
        secret = b"x" * 32
        result = keyed_ocr_fingerprint("Pay to 0712345678 now", secret)
        self.assertEqual(len(result), 64)
        self.assertNotIn("0712345678", result)
        self.assertNotEqual(result, keyed_ocr_fingerprint("Pay to 0712345678 now", b"y" * 32))

    def test_ocr_hmac_requires_strong_secret(self):
        with self.assertRaises(ValueError):
            keyed_ocr_fingerprint("hello", b"short")

    def test_content_credentials_absence_is_not_ai_claim(self):
        row = interpret_content_credentials("not_present")
        self.assertIn("not proof", row["limitation"])

    def test_content_credentials_valid_does_not_prove_claim_true(self):
        row = interpret_content_credentials("valid", "Example Issuer")
        self.assertEqual(row["attribution"], "Example Issuer")
        self.assertIn("not a complete guarantee", row["limitation"])


class AudioIntelligenceTests(unittest.TestCase):
    def test_requires_consent(self):
        with self.assertRaises(PermissionError):
            analyze_call_transcript("share your OTP", consent_confirmed=False, provider="test", artifact_ref="audio_case_001")

    def test_detects_english_otp_and_remote_access(self):
        row = analyze_call_transcript("Please share your OTP and install AnyDesk", consent_confirmed=True,
                                      provider="test-stt", artifact_ref="audio_case_001")
        self.assertIn("credential_theft", row["matched_categories"])
        self.assertIn("remote_access_pressure", row["matched_categories"])
        self.assertTrue(all(item["polarity"] == "context" for item in row["findings"]))

    def test_detects_kiswahili_patterns(self):
        row = analyze_call_transcript("Nipe PIN yako. Lipa sasa", consent_confirmed=True,
                                      provider="test-stt", artifact_ref="audio_case_002")
        self.assertIn("credential_theft", row["matched_categories"])
        self.assertIn("urgent_payment_pressure", row["matched_categories"])

    def test_risk_polarity_requires_reviewed_external_speaker_attribution(self):
        row = analyze_call_transcript("Nipe PIN yako", consent_confirmed=True, provider="test-stt", artifact_ref="audio_case_006",
                                      speaker_role="external_party", speaker_role_reviewed=True)
        self.assertEqual(row["findings"][0]["polarity"], "risk")

    def test_neutral_transcript_has_no_risk_findings(self):
        row = analyze_call_transcript("Habari, mzigo wako umefika", consent_confirmed=True,
                                      provider="test-stt", artifact_ref="audio_case_003")
        self.assertEqual(row["findings"], [])

    def test_transcript_is_not_returned(self):
        row = analyze_call_transcript("Share your OTP", consent_confirmed=True,
                                      provider="test-stt", artifact_ref="audio_case_004")
        self.assertNotIn("transcript", row)
        self.assertFalse(row["raw_transcript_stored"])

    def test_rejects_oversized_transcript(self):
        with self.assertRaises(ValueError):
            analyze_call_transcript("x" * 30001, consent_confirmed=True, provider="test", artifact_ref="audio_case_005")


class BusinessVerificationTests(unittest.TestCase):
    def test_normalize_kenyan_phone(self):
        self.assertEqual(normalize_ke_phone("0712 345 678"), "254712345678")
        self.assertEqual(normalize_ke_phone("+254 712 345 678"), "254712345678")
        self.assertEqual(normalize_ke_phone("0112 345 678"), "254112345678")

    def test_brs_official_match_requires_both_name_and_registration(self):
        row = compare_business_records({"business_name": "Toroka Shop Ltd", "registration_number": "CPR/123"},
                                       {"source_type": "verified_brs_official_search", "registered_name": "Toroka Shop Limited", "registration_number": "CPR/123"})
        self.assertEqual(row["status"], "registry_identity_match")
        self.assertTrue(row["official_record"])

    def test_maps_listing_never_becomes_official_record(self):
        row = compare_business_records({"business_name": "Toroka Shop"}, {"source_type": "maps_place_listing", "business_name": "Toroka Shop"})
        self.assertEqual(row["status"], "location_candidate_only")
        self.assertFalse(row["official_record"])

    def test_uploaded_document_is_not_official_record(self):
        row = compare_business_records({"business_name": "Toroka Shop"}, {"source_type": "user_uploaded_registry_document", "registered_name": "Toroka Shop"})
        self.assertEqual(row["status"], "unverified_claim_or_document")
        self.assertFalse(row["official_record"])

    def test_official_registry_mismatch_is_flagged_as_context(self):
        row = compare_business_records({"business_name": "Toroka Shop", "registration_number": "CPR/123"},
                                       {"source_type": "verified_brs_official_search", "registered_name": "Another Shop", "registration_number": "CPR/999"})
        self.assertEqual(row["status"], "registry_record_mismatch")
        self.assertIn("registration_number", row["mismatches"])

    def test_invalid_source_rejected(self):
        with self.assertRaises(ValueError):
            compare_business_records({}, {"source_type": "web_scrape"})

    def test_map_location_mismatch_is_candidate_discrepancy_not_official_result(self):
        row = compare_business_records({"business_name": "Shop", "coordinates": (-1.28, 36.82)},
                                       {"source_type": "maps_place_listing", "business_name": "Shop", "coordinates": (-1.30, 36.82)})
        self.assertEqual(row["status"], "location_candidate_discrepancy")
        self.assertFalse(row["official_record"])
        self.assertGreater(row["location_distance_km"], 1.5)

    def test_map_location_mismatch_is_candidate_discrepancy_not_official_result(self):
        row = compare_business_records({"business_name": "Shop", "coordinates": (-1.28, 36.82)},
                                       {"source_type": "maps_place_listing", "business_name": "Shop", "coordinates": (-1.30, 36.82)})
        self.assertEqual(row["status"], "location_candidate_discrepancy")
        self.assertFalse(row["official_record"])
        self.assertGreater(row["location_distance_km"], 1.5)

    def test_haversine_distance(self):
        self.assertGreater(haversine_km((-1.286389, 36.817223), (-1.2921, 36.8219)), 0)
        with self.assertRaises(ValueError):
            haversine_km((95, 0), (0, 0))


class OrchestrationTests(unittest.TestCase):
    def test_all_sections_and_privacy_markers(self):
        investigator = Phase6Investigator()
        matrix = [[i for i in range(9)] for _ in range(8)]
        result = investigator.investigate(
            case_ref="toroka_case_0001",
            website_snapshot={"domain_age_days": 4},
            social_observations=[{"artifact_ref": "social_case_001", "collection_mode": "user_supplied_capture", "profile_url": "https://instagram.com/shop"}],
            image_artifacts=[{"artifact_ref": "image_case_001", "bytes": b"image", "grayscale_8x9": matrix}],
            audio_transcripts=[{"artifact_ref": "audio_case_001", "transcript": "Nipe PIN yako", "consent_confirmed": True, "provider": "demo"}],
            business_checks=[{"artifact_ref": "business_case_001", "claim": {"business_name": "Shop"}, "record": {"source_type": "maps_place_listing", "business_name": "Shop"}}],
        )
        payload = result.to_dict()
        self.assertEqual(payload["phase"], 6)
        self.assertFalse(payload["raw_uploads_stored"])
        self.assertTrue(all(k in payload["sections"] for k in ["website", "social", "images", "audio", "business"]))

    def test_bad_case_ref_rejected(self):
        with self.assertRaises(ValueError):
            Phase6Investigator().investigate(case_ref="0712345678")

    def test_phase5_adapter_when_package_available(self):
        import importlib.util
        if importlib.util.find_spec("toroka_phase5") is None:
            self.skipTest("Phase 5 package not on PYTHONPATH")
        result = Phase6Investigator().investigate(case_ref="toroka_case_0002", website_snapshot={"domain_age_days": 5})
        signals = result.to_phase5_signals()
        self.assertTrue(signals)
        self.assertEqual(signals[0].source_group, "public_web_observation")

    def test_phase2_adapter_when_package_available(self):
        import importlib.util
        if importlib.util.find_spec("toroka_evidence") is None:
            self.skipTest("Phase 2 package not on PYTHONPATH")
        result = Phase6Investigator().investigate(case_ref="toroka_case_0003", audio_transcripts=[{"artifact_ref": "audio_case_003", "transcript": "Nipe PIN yako", "consent_confirmed": True, "provider": "test"}])
        rows = result.to_phase2_evidence()
        self.assertTrue(rows)
        self.assertEqual(rows[0].source_group, "user_report")
        self.assertFalse(rows[0].verified)


if __name__ == "__main__":
    unittest.main(verbosity=2)
