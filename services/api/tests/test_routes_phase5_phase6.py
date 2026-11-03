"""Tests for Phase 5 and Phase 6 investigation endpoints."""
import pytest


def test_multimodal_analysis_endpoint(env):
    payload = {
        "artifacts": [
            {
                "artifact_ref": "receipt_test_001",
                "artifact_type": "mpesa_receipt_ocr",
                "extracted_text": "Confirmed. Ksh1,500.00 sent to JOHN DOE 0712345678 on 4/11/26 at 10:00 AM.",
                "source_group": "user_submitted_artifact",
                "language": "en"
            }
        ],
        "expected_payment": {
            "amount": "1500.00",
            "recipient_identifier": "0712345678",
            "recipient_name": "JOHN DOE"
        }
    }
    r = env.client.post("/v1/investigations/case_test_0001/multimodal-analysis", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["case_ref"] == "case_test_0001"
    assert "indicator_band" in data
    assert "evidence_strength" in data
    assert "artifact_summaries" in data
    assert data["raw_artifact_content_stored"] is False


def test_multimodal_analysis_rejects_phone_case_ref(env):
    payload = {
        "artifacts": [
            {
                "artifact_ref": "receipt_test_001",
                "artifact_type": "message",
                "extracted_text": "Hello world",
                "source_group": "user_submitted_artifact"
            }
        ]
    }
    # 0712345678 is a phone number, should be rejected by case_ref validation
    r = env.client.post("/v1/investigations/0712345678/multimodal-analysis", json=payload)
    assert r.status_code == 400


def test_phase6_analysis_endpoint(env):
    payload = {
        "website_snapshot": {
            "tls_certificate_valid": True,
            "tls_hostname_match": True,
            "tls_days_remaining": 60,
            "domain_age_days": 180,
            "redirect_hosts": ["example.com"],
            "security_headers": {"strict-transport-security": "max-age=31536000"}
        },
        "social_observations": [
            {
                "artifact_ref": "social_test_001",
                "collection_mode": "platform_authorized_api",
                "profile_url": "https://www.tiktok.com/@safeshop",
                "observed_at": "2026-11-04T08:00:00Z",
                "public_fields": {"display_name": "Safe Shop", "is_platform_verified": False}
            }
        ],
        "image_artifacts": [
            {
                "artifact_ref": "image_test_001",
                "bytes": "aW1hZ2VfZGF0YQ==",
                "c2pa_status": "not_checked"
            }
        ]
    }
    r = env.client.post("/v1/investigations/case_test_0002/phase6", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["case_ref"] == "case_test_0002"
    assert data["phase"] == 6
    assert "findings" in data
    assert "sections" in data
    assert data["raw_uploads_stored"] is False


def test_phase6_rejects_phone_case_ref(env):
    payload = {}
    r = env.client.post("/v1/investigations/0712345678/phase6", json=payload)
    assert r.status_code == 400
