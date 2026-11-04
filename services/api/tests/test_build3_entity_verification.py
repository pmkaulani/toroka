from __future__ import annotations

from datetime import date, timedelta
import hashlib

import pytest
from sqlalchemy import select

from app import db as m
from toroka_build3 import parse_nea_csv, snapshot_freshness
from toroka_build3.normalization import extract_claims, normalize_domain
from app.routes_build3 import _is_shared_platform_domain

NEA_SOURCE = "https://www.neaims.go.ke/EmploymentAgencyList.aspx"
NEA_CSV = """NEA Reg No,Agency Name,E-mail Address,Website,Service Type,Certificate Valid From,Certificate Expiry,Status
RA/2025/10/24,Riverside Manpower Limited,info@riversidemanpower.com,www.riversidemanpower.com,Foreign & Local Recruitment,25-09-2018,03-10-2027,Valid
NA/2021/03/27,A.F. & R Manpower Limited,afrmanpower@gmail.com,N/A,Foreign & Local Recruitment,01-03-2021,01-03-2025,Expired
"""


def _as_of():
    return date.today().isoformat()


def _import_nea(env, headers, *, csv=NEA_CSV, as_of=None):
    return env.client.post(
        "/v1/admin/build3/nea/import",
        headers=headers,
        data={"source_url": NEA_SOURCE, "data_as_of": as_of or _as_of()},
        files={"file": ("nea-register.csv", csv.encode("utf-8"), "text/csv")},
    )


def _create_brs(env, headers, *, registration_number="PVT-ABC12345", name="Example Business Limited"):
    return env.client.post("/v1/admin/build3/brs-records", headers=headers, json={
        "registration_type": "company_cr12",
        "registration_number": registration_number,
        "registered_name": name,
        "source_url": "https://brs.ecitizen.go.ke/",
        "evidence_sha256": hashlib.sha256(b"redacted official record").hexdigest(),
        "checked_at": _as_of(),
        "review_interval_days": 90,
    })


def test_nea_csv_import_accepts_actual_ra_na_formats_and_minimises_contact_details():
    parsed = parse_nea_csv(NEA_CSV.encode(), source_url=NEA_SOURCE, data_as_of=_as_of())
    assert parsed["record_count"] == 2
    assert parsed["rows"][0]["registration_number"] == "RA/2025/10/24"
    assert parsed["rows"][1]["registration_number"] == "NA/2021/03/27"
    assert parsed["rows"][0]["website_domains"] == ["riversidemanpower.com"]
    assert parsed["rows"][0]["email_domains"] == ["riversidemanpower.com"]
    assert "info@riversidemanpower.com" not in str(parsed["rows"])
    assert parsed["rows"][0]["licence_status"] == "valid"
    assert parsed["rows"][1]["licence_status"] == "expired"


def test_nea_csv_parser_handles_multiple_emails_in_one_published_cell():
    csv = "NEA Reg No,Agency Name,E-mail Address,Website,Status\nRA/2025/10/24,Agency Limited,first@gmail.com/second@agency.co.ke,agency.co.ke,Valid\n"
    parsed = parse_nea_csv(csv.encode(), source_url=NEA_SOURCE, data_as_of=_as_of())
    assert set(parsed["rows"][0]["email_domains"]) == {"gmail.com", "agency.co.ke"}


def test_nea_csv_rejects_non_official_source_future_date_and_too_many_rows():
    with pytest.raises(ValueError, match="official NEA"):
        parse_nea_csv(NEA_CSV.encode(), source_url="https://nea-example.com/register", data_as_of=_as_of())
    with pytest.raises(ValueError, match="official NEA"):
        parse_nea_csv(NEA_CSV.encode(), source_url=NEA_SOURCE + "?download=1", data_as_of=_as_of())
    future = (date.today() + timedelta(days=1)).isoformat()
    with pytest.raises(ValueError, match="future"):
        parse_nea_csv(NEA_CSV.encode(), source_url=NEA_SOURCE, data_as_of=future)
    many = "NEA Reg No,Agency Name,Status\n" + "BAD,Invalid,Valid\n" * 5001
    with pytest.raises(ValueError, match="5000"):
        parse_nea_csv(many.encode(), source_url=NEA_SOURCE, data_as_of=_as_of())


def test_snapshot_freshness_is_explicit():
    today = date(2026, 11, 4)
    assert snapshot_freshness("2026-11-04", today=today)["freshness"] == "fresh"
    assert snapshot_freshness("2026-10-20", today=today)["freshness"] == "aging"
    assert snapshot_freshness("2026-09-01", today=today)["freshness"] == "stale"


def test_domain_claim_extraction_recognises_social_and_web_domains():
    claims = extract_claims("Seller page: https://www.instagram.com/example_shop and https://example.co.ke/contact")
    assert claims["social_profiles"] == ["instagram:example_shop"]
    assert claims["domains"] == ["example.co.ke"]


def test_shared_platform_guard_does_not_block_generic_suffixes():
    assert not _is_shared_platform_domain("ordinary-company.com")
    assert not _is_shared_platform_domain("company.co.ke")
    assert _is_shared_platform_domain("co.ke")
    assert _is_shared_platform_domain("shop.myshopify.com")
    assert _is_shared_platform_domain("brand.wixsite.com")


def test_nea_import_requires_moderator_and_public_search_discloses_snapshot_scope(env):
    assert _import_nea(env, {}).status_code == 401
    user, _ = env.user("build3-user@example.com")
    assert _import_nea(env, user).status_code == 403
    mod, _ = env.user("build3-mod@example.com", "moderator")
    imported = _import_nea(env, mod)
    assert imported.status_code == 200, imported.text
    data = imported.json()
    assert data["record_count"] == 2
    found = env.client.get("/v1/build3/nea/search", params={"q": "RA/2025/10/24"}).json()
    assert found["status"] == "checked"
    assert found["results"][0]["agency_name"] == "Riverside Manpower Limited"
    assert found["results"][0]["display_status"] == "valid"
    assert found["results"][0]["data_as_of"] == _as_of()
    assert "not proof" in found["interpretation_note"]
    assert "info@riversidemanpower.com" not in str(found)


def test_no_nea_snapshot_is_not_misrepresented_as_unregistered(env):
    response = env.client.get("/v1/build3/nea/search", params={"q": "Example Agency"})
    assert response.status_code == 200
    assert response.json()["status"] == "snapshot_unavailable"
    assert "official register" in response.json()["interpretation_note"]


def test_stale_nea_snapshot_does_not_report_a_current_valid_licence(env):
    mod, _ = env.user("stale-nea-mod@example.com", "moderator")
    imported = _import_nea(env, mod, as_of="2026-05-18")
    assert imported.status_code == 200
    found = env.client.get("/v1/build3/nea/search", params={"q": "RA/2025/10/24"}).json()
    assert found["results"][0]["display_status"] == "historical_valid_status_not_current"
    assert found["results"][0]["freshness"] == "stale"


def test_nea_snapshot_replacement_supersedes_previous_snapshot(env):
    mod, _ = env.user("replace-nea-mod@example.com", "moderator")
    first = _import_nea(env, mod)
    second = _import_nea(env, mod)
    assert first.status_code == second.status_code == 200
    with env.db() as db:
        statuses = list(db.execute(select(m.NEARegistrySnapshot.status)).scalars())
    assert statuses.count("active") == 1
    assert statuses.count("superseded") == 1


def test_brs_records_are_moderator_only_and_store_hmac_not_registration_number(env):
    assert _create_brs(env, {}).status_code == 401
    user, _ = env.user("brs-user@example.com")
    assert _create_brs(env, user).status_code == 403
    moderator, _ = env.user("brs-moderator@example.com", "moderator")
    result = _create_brs(env, moderator)
    assert result.status_code == 200, result.text
    payload = result.json()
    assert payload["status"] == "reviewed_record_saved"
    assert payload["registration_number_masked"] != "PVTABC12345"
    with env.db() as db:
        row = db.get(m.BRSBusinessRecord, payload["id"])
        assert row.registration_hmac != "PVTABC12345"
        assert row.registered_name == "Example Business Limited"
        assert not hasattr(row, "cr12_document")


def test_brs_record_rejects_unofficial_source_and_future_verification_date(env):
    moderator, _ = env.user("brs-validation-mod@example.com", "moderator")
    body = {
        "registration_type": "company_cr12", "registration_number": "PVT-ABC12345",
        "registered_name": "Example Business Limited", "source_url": "https://fake-brs.example.com/",
        "evidence_sha256": hashlib.sha256(b"record").hexdigest(), "checked_at": _as_of(),
    }
    assert env.client.post("/v1/admin/build3/brs-records", json=body, headers=moderator).status_code == 422
    body["source_url"] = "https://brs.ecitizen.go.ke/"
    body["checked_at"] = (date.today() + timedelta(days=1)).isoformat()
    assert env.client.post("/v1/admin/build3/brs-records", json=body, headers=moderator).status_code == 422


def test_website_association_and_social_profile_must_be_separately_reviewed(env):
    mod, _ = env.user("brs-links-mod@example.com", "moderator")
    created = _create_brs(env, mod)
    record_id = created.json()["id"]
    base = {
        "association_type": "website_domain", "value": "examplebusiness.co.ke",
        "source_url": "https://examplebusiness.co.ke/contact", "evidence_sha256": hashlib.sha256(b"website evidence").hexdigest(),
        "reviewed_at": _as_of(), "control_review_confirmed": True,
    }
    added = env.client.post(f"/v1/admin/build3/brs-records/{record_id}/associations", json=base, headers=mod)
    assert added.status_code == 200, added.text
    social = {
        "association_type": "social_profile", "value": "https://www.instagram.com/examplebusiness/",
        "source_url": "https://examplebusiness.co.ke/contact", "evidence_sha256": hashlib.sha256(b"profile link").hexdigest(),
        "reviewed_at": _as_of(), "control_review_confirmed": True,
    }
    assert env.client.post(f"/v1/admin/build3/brs-records/{record_id}/associations", json=social, headers=mod).status_code == 200
    # Website evidence alone is not enough to add a profile link from an unrelated domain.
    social["source_url"] = "https://other-domain.co.ke/about"
    assert env.client.post(f"/v1/admin/build3/brs-records/{record_id}/associations", json=social, headers=mod).status_code == 422
    # Normal commercial domains are accepted; shared platform hosting is not.
    shared = {**base, "value": "merchant.myshopify.com", "source_url": "https://merchant.myshopify.com/about"}
    assert env.client.post(f"/v1/admin/build3/brs-records/{record_id}/associations", json=shared, headers=mod).status_code == 422
    no_confirm = {**base, "value": "anotherbusiness.co.ke", "source_url": "https://anotherbusiness.co.ke/", "control_review_confirmed": False}
    assert env.client.post(f"/v1/admin/build3/brs-records/{record_id}/associations", json=no_confirm, headers=mod).status_code == 422


def test_domain_or_social_profile_can_reverse_match_reviewed_brs_association(env):
    mod, _ = env.user("brs-reverse-mod@example.com", "moderator")
    created = _create_brs(env, mod)
    record_id = created.json()["id"]
    website = {
        "association_type": "website_domain", "value": "examplebusiness.co.ke",
        "source_url": "https://examplebusiness.co.ke/contact", "evidence_sha256": hashlib.sha256(b"website").hexdigest(),
        "reviewed_at": _as_of(), "control_review_confirmed": True,
    }
    assert env.client.post(f"/v1/admin/build3/brs-records/{record_id}/associations", json=website, headers=mod).status_code == 200
    social = {
        "association_type": "social_profile", "value": "https://www.instagram.com/examplebusiness/",
        "source_url": "https://examplebusiness.co.ke/contact", "evidence_sha256": hashlib.sha256(b"profile").hexdigest(),
        "reviewed_at": _as_of(), "control_review_confirmed": True,
    }
    assert env.client.post(f"/v1/admin/build3/brs-records/{record_id}/associations", json=social, headers=mod).status_code == 200
    domain_result = env.client.post("/v1/build3/entities/verify", json={"domain": "www.examplebusiness.co.ke"})
    assert domain_result.status_code == 200, domain_result.text
    brs = domain_result.json()["brs"]
    assert brs["match_method"] == "reviewed_digital_association"
    assert brs["comparisons"]["website_domain_association_match"] is True
    social_result = env.client.post("/v1/build3/entities/verify", json={"social_profile": "https://instagram.com/examplebusiness/"})
    assert social_result.status_code == 200
    assert social_result.json()["brs"]["comparisons"]["social_profile_association_match"] is True


def test_brs_revoke_removes_publicly_resolvable_association(env):
    mod, _ = env.user("brs-revoke-mod@example.com", "moderator")
    created = _create_brs(env, mod)
    record_id = created.json()["id"]
    body = {
        "association_type": "website_domain", "value": "examplebusiness.co.ke",
        "source_url": "https://examplebusiness.co.ke/contact", "evidence_sha256": hashlib.sha256(b"website").hexdigest(),
        "reviewed_at": _as_of(), "control_review_confirmed": True,
    }
    env.client.post(f"/v1/admin/build3/brs-records/{record_id}/associations", json=body, headers=mod)
    revoked = env.client.post(f"/v1/admin/build3/brs-records/{record_id}/revoke", json={"reason_code": "source_correction"}, headers=mod)
    assert revoked.status_code == 200
    result = env.client.post("/v1/build3/entities/verify", json={"domain": "examplebusiness.co.ke"}).json()
    assert result["brs"]["status"] == "manual_official_search_required"


def test_entity_verify_never_claims_no_match_means_unregistered(env):
    response = env.client.post("/v1/build3/entities/verify", json={"business_name": "Unknown Employment Agency", "employment_agency": True})
    assert response.status_code == 200
    result = response.json()
    assert result["nea"]["status"] == "manual_live_verification_required"
    assert result["brs"]["status"] == "manual_official_search_required"
    assert "Separate evidence" in result["overall_interpretation"]


def test_main_check_path_adds_nea_context_without_overriding_deterministic_verdict(env):
    text = "I have an overseas recruitment offer. NEA Reg No: RA/2025/10/24. Pay an application fee to reserve the job."
    before = env.check(text)["assessment"]["label"]
    moderator, _ = env.user("integrated-nea-mod@example.com", "moderator")
    assert _import_nea(env, moderator).status_code == 200
    after_result = env.check(text)
    assert after_result["assessment"]["label"] == before
    context = after_result["assessment"]["investigation_intelligence"]["entity_verification"]
    assert context["nea"]["status"] == "listed_valid_in_snapshot"
    assert context["nea"]["candidates"][0]["registration_number"] == "RA/2025/10/24"


def test_main_check_can_match_brs_business_via_domain_without_registration_number(env):
    moderator, _ = env.user("integrated-brs-mod@example.com", "moderator")
    created = _create_brs(env, moderator)
    record_id = created.json()["id"]
    association = {
        "association_type": "website_domain", "value": "examplebusiness.co.ke",
        "source_url": "https://examplebusiness.co.ke/contact", "evidence_sha256": hashlib.sha256(b"website").hexdigest(),
        "reviewed_at": _as_of(), "control_review_confirmed": True,
    }
    assert env.client.post(f"/v1/admin/build3/brs-records/{record_id}/associations", json=association, headers=moderator).status_code == 200
    checked = env.check("Company name: Example Business Limited\nShop website: https://examplebusiness.co.ke")
    result = checked["assessment"]["investigation_intelligence"]["entity_verification"]["brs"]
    assert result["match_method"] == "reviewed_digital_association"
    assert result["comparisons"]["website_domain_association_match"] is True


def test_entity_verify_rejects_malformed_inputs(env):
    assert env.client.post("/v1/build3/entities/verify", json={}).status_code == 422
    assert env.client.post("/v1/build3/entities/verify", json={"domain": "localhost"}).status_code == 422
    assert env.client.post("/v1/build3/entities/verify", json={"social_profile": "https://unknown.example/user"}).status_code == 422


def test_admin_brs_source_rejects_non_default_ports_and_url_credentials(env):
    mod, _ = env.user("brs-url-mod@example.com", "moderator")
    result = _create_brs(env, mod)
    assert result.status_code == 200
    payload = {
        "registration_type": "company_cr12", "registration_number": "PVT-OTHER123",
        "registered_name": "Other Business Limited", "source_url": "https://user:pass@brs.ecitizen.go.ke/",
        "evidence_sha256": hashlib.sha256(b"redacted record").hexdigest(), "checked_at": _as_of(),
    }
    assert env.client.post("/v1/admin/build3/brs-records", headers=mod, json=payload).status_code == 422
    payload["source_url"] = "https://brs.ecitizen.go.ke:8443/"
    assert env.client.post("/v1/admin/build3/brs-records", headers=mod, json=payload).status_code == 422


def test_email_domain_association_can_be_checked_without_exposing_local_part(env):
    mod, _ = env.user("brs-email-mod@example.com", "moderator")
    created = _create_brs(env, mod)
    record_id = created.json()["id"]
    website = {
        "association_type": "website_domain", "value": "examplebusiness.co.ke",
        "source_url": "https://examplebusiness.co.ke/contact", "evidence_sha256": hashlib.sha256(b"website").hexdigest(),
        "reviewed_at": _as_of(), "control_review_confirmed": True,
    }
    assert env.client.post(f"/v1/admin/build3/brs-records/{record_id}/associations", json=website, headers=mod).status_code == 200
    email_link = {
        "association_type": "contact_email_domain", "value": "examplebusiness.co.ke",
        "source_url": "https://examplebusiness.co.ke/contact", "evidence_sha256": hashlib.sha256(b"email published on website").hexdigest(),
        "reviewed_at": _as_of(), "control_review_confirmed": True,
    }
    assert env.client.post(f"/v1/admin/build3/brs-records/{record_id}/associations", json=email_link, headers=mod).status_code == 200
    result = env.client.post("/v1/build3/entities/verify", json={"contact_email": "private-person@examplebusiness.co.ke"})
    assert result.status_code == 200
    assert result.json()["brs"]["comparisons"]["business_email_domain_association_match"] is True
    assert "private-person" not in str(result.json())
