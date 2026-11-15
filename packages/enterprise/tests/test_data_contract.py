"""Regression test suite for Phase 2: Bank Data Contract and Detector Readiness Framework."""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from toroka_enterprise.coverage import BLIND, CHECK, DEGRADED, READY, coverage_report, render
from toroka_enterprise.data_contract import (
    CONTRACT_VERSION,
    DETECTOR_DEPENDENCIES,
    FIELD_METADATA,
    contract_dict,
    contract_fingerprint,
    contract_markdown,
    validate_registry,
)
from toroka_enterprise.ingest import FEED_KEY, REQUIRED, SPEC, DataQuality, ingest_dir
from toroka_enterprise.manifest import build_manifest, reproduce, result_digest
from toroka_enterprise.mapping import OPTIONAL, load_mapping
from toroka_enterprise.profile import INSIDER_PROFILE
from toroka_enterprise.pseudonym import Pseudonymiser
from toroka_enterprise.replay import generate
from toroka_enterprise.scan import run_scan
from toroka_enterprise.scenarios import EntitlementIntegrity, Focus, Rules
from toroka_enterprise.schema import AuditEvent, Dataset, SysAccount
from .helpers import base_feeds, scan as scan_feeds, ts

SECRET = "s" * 40


def test_01_all_eight_detectors_registered():
    """1. All eight detectors have registered dependencies."""
    assert len(DETECTOR_DEPENDENCIES) == 8
    expected = {
        "access_justification",
        "bulk_unjustified_browsing",
        "auth_channel_change",
        "account_lifecycle",
        "change_then_money",
        "suspense_posting_integrity",
        "payroll_beneficiary_integrity",
        "entitlement_integrity",
    }
    actual = {d.detector_id for d in DETECTOR_DEPENDENCIES}
    assert actual == expected


def test_02_every_registered_feed_exists_in_spec():
    """2. Every registered feed exists in ingest.SPEC."""
    for d in DETECTOR_DEPENDENCIES:
        for feed in d.required_feeds:
            assert feed in SPEC, f"{d.detector_id}: required feed '{feed}' not in SPEC"
            assert feed in FEED_KEY, f"{d.detector_id}: required feed '{feed}' not in FEED_KEY"
        for feed in d.supporting_feeds:
            assert feed in SPEC, f"{d.detector_id}: supporting feed '{feed}' not in SPEC"
            assert feed in FEED_KEY, f"{d.detector_id}: supporting feed '{feed}' not in FEED_KEY"


def test_03_every_registered_field_exists_in_canonical_feed():
    """3. Every registered field exists in its canonical feed."""
    for d in DETECTOR_DEPENDENCIES:
        for qualified in d.required_fields + d.supporting_fields:
            feed, sep, field = qualified.partition(".")
            assert sep == ".", f"{d.detector_id}: invalid field format '{qualified}'"
            assert feed in SPEC, f"{d.detector_id}: feed '{feed}' not in SPEC"
            assert field in SPEC[feed], f"{d.detector_id}: field '{field}' not in SPEC['{feed}']"


def test_04_every_canonical_field_has_metadata():
    """4. Every canonical field has field metadata in FIELD_METADATA."""
    validate_registry()  # Raises ValueError if missing
    for feed, fields in SPEC.items():
        assert feed in FIELD_METADATA
        for field in fields:
            meta = FIELD_METADATA[feed][field]
            assert "data_type" in meta
            assert "description" in meta
            assert "pii_classification" in meta
            assert len(meta["description"]) > 10


def test_05_missing_required_feeds_produce_blind(tmp_path):
    """5. Missing required feeds produce BLIND."""
    generate(tmp_path, seed=3)
    ps = Pseudonymiser(SECRET)
    ds, q = ingest_dir(tmp_path, ps)

    # Simulate missing portfolio feed
    ds.available.remove("assignments")
    cov = {r["detector_id"]: r for r in coverage_report(ds)}
    assert cov["access_justification"]["status"] == BLIND
    assert "missing feed(s): portfolio" in cov["access_justification"]["explanation"]
    assert cov["bulk_unjustified_browsing"]["status"] == BLIND

    # Simulate missing postings feed
    ds.available.remove("postings")
    cov2 = {r["detector_id"]: r for r in coverage_report(ds)}
    assert cov2["suspense_posting_integrity"]["status"] == BLIND
    assert cov2["payroll_beneficiary_integrity"]["status"] == BLIND


def test_06_missing_required_fields_produce_blind(tmp_path):
    """6. Missing required fields produce BLIND."""
    generate(tmp_path, seed=3)
    ps = Pseudonymiser(SECRET)
    ds, q = ingest_dir(tmp_path, ps)

    # When salary_account is absent, payroll_beneficiary_integrity must be BLIND
    ds.absent_fields.add("hr_roster.salary_account")
    cov = {r["detector_id"]: r for r in coverage_report(ds)}
    assert cov["payroll_beneficiary_integrity"]["status"] == BLIND
    assert "hr_roster.salary_account" in cov["payroll_beneficiary_integrity"]["explanation"]

    # When approved_by_account is absent, suspense_posting_integrity must be BLIND
    ds.absent_fields.add("postings.approved_by_account")
    cov2 = {r["detector_id"]: r for r in coverage_report(ds)}
    assert cov2["suspense_posting_integrity"]["status"] == BLIND


def test_07_missing_supporting_fields_produce_degraded_where_material(tmp_path):
    """7. Missing optional/supporting fields produce DEGRADED where material."""
    generate(tmp_path, seed=3)
    ps = Pseudonymiser(SECRET)
    ds, q = ingest_dir(tmp_path, ps)

    # Missing CRM tickets or staff_id on tickets degrades access_justification
    ds.absent_fields.add("service_requests.staff_id")
    cov = {r["detector_id"]: r for r in coverage_report(ds)}
    assert cov["access_justification"]["status"] == DEGRADED
    assert "CRM" in cov["access_justification"]["explanation"]

    # Missing approver on audit events degrades account_lifecycle
    ds.absent_fields.add("audit_log.approver_account_id")
    cov2 = {r["detector_id"]: r for r in coverage_report(ds)}
    assert cov2["account_lifecycle"]["status"] == DEGRADED
    assert "approver" in cov2["account_lifecycle"]["explanation"]

    # Missing is_privileged degrades entitlement_integrity
    ds.absent_fields.add("system_accounts.is_privileged")
    cov3 = {r["detector_id"]: r for r in coverage_report(ds)}
    assert cov3["entitlement_integrity"]["status"] == DEGRADED
    assert "is_privileged" in cov3["entitlement_integrity"]["explanation"]


def test_08_missing_non_material_optional_fields_do_not_produce_blind(tmp_path):
    """8. Missing non-material optional fields do not automatically make a detector BLIND."""
    generate(tmp_path, seed=3)
    ps = Pseudonymiser(SECRET)
    ds, q = ingest_dir(tmp_path, ps)

    # Add non-material optional fields to absent
    ds.absent_fields.update({"service_requests.closed_at", "customers.dormant_since", "payments.beneficiary"})
    cov = {r["detector_id"]: r for r in coverage_report(ds)}

    # These detectors should remain READY (or CHECK), not BLIND
    assert cov["access_justification"]["status"] in (READY, DEGRADED)
    assert cov["account_lifecycle"]["status"] in (READY, DEGRADED)
    assert cov["change_then_money"]["status"] in (READY, CHECK)


def test_09_material_feed_quality_problems_produce_degraded(tmp_path):
    """9. Material feed-quality problems produce DEGRADED."""
    generate(tmp_path, seed=3)
    ps = Pseudonymiser(SECRET)
    ds, q = ingest_dir(tmp_path, ps)

    # Mark crm feed as degraded
    ds.degraded_feeds.add("crm")
    cov = {r["detector_id"]: r for r in coverage_report(ds)}
    assert cov["access_justification"]["status"] == DEGRADED
    assert "input quality degraded for: crm" in cov["access_justification"]["explanation"]


def test_10_absent_optional_fields_detected_for_canonical_csv(tmp_path):
    """10. Absent optional fields are detected for canonical CSV ingestion."""
    # Write audit_log.csv without approver_account_id
    audit_rows = [
        {"ts": "2026-05-01T09:00:00Z", "account_id": "ACC1", "action": "profile_view", "customer_id": "CUST1"}
    ]
    audit_file = tmp_path / "audit_log.csv"
    with open(audit_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ts", "account_id", "action", "customer_id"])
        writer.writeheader()
        writer.writerows(audit_rows)

    # Write minimal system_accounts.csv without is_privileged
    sys_file = tmp_path / "system_accounts.csv"
    with open(sys_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["account_id", "staff_id", "system", "status"])
        writer.writeheader()
        writer.writerow({"account_id": "ACC1", "staff_id": "STF1", "system": "core", "status": "active"})

    ps = Pseudonymiser(SECRET)
    ds, q = ingest_dir(tmp_path, ps)

    assert "audit_log.approver_account_id" in q.absent_fields
    assert "system_accounts.is_privileged" in q.absent_fields
    assert "audit_log.approver_account_id" in ds.absent_fields
    assert "system_accounts.is_privileged" in ds.absent_fields


def test_11_absent_optional_fields_detected_for_mapped_ingestion(tmp_path):
    """11. Absent optional fields are detected for mapped ingestion."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    log_file = data_dir / "audit.txt"
    log_file.write_text("when|user|act|cif\n2026-05-01T09:00:00Z|ACC1|profile_view|CUST1\n")
    sys_file = data_dir / "users.txt"
    sys_file.write_text("acc|staff|app|st\nACC1|STF1|core|active\n")

    mapping_toml = f"""
    [feeds.audit_log]
    file = "audit.txt"
    delimiter = "|"
    columns = {{ ts = "when", account_id = "user", action = "act", customer_id = "cif" }}

    [feeds.system_accounts]
    file = "users.txt"
    delimiter = "|"
    columns = {{ account_id = "acc", staff_id = "staff", system = "app", status = "st" }}
    """
    mapping = load_mapping(mapping_toml)
    ps = Pseudonymiser(SECRET)
    ds, q = ingest_dir(data_dir, ps, mapping)

    assert "audit_log.approver_account_id" in q.absent_fields
    assert "system_accounts.is_privileged" in q.absent_fields
    assert "audit_log.approver_account_id" in ds.absent_fields
    assert "system_accounts.is_privileged" in ds.absent_fields


def test_12_canonical_and_mapped_input_paths_report_missing_fields_consistently(tmp_path):
    """12. Canonical and mapped input paths report missing fields consistently without duplicates."""
    # Canonical setup
    c_dir = tmp_path / "canonical"
    c_dir.mkdir()
    (c_dir / "audit_log.csv").write_text("ts,account_id,action,customer_id\n2026-05-01T09:00:00Z,ACC1,profile_view,C1\n")
    (c_dir / "system_accounts.csv").write_text("account_id,staff_id,system,status\nACC1,STF1,core,active\n")

    ps1 = Pseudonymiser(SECRET)
    _, q_canon = ingest_dir(c_dir, ps1)

    # Mapped setup
    m_dir = tmp_path / "mapped"
    m_dir.mkdir()
    (m_dir / "audit.txt").write_text("ts,account_id,action,customer_id\n2026-05-01T09:00:00Z,ACC1,profile_view,C1\n")
    (m_dir / "sys.txt").write_text("account_id,staff_id,system,status\nACC1,STF1,core,active\n")
    mapping_toml = """
    [feeds.audit_log]
    file = "audit.txt"
    columns = { ts = "ts", account_id = "account_id", action = "action", customer_id = "customer_id" }
    [feeds.system_accounts]
    file = "sys.txt"
    columns = { account_id = "account_id", staff_id = "staff_id", system = "system", status = "status" }
    """
    ps2 = Pseudonymiser(SECRET)
    _, q_mapped = ingest_dir(m_dir, ps2, load_mapping(mapping_toml))

    # Compare absent fields between both paths
    shared_absent = {"audit_log.approver_account_id", "system_accounts.is_privileged"}
    assert shared_absent.issubset(set(q_canon.absent_fields))
    assert shared_absent.issubset(set(q_mapped.absent_fields))
    # Confirm no duplicates in either list
    assert len(q_canon.absent_fields) == len(set(q_canon.absent_fields))
    assert len(q_mapped.absent_fields) == len(set(q_mapped.absent_fields))


def test_13_cli_data_contract_json_produces_valid_json():
    """13. data-contract --format json produces valid JSON with required contract elements."""
    contract = contract_dict()
    text = json.dumps(contract)
    parsed = json.loads(text)
    assert parsed["contract_version"] == CONTRACT_VERSION
    assert "feeds" in parsed and len(parsed["feeds"]) == len(SPEC)
    assert "detectors" in parsed and len(parsed["detectors"]) == len(DETECTOR_DEPENDENCIES)


def test_14_markdown_output_readable_and_contains_field_requirements():
    """14. Markdown output is readable and contains field requirements and detector table."""
    md = contract_markdown()
    assert f"Bank Data Contract (v{CONTRACT_VERSION})" in md
    assert "Canonical Feeds Overview" in md
    assert "Feed Schemas & Field Catalog" in md
    assert "Detector Dependencies & Readiness Matrix" in md
    assert "READY" in md and "BLIND" in md and "DEGRADED" in md and "CHECK" in md
    for feed in SPEC:
        assert f"`{feed}`" in md


def test_15_manifest_records_contract_version_and_fingerprint(tmp_path):
    """15. The manifest records the contract version and deterministic fingerprint."""
    generate(tmp_path, seed=5)
    ps = Pseudonymiser(SECRET)
    ds, q = ingest_dir(tmp_path, ps)
    manifest = build_manifest(q, mapping_text=None, rules=Rules(), profile=INSIDER_PROFILE, secret=SECRET)

    assert "contract_version" in manifest
    assert manifest["contract_version"] == CONTRACT_VERSION
    assert "contract_sha256" in manifest
    assert len(manifest["contract_sha256"]) == 64
    assert manifest["contract_sha256"] == contract_fingerprint()


def test_16_reproduction_detects_changed_contract_fingerprint(tmp_path):
    """16. Reproduction detects a changed contract fingerprint."""
    generate(tmp_path, seed=5)
    ps = Pseudonymiser(SECRET)
    ds, q = ingest_dir(tmp_path, ps)
    sc = run_scan(ds, quality=q)
    manifest = build_manifest(q, mapping_text=None, rules=Rules(), profile=INSIDER_PROFILE, secret=SECRET)
    digest = result_digest(sc)

    # Tamper with stored contract fingerprint
    tampered_manifest = dict(manifest, contract_sha256="0" * 64)
    res = reproduce(tampered_manifest, digest, tmp_path, mapping_text=None, rules=Rules(), profile=INSIDER_PROFILE, secret=SECRET)

    assert not res["ok"]
    assert "contract_sha256" in res["config_differences"]
    assert "Configuration differs" in res["explanation"]


def test_17_render_coverage_table():
    """17. render(coverage_report(ds)) outputs readable aligned tabular format."""
    ds = Dataset()
    cov = coverage_report(ds)
    rendered = render(cov)
    assert "BLIND" in rendered
    assert len(rendered.splitlines()) == 8


def test_18_entitlement_integrity_without_is_privileged_does_not_manufacture_risk():
    """18. Missing is_privileged data cannot silently produce an unsupported duplicate-profile risk conclusion."""
    now = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    focus = Focus("STF-TEST", None)

    # Scenario with 2 accounts for STF-TEST in core system
    ds = Dataset()
    ds.available.add("accounts")
    ds.events.append(AuditEvent(1, now, "ACC-01", "profile_view", "C-01", None))
    ds.accounts["ACC-01"] = SysAccount("ACC-01", "STF-TEST", "core", "active", False)
    ds.accounts["ACC-02"] = SysAccount("ACC-02", "STF-TEST", "core", "active", False)
    ds.reindex()

    # Case A: When is_privileged is ABSENT, must produce CONTEXT, NOT RISK
    ds.absent_fields.add("system_accounts.is_privileged")
    detector = EntitlementIntegrity(ds, Rules())
    evs_absent = detector.run(focus)
    assert len(evs_absent) == 1
    assert evs_absent[0].polarity == "context"
    assert "is_privileged is absent" in evs_absent[0].why_it_matters
    assert "privilege level is unsupplied" in evs_absent[0].summary
    assert evs_absent[0].strength == 1

    # Case B: When is_privileged IS supplied and both are standard, it properly flags risk
    ds.absent_fields.remove("system_accounts.is_privileged")
    detector_normal = EntitlementIntegrity(ds, Rules())
    evs_normal = detector_normal.run(focus)
    assert len(evs_normal) == 1
    assert evs_normal[0].polarity == "risk"
    assert "undermines segregation of duties" in evs_normal[0].why_it_matters
