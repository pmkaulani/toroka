"""Regression test suite for Phase 2: Bank Data Contract and Detector Readiness Framework."""
from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone
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
from toroka_enterprise.ingest import FEED_KEY, REQUIRED, SPEC, DataQuality, _amount, ingest_dir
from toroka_enterprise.manifest import build_manifest, reproduce, result_digest
from toroka_enterprise.mapping import OPTIONAL, load_mapping
from toroka_enterprise.profile import INSIDER_PROFILE
from toroka_enterprise.pseudonym import Pseudonymiser
from toroka_enterprise.replay import generate
from toroka_enterprise.scan import run_scan
from toroka_enterprise.scenarios import (
    AccessJustification,
    AuthChannelChange,
    BulkBrowsing,
    ChangeThenMoney,
    EntitlementIntegrity,
    Focus,
    PayrollBeneficiary,
    PostingIntegrity,
    Rules,
    format_money,
    format_money_totals,
)
from toroka_enterprise.schema import AuditEvent, Customer, Dataset, Instruction, Payment, Posting, Staff, SysAccount
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
    assert cov["change_then_money"]["status"] in (READY, DEGRADED, CHECK)


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
    ds.events.append(AuditEvent(ts=now, account_ref="ACC-01", action="profile_view", customer_ref="C-01", approver_ref=None, row=1))
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
    assert isinstance(evs_absent[0].observed_at, datetime)

    # Case B: When is_privileged IS supplied and both are standard, it properly flags risk
    ds.absent_fields.remove("system_accounts.is_privileged")
    detector_normal = EntitlementIntegrity(ds, Rules())
    evs_normal = detector_normal.run(focus)
    assert len(evs_normal) == 1
    assert evs_normal[0].polarity == "risk"
    assert "undermines segregation of duties" in evs_normal[0].why_it_matters
    assert isinstance(evs_normal[0].observed_at, datetime)


def test_19_payroll_destination_absent_produces_blind_and_provider_stands_down():
    """19. When postings.counter_party is absent, payroll detector is BLIND and stands down."""
    ds = Dataset()
    ds.available.update({"postings", "hr", "accounts"})
    ds.absent_fields.add("postings.counter_party")
    cov = {r["detector_id"]: r for r in coverage_report(ds)}
    assert cov["payroll_beneficiary_integrity"]["status"] == BLIND
    assert "postings.counter_party" in cov["payroll_beneficiary_integrity"]["explanation"]

    det = PayrollBeneficiary(ds, Rules())
    assert det.run(Focus("S1", None)) == []


def test_20_payroll_destination_blank_on_individual_rows_produces_context_not_risk():
    """20. Manual salary posting with blank/None counterparty produces context, never risk."""
    now = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    ds = Dataset()
    ds.available.update({"postings", "hr", "accounts"})
    ds.accounts["A-S1"] = SysAccount("A-S1", "S1", "core", "active", False)
    ds.postings.append(Posting("P1", now, "PAYROLL", None, 5000000, "A-S1", None, True, "SALARY"))
    ds.staff["S1"] = Staff(staff_ref="S1", status="active", role="teller", branch="BR01", end_date=None, salary_account_ref="SAL-S1")
    ds.reindex()

    det = PayrollBeneficiary(ds, Rules())
    evs = det.run(Focus("S1", None))
    assert len(evs) == 1
    assert evs[0].polarity == "context"
    assert "no usable destination-account reference" in evs[0].summary
    assert evs[0].strength == 1
    assert isinstance(evs[0].observed_at, datetime)


def test_21_payroll_destination_known_not_in_hr_produces_risk():
    """21. Manual salary posting with known destination not on HR roster produces risk."""
    now = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    ds = Dataset()
    ds.available.update({"postings", "hr", "accounts"})
    ds.accounts["A-S1"] = SysAccount("A-S1", "S1", "core", "active", False)
    ds.postings.append(Posting("P1", now, "PAYROLL", "ACC-FRAUD", 5000000, "A-S1", None, True, "SALARY"))
    ds.staff["S1"] = Staff(staff_ref="S1", status="active", role="teller", branch="BR01", end_date=None, salary_account_ref="SAL-S1")
    ds.reindex()

    det = PayrollBeneficiary(ds, Rules())
    evs = det.run(Focus("S1", None))
    assert len(evs) == 1
    assert evs[0].polarity == "risk"
    assert "match no employee on the HR roster" in evs[0].summary
    assert evs[0].strength == 4
    assert isinstance(evs[0].observed_at, datetime)


def test_22_valid_hr_salary_account_match_is_benign():
    """22. Manual salary posting to verified HR employee salary account returns no findings."""
    now = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    ds = Dataset()
    ds.available.update({"postings", "hr", "accounts"})
    ds.accounts["A-S1"] = SysAccount("A-S1", "S1", "core", "active", False)
    ds.postings.append(Posting("P1", now, "PAYROLL", "SAL-S1", 5000000, "A-S1", None, True, "SALARY"))
    ds.staff["S1"] = Staff(staff_ref="S1", status="active", role="teller", branch="BR01", end_date=None, salary_account_ref="SAL-S1")
    ds.reindex()

    det = PayrollBeneficiary(ds, Rules())
    assert det.run(Focus("S1", None)) == []


def test_23_credit_transaction_after_contact_change_does_not_trigger_outbound_risk():
    """23. Inbound credit transaction following account change must not trigger outbound money risk."""
    t0 = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(days=1)
    ds = Dataset()
    ds.available.update({"audit", "payments", "instructions", "accounts"})
    ds.accounts["A-S1"] = SysAccount("A-S1", "S1", "core", "active", False)
    ds.events.append(AuditEvent(ts=t0, account_ref="A-S1", action="contact_change", customer_ref="C-01", approver_ref=None, row=1))
    ds.payments.append(Payment(payment_id="PMT-1", ts=t1, customer_ref="C-01", channel="online", amount=1000000, beneficiary_ref="B-1", direction="credit"))
    ds.reindex()

    det = ChangeThenMoney(ds, Rules())
    evs = det.run(Focus("S1", "C-01"))
    assert evs == []


def test_24_debit_transaction_after_contact_change_produces_risk():
    """24. Outbound debit transaction following unexplained change produces risk evidence."""
    t0 = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(days=1)
    ds = Dataset()
    ds.available.update({"audit", "payments", "instructions", "accounts"})
    ds.accounts["A-S1"] = SysAccount("A-S1", "S1", "core", "active", False)
    ds.events.append(AuditEvent(ts=t0, account_ref="A-S1", action="contact_change", customer_ref="C-01", approver_ref=None, row=1))
    ds.payments.append(Payment(payment_id="PMT-1", ts=t1, customer_ref="C-01", channel="online", amount=1000000, beneficiary_ref="B-1", direction="debit"))
    ds.reindex()

    det = ChangeThenMoney(ds, Rules())
    evs = det.run(Focus("S1", "C-01"))
    assert len(evs) == 1
    assert evs[0].polarity == "risk"
    assert "followed by 1 outbound payment(s)" in evs[0].summary
    assert isinstance(evs[0].observed_at, datetime)


def test_25_unknown_direction_after_contact_change_produces_context_not_risk():
    """25. Payment with unknown direction produces context disclosure, never outbound risk."""
    t0 = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(days=1)
    ds = Dataset()
    ds.available.update({"audit", "payments", "instructions", "accounts"})
    ds.accounts["A-S1"] = SysAccount("A-S1", "S1", "core", "active", False)
    ds.events.append(AuditEvent(ts=t0, account_ref="A-S1", action="contact_change", customer_ref="C-01", approver_ref=None, row=1))
    ds.payments.append(Payment(payment_id="PMT-1", ts=t1, customer_ref="C-01", channel="online", amount=1000000, beneficiary_ref="B-1", direction="unknown"))
    ds.reindex()

    det = ChangeThenMoney(ds, Rules())
    evs = det.run(Focus("S1", "C-01"))
    assert len(evs) == 1
    assert evs[0].polarity == "context"
    assert "direction (debit/credit) is unsupplied or unknown" in evs[0].summary
    assert evs[0].strength == 1


def test_26_missing_direction_field_produces_context_not_risk():
    """26. Missing payments.direction field produces context and DEGRADED readiness."""
    t0 = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(days=1)
    ds = Dataset()
    ds.available.update({"audit", "payments", "instructions", "accounts"})
    ds.absent_fields.add("payments.direction")
    ds.accounts["A-S1"] = SysAccount("A-S1", "S1", "core", "active", False)
    ds.events.append(AuditEvent(ts=t0, account_ref="A-S1", action="contact_change", customer_ref="C-01", approver_ref=None, row=1))
    ds.payments.append(Payment(payment_id="PMT-1", ts=t1, customer_ref="C-01", channel="online", amount=1000000, beneficiary_ref="B-1", direction="unknown"))
    ds.reindex()

    cov = {r["detector_id"]: r for r in coverage_report(ds)}
    assert cov["change_then_money"]["status"] == DEGRADED

    det = ChangeThenMoney(ds, Rules())
    evs = det.run(Focus("S1", "C-01"))
    assert len(evs) == 1
    assert evs[0].polarity == "context"


def test_27_missing_system_accounts_produces_blind_for_attributing_detectors():
    """27. Missing system_accounts feed makes all account-attributing detectors BLIND."""
    ds = Dataset()
    ds.available.update({"audit", "assignments", "instructions", "payments", "customers", "postings", "hr"})
    cov = {r["detector_id"]: r for r in coverage_report(ds)}
    for det_id in ("access_justification", "bulk_unjustified_browsing", "auth_channel_change", "account_lifecycle", "change_then_money", "suspense_posting_integrity", "payroll_beneficiary_integrity"):
        assert cov[det_id]["status"] == BLIND, f"{det_id} should be BLIND without system_accounts"
        assert "system_accounts" in cov[det_id]["explanation"]


def test_28_missing_crm_and_missing_hr_produces_context_not_risk():
    """28. Missing CRM and missing HR produces context disclosure in access checks, never risk."""
    now = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    ds = Dataset()
    ds.available.update({"audit", "assignments", "accounts"})
    ds.accounts["A-S1"] = SysAccount("A-S1", "S1", "core", "active", False)
    ds.events.append(AuditEvent(ts=now, account_ref="A-S1", action="profile_view", customer_ref="C-01", approver_ref=None, row=1))
    ds.reindex()

    focus = Focus("S1", "C-01")
    det = AccessJustification(ds, Rules())
    evs = det.run(focus)
    assert len(evs) == 1
    assert evs[0].polarity == "context"
    assert "service-request data is incomplete or unavailable" in evs[0].summary
    assert evs[0].strength == 1


def test_29_crm_present_but_staff_id_absent_produces_context_not_risk():
    """29. CRM present but service_requests.staff_id absent degrades access checks to context."""
    now = datetime(2026, 6, 1, 10, 0, tzinfo=timezone.utc)
    ds = Dataset()
    ds.available.update({"audit", "assignments", "accounts", "crm"})
    ds.absent_fields.add("service_requests.staff_id")
    ds.accounts["A-S1"] = SysAccount("A-S1", "S1", "core", "active", False)
    ds.events.append(AuditEvent(ts=now, account_ref="A-S1", action="profile_view", customer_ref="C-01", approver_ref=None, row=1))
    ds.reindex()

    focus = Focus("S1", "C-01")
    det = AccessJustification(ds, Rules())
    evs = det.run(focus)
    assert len(evs) == 1
    assert evs[0].polarity == "context"
    assert evs[0].strength == 1


def test_30_supporting_feed_absence_produces_degraded():
    """30. Absence of supporting feeds produces DEGRADED status in coverage."""
    ds = Dataset()
    ds.available.update({"audit", "assignments", "accounts"})
    cov = {r["detector_id"]: r for r in coverage_report(ds)}
    assert cov["access_justification"]["status"] == DEGRADED
    assert "missing supporting feed: service_requests (CRM)" in cov["access_justification"]["explanation"]
    assert cov["bulk_unjustified_browsing"]["status"] == DEGRADED


def test_31_unrelated_feed_degradation_does_not_degrade_detector():
    """31. Feed degradation on portfolio does not degrade auth_channel_change (which does not use it)."""
    ds = Dataset()
    ds.available.update({"audit", "instructions", "accounts"})
    ds.degraded_feeds.add("assignments")
    cov = {r["detector_id"]: r for r in coverage_report(ds)}
    assert cov["auth_channel_change"]["status"] in (READY, CHECK)
    assert "assignments" not in cov["auth_channel_change"]["degraded_feeds"]


def test_32_monetary_precision_is_retained_without_float_rounding():
    """32. Decimal financial amounts retain exact decimal cents precision without floating-point errors."""
    cents1 = _amount("1,500.50")
    assert cents1 == 150050
    assert format_money(cents1, "KES") == "KES 1,500.50"

    cents2 = _amount("725280.00")
    assert cents2 == 72528000
    assert format_money(cents2, "KES") == "KES 725,280"

    cents3 = _amount(4000000)
    assert cents3 == 4000000
    assert format_money(cents3, "KES") == "KES 40,000"


def test_33_mixed_currencies_are_not_combined():
    """33. Mixed currencies are kept separate and not combined into one total."""
    p1 = Payment("P1", datetime.now(timezone.utc), "C1", "atm", 100000, None, "debit", "KES")
    p2 = Payment("P2", datetime.now(timezone.utc), "C1", "online", 5050, None, "debit", "USD")
    formatted = format_money_totals([p1, p2])
    assert "KES 1,000" in formatted
    assert "USD 50.50" in formatted
    assert "KSh" not in formatted


def test_34_every_detector_declared_dependencies_match_runtime():
    """34. Every detector's registered feeds and fields match its provider requirements."""
    from toroka_enterprise.scenarios import (
        AccessJustification,
        AuthChannelChange,
        BulkBrowsing,
        ChangeThenMoney,
        EntitlementIntegrity,
        PayrollBeneficiary,
        PostingIntegrity,
        AccountLifecycle,
    )
    providers = {
        "access_justification": AccessJustification,
        "bulk_unjustified_browsing": BulkBrowsing,
        "auth_channel_change": AuthChannelChange,
        "account_lifecycle": AccountLifecycle,
        "change_then_money": ChangeThenMoney,
        "suspense_posting_integrity": PostingIntegrity,
        "payroll_beneficiary_integrity": PayrollBeneficiary,
        "entitlement_integrity": EntitlementIntegrity,
    }
    dep_map = {d.detector_id: d for d in DETECTOR_DEPENDENCIES}

    for det_id, prov in providers.items():
        dep = dep_map[det_id]
        prov_runtime_feeds = getattr(prov, "requires", frozenset())
        registered_runtime_feeds = {FEED_KEY[f] for f in dep.required_feeds}
        assert prov_runtime_feeds <= registered_runtime_feeds, f"{det_id}: provider requires {prov_runtime_feeds} not in registered {registered_runtime_feeds}"

        prov_req_fields = getattr(prov, "requires_fields", frozenset())
        registered_req_fields = set(dep.required_fields)
        assert prov_req_fields <= registered_req_fields, f"{det_id}: provider requires_fields {prov_req_fields} not in registered {registered_req_fields}"
