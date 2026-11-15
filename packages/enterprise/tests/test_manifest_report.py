import re
from html.parser import HTMLParser

import pytest
from toroka_enterprise.ingest import ingest_dir
from toroka_enterprise.manifest import build_manifest, reproduce, result_digest
from toroka_enterprise.profile import INSIDER_PROFILE
from toroka_enterprise.pseudonym import Pseudonymiser
from toroka_enterprise.replay import generate
from toroka_enterprise.report import render_case
from toroka_enterprise.scan import run_scan
from toroka_enterprise.scenarios import Rules
from .helpers import base_feeds, scan as scan_feeds, ts

SECRET = "r" * 40


@pytest.fixture
def run(tmp_path):
    generate(tmp_path, seed=5)
    ps = Pseudonymiser(SECRET)
    ds, q = ingest_dir(tmp_path, ps)
    sc = run_scan(ds, quality=q)
    man = build_manifest(q, mapping_text=None, rules=Rules(), profile=INSIDER_PROFILE, secret=SECRET)
    return tmp_path, sc, man, result_digest(sc)


def repro(data, man, digest, rules=None, secret=SECRET):
    return reproduce(man, digest, data, mapping_text=None, rules=rules or Rules(), profile=INSIDER_PROFILE, secret=secret)


def test_an_unchanged_rerun_reproduces_exactly(run):
    data, _, man, digest = run
    res = repro(data, man, digest)
    assert res["ok"] and res["digest_match"] and res["inputs_match"] and res["original_manifest_id"] == res["current_manifest_id"]


def test_a_changed_source_file_is_named_and_is_not_called_a_failed_reproduction(run):
    data, _, man, digest = run
    f = data / "payments.csv"
    f.write_text(f.read_text().replace("P000001", "P000001x", 1))
    res = repro(data, man, digest)
    assert not res["ok"] and res["changed_files"] == ["payments/payments.csv"] and "different analysis" in res["explanation"]


def test_changed_thresholds_or_key_are_reported_as_configuration_differences(run):
    data, _, man, digest = run
    assert repro(data, man, digest, rules=Rules(bulk_unjustified_threshold=99))["config_differences"] == ["rules"]
    other_key = repro(data, man, digest, secret="q" * 40)
    assert "pseudonym_key_fingerprint" in other_key["config_differences"] and not other_key["ok"]
    assert SECRET not in str(man) and man["pseudonym_key_fingerprint"] != "r" * 12


def test_manifest_id_depends_on_inputs_and_config_but_not_on_when_it_ran(run, tmp_path):
    data, _, man, _ = run
    ps = Pseudonymiser(SECRET)
    _, q = ingest_dir(data, ps)
    again = build_manifest(q, mapping_text=None, rules=Rules(), profile=INSIDER_PROFILE, secret=SECRET)
    assert again["manifest_id"] == man["manifest_id"]
    assert build_manifest(q, mapping_text="x", rules=Rules(), profile=INSIDER_PROFILE, secret=SECRET)["manifest_id"] != man["manifest_id"]


def test_result_digest_is_sensitive_to_what_the_scan_concludes(run):
    data, sc, _, digest = run
    ps = Pseudonymiser(SECRET)
    ds, q = ingest_dir(data, ps)
    assert result_digest(run_scan(ds, Rules(bulk_unjustified_threshold=99), q)) != digest
    assert result_digest(run_scan(ds, Rules(), q)) == digest


class _Strict(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags, self.scripts = [], 0

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.scripts += tag == "script"


def test_report_is_well_formed_pseudonymised_and_carries_provenance(run):
    data, sc, man, _ = run
    lead = max(sc.leads, key=lambda l: len(l.result.risk_evidence)).to_dict()
    page = render_case(lead, man)
    p = _Strict(); p.feed(page)
    assert "svg" in p.tags and p.scripts == 0
    assert "not a finding" in page and man["manifest_id"] in page and "Alternative explanations" in page and "What could not be checked" in page
    assert all(e["summary"].split(".")[0][:40] in page.replace("&amp;", "&") for e in lead["risk_evidence"][:2])
    assert not re.search(r"\bS00\d\d\b|\bC0\d{5}\b", page)             # no raw staff or customer ids
    assert page.count("<tr>") >= len(lead["risk_evidence"]) + 2


def test_hostile_values_from_bank_data_cannot_inject_markup(tmp_path):
    f = base_feeds()
    f["audit_log"] = [{"ts": ts(), "account_id": "A-S2", "action": "profile_view", "customer_id": "C-X"},
                      {"ts": ts(minutes=3), "account_id": "A-S2", "action": "contact_change", "customer_id": "C-X"}]
    f["instructions"] = [{"instruction_id": "<script>alert(1)</script>", "customer_id": "C-X", "kind": "contact_change", "received_at": ts(hours=-2)}]
    _, _, sc, _ = scan_feeds(tmp_path, f)
    lead = next(l for l in sc.leads if any("<script>" in r for e in l.result.supporting_evidence for r in e.metadata["record_refs"])).to_dict()
    page = render_case(lead, None)
    assert "<script>" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page
