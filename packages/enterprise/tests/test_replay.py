import json

from toroka_enterprise.ingest import ingest_dir
from toroka_enterprise.pseudonym import Pseudonymiser
from toroka_enterprise.replay import evaluate, generate
from toroka_enterprise.scan import run_scan


def run(tmp_path, seed=7, gating=True):
    truth = generate(tmp_path, seed=seed)
    ps = Pseudonymiser("k" * 40)
    ds, q = ingest_dir(tmp_path, ps)
    if not gating:
        ds.crm_gap_branches = set()
    scan = run_scan(ds, quality=q)
    return truth, scan, ps, evaluate(scan, truth, ps.vault)


def test_generation_is_deterministic(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    assert generate(a, seed=3) == generate(b, seed=3)
    assert (a / "audit_log.csv").read_text() == (b / "audit_log.csv").read_text()


def test_all_injected_patterns_are_found_with_no_false_review_leads(tmp_path):
    _, _, _, ev = run(tmp_path)
    assert ev["found"] == ev["injected"] == 9 and ev["false_review_leads"] == 0 and ev["conflicting_on_benign"] == 0


def test_data_quality_gating_is_what_prevents_false_leads_from_the_unintegrated_branch(tmp_path):
    _, _, _, ev = run(tmp_path, gating=False)
    assert ev["false_review_leads"] > 0


def test_no_raw_identifiers_reach_the_leads(tmp_path):
    truth, scan, _, _ = run(tmp_path)
    blob = json.dumps([l.to_dict() for l in scan.leads], default=str)
    assert not any(t["staff"] in blob for t in truth) and "C0000" not in blob and "S00" not in blob
