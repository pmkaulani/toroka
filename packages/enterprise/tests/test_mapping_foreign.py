import re



import pytest

from toroka_enterprise.coverage import coverage_report

from toroka_enterprise.discover import suggest_mapping

from toroka_enterprise.foreign import STYLES, export

from toroka_enterprise.ingest import ingest_dir

from toroka_enterprise.mapping import MappingError, load_mapping, read_mapped

from toroka_enterprise.pseudonym import Pseudonymiser

from toroka_enterprise.replay import evaluate, generate

from toroka_enterprise.scan import run_scan



SECRET = "m" * 40





@pytest.fixture(scope="module")

def canon(tmp_path_factory):

    d = tmp_path_factory.mktemp("canon")

    truth = generate(d, seed=11)

    return d, truth





def run(data_dir, mapping_text=None):

    ps = Pseudonymiser(SECRET)

    mp = load_mapping(mapping_text) if mapping_text else None

    ds, q = ingest_dir(data_dir, ps, mp)

    return ds, q, run_scan(ds, quality=q), ps





def leadset(scan):

    return {(l.label, l.focus.label()) for l in scan.leads}





@pytest.mark.parametrize("style", ["A", "B"])

def test_foreign_exports_give_identical_findings_to_the_canonical_run(canon, tmp_path, style):

    d, truth = canon

    toml = export(d, tmp_path, style)

    _, _, base, _ = run(d)

    ds, q, foreign, ps = run(tmp_path, toml)

    assert leadset(foreign) == leadset(base) and foreign.examined == base.examined

    ev = evaluate(foreign, truth, ps.vault)

    assert ev["found"] == ev["injected"] == 9 and ev["false_review_leads"] == 0

    assert not q.unmapped_values and not q.ts_format_failures and not q.absent_fields

    assert all(r["status"] in ("ready", "degraded") for r in coverage_report(ds))





def test_unmapped_codes_are_counted_and_the_detector_is_flagged_not_silently_blind(canon, tmp_path):

    d, truth = canon

    toml = export(d, tmp_path, "A").replace('"CUS-MOB-CHG" = "contact_change"\n', "")

    ds, q, scan, ps = run(tmp_path, toml)

    assert "action=CUS-MOB-CHG" in q.unmapped_values["audit_log"]

    assert any("no mapping" in n and "CUS-MOB-CHG" in n for n in q.notes)

    cov = {r["detector"]: r for r in coverage_report(ds)}

    assert cov["auth_channel_change"]["status"] == "check" and "contact_change" in cov["auth_channel_change"]["reason"]

    assert evaluate(scan, truth, ps.vault)["found"] < 9            # and the gap is visible, not hidden





def test_absent_optional_fields_make_dependent_checks_stand_down_instead_of_inventing_risk(canon, tmp_path):

    d, truth = canon

    toml = export(d, tmp_path, "A")

    toml = re.sub(r'approver_account_id = "AUTH_BY"\n', "", toml)

    toml = re.sub(r'approved_by_account = "CHECKER"\n', "", toml)

    toml = re.sub(r'salary_account = "PAYROLL_ACCT"\n', "", toml)

    ds, q, scan, ps = run(tmp_path, toml)

    assert {"audit_log.approver_account_id", "postings.approved_by_account", "hr_roster.salary_account"} <= ds.absent_fields

    risk = [e.summary for l in scan.leads for e in l.result.risk_evidence]

    assert not any("No approver is recorded" in s or "unapproved or self-approved" in s or "match no employee" in s for s in risk)

    cov = {r["detector"]: r["status"] for r in coverage_report(ds)}

    assert cov["suspense_posting_integrity"] == "blind" and cov["payroll_beneficiary_integrity"] == "blind" and cov["account_lifecycle"] == "degraded"

    assert evaluate(scan, truth, ps.vault)["false_review_leads"] == 0





def test_mapping_errors_name_the_problem(canon, tmp_path):

    d, _ = canon

    toml = export(d, tmp_path, "A")

    with pytest.raises(MappingError, match="not valid TOML"):

        load_mapping("[feeds.audit_log")

    with pytest.raises(MappingError, match="unknown feed"):

        load_mapping('[feeds.nonsense]\nfile = "x"\n[feeds.nonsense.columns]\n')

    with pytest.raises(MappingError, match="required canonical column"):

        load_mapping(toml.replace('account_id = "USR_ID"\n', ""))

    with pytest.raises(MappingError, match="unknown canonical column"):

        load_mapping(toml.replace('ts = "TRAN_DATE_TIME"', 'tz = "TRAN_DATE_TIME"'))

    with pytest.raises(MappingError, match="not in the file"):

        ingest_dir(tmp_path, Pseudonymiser(SECRET), load_mapping(toml.replace('"USR_ID"', '"NO_SUCH_COLUMN"')))





def test_a_wrong_timestamp_format_rejects_rows_with_a_clear_note(canon, tmp_path):

    d, _ = canon

    toml = export(d, tmp_path, "A").replace('timestamp_format = "%d/%m/%Y %H:%M:%S"', 'timestamp_format = "%Y/%m/%d %H:%M"')

    _, q, _, _ = run(tmp_path, toml)

    assert q.ts_format_failures["audit_log"] > 0 and any("did not match the declared format" in n for n in q.notes)





@pytest.mark.parametrize("style,file", [("A", "AUDIT_TRAIL_2026Q2.txt"), ("B", "audit_log_export.tsv")])

def test_suggest_mapping_drafts_a_usable_audit_mapping_from_an_unfamiliar_export(canon, tmp_path, style, file):

    d, _ = canon

    export(d, tmp_path, style)

    text, report = suggest_mapping(tmp_path / file, "audit_log")

    want = STYLES[style]["cols"]["audit_log"]

    got = {c: report["matched"].get(c, {}).get("source") for c in want}

    right = sum(got[c] == want[c] for c in want)

    assert right >= 4, (got, want)                                    # a draft to confirm, not an oracle

    import csv as _csv

    present = {r["action"] for r in _csv.DictReader(open(d / "audit_log.csv"))}           # only codes that really occur in the data

    codes = STYLES[style]["codes"][("audit_log", "action")]

    assert present >= {"profile_view", "contact_change", "card_issue", "beneficiary_add", "account_reactivate"}

    for canon_action, src in codes.items():

        if canon_action in present:

            assert f'"{src}" = "{canon_action}"' in text, (src, canon_action)

    assert "SUGGESTION" in text and report["timestamp_format"] == STYLES[style]["ts"]





def test_suggest_mapping_handles_single_column_file(tmp_path):

    f = tmp_path / "single_col.txt"

    f.write_text("account_id\nA1\nA2\n")

    text, report = suggest_mapping(f, "system_accounts")

    assert report["delimiter"] == ","

    assert "account_id" in report["matched"]





def test_mapping_handles_directory_with_brackets(tmp_path):

    bracket_dir = tmp_path / "test[1]"

    bracket_dir.mkdir()

    (bracket_dir / "audit_2026.csv").write_text("when,who,what,whom\n2026-05-01 10:00:00,A1,view,C1\n")

    toml_text = '''[feeds.audit_log]

file = "audit_*.csv"

delimiter = ","

columns = {ts = "when", account_id = "who", action = "what", customer_id = "whom"}

values = {action = {view = "profile_view"}}

'''

    mp = load_mapping(toml_text)

    from toroka_enterprise.ingest import DataQuality

    q = DataQuality()

    res = read_mapped(bracket_dir, "audit_log", mp.feeds["audit_log"], q)

    assert res is not None and len(res) == 1

    assert res[0][1]["account_id"] == "A1"

