import pytest

from toroka_enterprise.ingest import IngestError, ingest_dir

from toroka_enterprise.pseudonym import Pseudonymiser

from .helpers import base_feeds, scan, ts, write





def test_pseudonyms_are_deterministic_kind_specific_and_keyed():

    a, b = Pseudonymiser("a" * 40), Pseudonymiser("b" * 40)

    assert a.ref("stf", "S1") == a.ref("stf", "S1") != a.ref("cus", "S1") != b.ref("stf", "S1")
    assert a.ref("bank_account", "S1") != a.ref("cus", "S1")
    assert len(a.ref("bank_account", "S1").split("-", 1)[1]) == 32
    assert a.ref("bank_account", "S1") == a.ref("bank_account", "S1")

    assert a.ref("stf", " ") is None and a.vault[a.ref("stf", "S1")] == "S1"

    with pytest.raises(ValueError):

        Pseudonymiser("short")





def test_missing_required_feed_and_missing_columns_fail_loudly(tmp_path):

    feeds = base_feeds()

    del feeds["audit_log"]

    write(tmp_path, feeds)

    with pytest.raises(IngestError, match="audit_log"):

        ingest_dir(tmp_path, Pseudonymiser("s" * 40))

    (tmp_path / "audit_log.csv").write_text("ts,account_id\n")

    with pytest.raises(IngestError, match="missing required columns"):

        ingest_dir(tmp_path, Pseudonymiser("s" * 40))





def test_bad_rows_are_rejected_with_a_reason_and_naive_timestamps_read_as_eat(tmp_path):

    f = base_feeds()

    f["audit_log"] = [{"ts": "2026-05-04 09:15:00", "account_id": "A-S1", "action": "profile_view", "customer_id": "C-OWN"},

                      {"ts": "not-a-date", "account_id": "A-S1", "action": "profile_view", "customer_id": "C-OWN"},

                      {"ts": ts(), "account_id": "", "action": "profile_view", "customer_id": "C-OWN"}]

    ds, q, _, _ = scan(tmp_path, f)

    assert len(ds.events) == 1 and q.rows_rejected["audit_log"] == 2

    assert q.naive_timestamps_assumed_eat == 1 and ds.events[0].ts.hour == 6   # 09:15 EAT = 06:15 UTC

    assert any("line" in s for s in q.rejected_samples)





def test_missing_crm_feed_marks_every_branch_as_a_gap_and_unmapped_accounts_are_reported(tmp_path):

    f = base_feeds(with_crm=False)

    f["audit_log"] = [{"ts": ts(), "account_id": "A-GHOST", "action": "profile_view", "customer_id": "C-X"}]

    ds, q, _, _ = scan(tmp_path, f)

    assert ds.crm_gap_branches == {"BR01"} and q.events_unmapped_accounts == 1

    assert any("No usable CRM feed" in n for n in q.notes)





def test_decimal_and_comma_amounts_parsed_correctly(tmp_path):

    from toroka_enterprise.ingest import ingest_dir

    from toroka_enterprise.pseudonym import Pseudonymiser



    (tmp_path / "audit_log.csv").write_text("ts,account_id,action,customer_id,approver_account_id\n2026-05-01 10:00:00,A1,profile_view,C1,\n")

    (tmp_path / "system_accounts.csv").write_text("account_id,staff_id,system,status,is_privileged\nA1,S1,CORE,active,false\n")

    (tmp_path / "payments.csv").write_text('payment_id,ts,customer_id,channel,amount,beneficiary\nPMT1,2026-05-01 11:00:00,C1,online,"1,500.50",B1\n')

    (tmp_path / "postings.csv").write_text("posting_id,ts,ledger,counter_party,amount,entered_by_account,approved_by_account,manual,narrative\nP1,2026-05-01 12:00:00,SUSPENSE,C1,725280.00,A1,,true,DISPUTE\n")



    ds, q = ingest_dir(tmp_path, Pseudonymiser("x" * 32))

    assert q.rows_rejected == {}

    assert ds.payments[0].amount == 1500

    assert ds.postings[0].amount == 725280




def test_rejected_rows_and_unmapped_codes_degrade_feed_health(tmp_path):
    f = base_feeds()
    f["audit_log"] = [
        {"ts": ts(hours=i), "account_id": "A-S2", "action": "profile_view", "customer_id": "C-X"}
        for i in range(18)
    ] + [
        {"ts": "not-a-date", "account_id": "A-S2", "action": "profile_view", "customer_id": "C-X"}
        for _ in range(2)
    ]
    ds, q, _, _ = scan(tmp_path, f)
    assert q.feed_health["audit_log"]["status"] == "degraded"
    assert q.feed_health["audit_log"]["rejection_rate"] == 0.1
    assert "audit" in ds.degraded_feeds
    from toroka_enterprise.coverage import coverage_report
    coverage = {row["detector"]: row for row in coverage_report(ds)}
    assert coverage["access_justification"]["status"] == "degraded"
