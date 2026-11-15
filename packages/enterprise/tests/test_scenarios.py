from toroka_enterprise.scenarios import Rules, AuthChannelChange, Focus, PostingIntegrity
from .helpers import base_feeds, labels, scan, ts


def otp_feeds(with_instruction=False, with_ticket=False, payments=True):
    f = base_feeds()
    f["audit_log"] = [{"ts": ts(), "account_id": "A-S2", "action": "profile_view", "customer_id": "C-X"},
                      {"ts": ts(minutes=3), "account_id": "A-S2", "action": "contact_change", "customer_id": "C-X"},
                      {"ts": ts(minutes=9), "account_id": "A-S2", "action": "card_issue", "customer_id": "C-X"}]
    if with_instruction:
        f["instructions"] = [{"instruction_id": "I1", "customer_id": "C-X", "kind": "contact_change", "received_at": ts(hours=-2)},
                              {"instruction_id": "I2", "customer_id": "C-X", "kind": "card_issue", "received_at": ts(hours=-2)}]
    if with_ticket:
        f["service_requests"].append({"request_id": "R-T", "customer_id": "C-X", "staff_id": "S2", "opened_at": ts(hours=-3), "closed_at": "", "kind": "service"})
    if payments:
        f["payments"] = [{"payment_id": f"P{d}", "ts": ts(days=d), "customer_id": "C-X", "channel": "atm", "amount": "40000"} for d in (1, 2, 4)]
    return f


def test_unexplained_sequence_is_a_priority_review(tmp_path):
    _, _, s, _ = scan(tmp_path, otp_feeds())
    assert list(labels(s).values()) == ["PRIORITY REVIEW"]
    lead = s.leads[0]
    assert {e.source_group for e in lead.result.risk_evidence} >= {"core_banking_audit", "customer_instruction", "payments"}
    assert all(e.metadata["record_refs"] for e in lead.result.risk_evidence)           # provenance on every item
    assert "not a finding of misconduct" in lead.result.limitations[0]


def test_same_events_with_ticket_and_instruction_are_not_surfaced(tmp_path):
    _, _, s, _ = scan(tmp_path, otp_feeds(with_instruction=True, with_ticket=True))
    assert s.leads == [] and s.not_surfaced.get("NO ANOMALY FOUND", 0) == 1


def test_a_single_rule_hit_never_reaches_priority_or_high_confidence(tmp_path):
    f = otp_feeds(payments=False)
    f["audit_log"] = f["audit_log"][:2]                                                  # contact change only, no card, no money
    f["service_requests"].append({"request_id": "R-T", "customer_id": "C-X", "staff_id": "S2", "opened_at": ts(hours=-3), "closed_at": "", "kind": "service"})
    _, _, s, _ = scan(tmp_path, f)
    assert len(s.leads) == 1 and s.leads[0].label != "PRIORITY REVIEW" and s.leads[0].result.confidence != "high"


def test_crm_gap_downgrades_access_findings_to_context(tmp_path):
    f = otp_feeds()
    del f["service_requests"]
    _, q, s, _ = scan(tmp_path, f)
    lead = s.leads[0]
    assert all(e.source_group != "core_banking_audit" for e in lead.result.risk_evidence)
    assert any(e.source_group == "crm" for e in lead.result.context_evidence)


def test_missing_postings_feed_is_reported_as_could_not_check(tmp_path):
    f = base_feeds()
    f["system_accounts"].append({"account_id": "A2-S1", "staff_id": "S1", "system": "core_banking", "status": "active", "is_privileged": "false"})
    f["audit_log"] = [{"ts": ts(), "account_id": "A-S1", "action": "profile_view", "customer_id": "C-OWN"}]
    del f["postings"]
    ds, _, s, _ = scan(tmp_path, f)
    assert "postings" not in ds.available and len(s.leads) == 1       # duplicate profile still surfaces
    unavailable = set(s.leads[0].result.unavailable_checks)
    assert {"suspense_posting_integrity", "payroll_beneficiary_integrity"} <= unavailable    # reported, not silently skipped


def test_unapproved_and_self_approved_suspense_postings_are_flagged_and_approved_ones_are_not(tmp_path):
    f = base_feeds()
    f["audit_log"] = [{"ts": ts(), "account_id": "A-S1", "action": "profile_view", "customer_id": "C-OWN"}]
    f["postings"] = [{"posting_id": "L1", "ts": ts(), "ledger": "SUSPENSE", "counter_party": "C-X", "amount": "90000", "entered_by_account": "A-S1", "approved_by_account": "A-S1", "manual": "true", "narrative": "OTHER"},
                     {"posting_id": "L2", "ts": ts(hours=1), "ledger": "SUSPENSE", "counter_party": "C-Y", "amount": "50000", "entered_by_account": "A-S1", "approved_by_account": "", "manual": "true", "narrative": "OTHER"},
                     {"posting_id": "L3", "ts": ts(hours=2), "ledger": "SUSPENSE", "counter_party": "C-OWN", "amount": "5000", "entered_by_account": "A-S2", "approved_by_account": "A-S1", "manual": "true", "narrative": "DISPUTE_REFUND"}]
    f["payments"] = [{"payment_id": "P1", "ts": ts(days=1), "customer_id": "C-X", "channel": "atm", "amount": "85000"}]
    _, _, s, ps = scan(tmp_path, f)
    flagged = {ps.vault[l.focus.staff_ref] for l in s.leads}
    assert flagged == {"S1"}                                  # S2's independently approved posting is not surfaced


def test_payroll_postings_to_non_employees_are_flagged_but_roster_accounts_are_not(tmp_path):
    f = base_feeds()
    f["audit_log"] = [{"ts": ts(), "account_id": "A-S1", "action": "profile_view", "customer_id": "C-OWN"}]
    f["postings"] = [{"posting_id": "L1", "ts": ts(), "ledger": "PAYROLL", "counter_party": "EXT-1", "amount": "300000", "entered_by_account": "A-S1", "approved_by_account": "A-S2", "manual": "true", "narrative": "SALARY"},
                     {"posting_id": "L2", "ts": ts(), "ledger": "PAYROLL", "counter_party": "SAL-S2", "amount": "5000", "entered_by_account": "A-S2", "approved_by_account": "A-S1", "manual": "true", "narrative": "SALARY"}]
    _, _, s, ps = scan(tmp_path, f)
    assert {ps.vault[l.focus.staff_ref] for l in s.leads} == {"S1"}


def test_entitlement_duplicate_leaver_and_admin_context(tmp_path):
    f = base_feeds(extra_staff=[{"staff_id": "S3", "status": "terminated", "role": "teller", "branch": "BR01", "end_date": ts(days=-10)},
                                {"staff_id": "S4", "status": "active", "role": "ops", "branch": "BR01"}])
    f["system_accounts"] += [{"account_id": "A2-S1", "staff_id": "S1", "system": "core_banking", "status": "active", "is_privileged": "false"},
                             {"account_id": "A2-S4", "staff_id": "S4", "system": "core_banking", "status": "active", "is_privileged": "true"}]
    f["audit_log"] = [{"ts": ts(), "account_id": "A-S1", "action": "profile_view", "customer_id": "C-OWN"},
                      {"ts": ts(), "account_id": "A-S3", "action": "profile_view", "customer_id": "C-X"},
                      {"ts": ts(), "account_id": "A-S4", "action": "profile_view", "customer_id": "C-X"}]
    _, _, s, ps = scan(tmp_path, f)
    assert {ps.vault[l.focus.staff_ref] for l in s.leads} == {"S1", "S3"}   # duplicate profile and leaver activity; S4's admin pair is context only


def test_bulk_browsing_needs_the_threshold_and_ignores_portfolio_and_ticketed_views(tmp_path):
    f = base_feeds()
    f["customers"] += [{"customer_id": f"C{i}", "status": "active"} for i in range(20)]
    f["audit_log"] = [{"ts": ts(hours=i), "account_id": "A-S2", "action": "profile_view", "customer_id": f"C{i}"} for i in range(20)]
    _, _, s, _ = scan(tmp_path, f)
    assert len(s.leads) == 1 and s.leads[0].label == "REVIEW"
    f["audit_log"] = f["audit_log"][:10]
    assert scan(tmp_path, f)[2].leads == []
    assert Rules().bulk_unjustified_threshold == 15


def test_entitlement_with_empty_audit_events_does_not_raise():
    from toroka_enterprise.schema import Dataset, Staff, SysAccount
    from toroka_enterprise.scenarios import EntitlementIntegrity, Focus, Rules

    ds = Dataset()
    ds.staff['S1'] = Staff('S1', 'active', 'Manager', 'BR01')
    ds.accounts['A1'] = SysAccount('A1', 'S1', 'CORE', 'active', False)
    ds.accounts['A2'] = SysAccount('A2', 'S1', 'CORE', 'active', False)
    ds.reindex()

    p = EntitlementIntegrity(ds, Rules())
    evs = p.run(Focus('S1'))
    assert len(evs) == 1
    assert evs[0].polarity == 'risk'



def test_instruction_received_after_operation_does_not_retroactively_authorise_it(tmp_path):
    f = base_feeds()
    f["audit_log"] = [{"ts": ts(), "account_id": "A-S2", "action": "contact_change", "customer_id": "C-X"}]
    f["instructions"] = [{"instruction_id": "I-LATE", "customer_id": "C-X", "kind": "contact_change",
                          "received_at": ts(hours=1), "recorded_at": ts(hours=2)}]
    ds, _, _, ps = scan(tmp_path, f)
    evs = AuthChannelChange(ds, Rules()).run(Focus(ps.ref("stf", "S2"), ps.ref("cus", "C-X")))
    assert any(e.polarity == "risk" for e in evs)


def test_unresolved_approver_is_context_not_independent_approval(tmp_path):
    f = base_feeds()
    f["postings"] = [{"posting_id": "L-UNKNOWN", "ts": ts(), "ledger": "SUSPENSE", "counter_party": "C-X",
                      "amount": "10000", "entered_by_account": "A-S1", "approved_by_account": "A-NOT-IN-ACCOUNT-FEED",
                      "manual": "true", "narrative": "OTHER"}]
    ds, _, _, ps = scan(tmp_path, f)
    evs = PostingIntegrity(ds, Rules()).run(Focus(ps.ref("stf", "S1")))
    assert evs and all(e.polarity == "context" for e in evs)
    assert any("could not be mapped" in e.summary for e in evs)
