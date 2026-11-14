import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from toroka_enterprise.audit import AuditLog
from toroka_enterprise.casework import CaseStore, Principal, generate_key

LEAD = {"focus": "STF-aaa/CUS-bbb", "label": "PRIORITY REVIEW", "staff_ref": "STF-aaa", "customer_ref": "CUS-bbb"}
SYS, INV, AUTH, AUD = Principal("svc", "system"), Principal("inv1", "investigator"), Principal("auth1", "authoriser"), Principal("aud1", "auditor")


class Clock:
    def __init__(self):
        self.now = datetime(2026, 6, 1, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


@pytest.fixture
def store(tmp_path):
    clock = Clock()
    audit = AuditLog(tmp_path / "a.db", clock)
    s = CaseStore(tmp_path / "c.db", audit, generate_key(), clock)
    s.store_vault(SYS, {"STF-aaa": "S0042"})
    s._test_clock = clock
    return s


def test_audit_chain_verifies_and_blocks_update_and_delete(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    for i in range(3):
        log.append("u", "investigator", "case.view", str(i))
    assert log.verify().ok and log.verify().checked == 3
    db = sqlite3.connect(tmp_path / "a.db")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("UPDATE audit SET actor='x' WHERE seq=2")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("DELETE FROM audit WHERE seq=2")


def test_verify_detects_tampering_even_when_triggers_are_bypassed(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    for i in range(4):
        log.append("u", "investigator", "case.view", str(i))
    head = log.verify().head_hash
    db = sqlite3.connect(tmp_path / "a.db")
    db.execute("DROP TRIGGER audit_no_update"); db.execute("DROP TRIGGER audit_no_delete")
    db.execute("UPDATE audit SET actor='someone-else' WHERE seq=2"); db.commit()
    res = log.verify()
    assert not res.ok and any("entry 2" in p for p in res.problems)
    db.execute("DELETE FROM audit WHERE seq=3"); db.commit()
    assert any("gap" in p for p in log.verify().problems) and head != ""


def test_roles_are_enforced_and_denials_are_audited(store):
    cid = store.open_from_lead(SYS, LEAD)
    with pytest.raises(PermissionError):
        store.add_note(AUTH, cid, "nope")
    with pytest.raises(PermissionError):
        store.approve_reveal(INV, 1)
    assert store.list_cases(AUD)[0]["id"] == cid
    assert any(e["action"] == "authz.denied" for e in store.audit.entries())


def test_reveal_needs_a_reason_a_different_authoriser_and_is_single_use(store):
    cid = store.open_from_lead(SYS, LEAD)
    with pytest.raises(ValueError):
        store.request_reveal(INV, cid, "STF-aaa", "too short")
    with pytest.raises(ValueError):
        store.request_reveal(INV, cid, "STF-zzz", "a long enough written reason here")
    rid = store.request_reveal(INV, cid, "STF-aaa", "Customer complaint requires confirming the staff member")
    with pytest.raises(PermissionError):
        store.reveal(INV, rid)                                               # not yet approved
    same_person = Principal("inv1", "authoriser")                            # same user id wearing the authoriser role
    with pytest.raises(PermissionError, match="requested it"):
        store.approve_reveal(same_person, rid)
    store.approve_reveal(AUTH, rid)
    assert store.reveal(INV, rid) == "S0042"
    with pytest.raises(PermissionError):
        store.reveal(INV, rid)                                               # single use
    actions = [e["action"] for e in store.audit.entries()]
    assert actions.count("reveal.use") == 1 and "reveal.approve" in actions


def test_an_approved_reveal_expires_after_24_hours(store):
    cid = store.open_from_lead(SYS, LEAD)
    rid = store.request_reveal(INV, cid, "STF-aaa", "Customer complaint requires confirming the staff member")
    store.approve_reveal(AUTH, rid)
    store._test_clock.now += timedelta(hours=25)
    with pytest.raises(PermissionError, match="expired"):
        store.reveal(INV, rid)


def test_closing_requires_alternatives_and_a_valid_disposition_and_duplicates_are_merged(store):
    cid = store.open_from_lead(SYS, LEAD)
    assert store.open_from_lead(SYS, LEAD) == cid
    with pytest.raises(ValueError):
        store.close_case(INV, cid, "substantiated_referral", "enough note here", "short")
    with pytest.raises(ValueError):
        store.close_case(INV, cid, "guilty", "enough note here", "considered a service ticket and a data gap in CRM")
    store.close_case(INV, cid, "not_substantiated", "Ticket found in CRM", "Considered a missing CRM link and a legitimate walk-in request")
    assert store.view_case(AUD, cid)["status"] == "closed" and store.audit.verify().ok


def _bypass(path):
    db = sqlite3.connect(path)
    db.execute("DROP TRIGGER audit_no_update"); db.execute("DROP TRIGGER audit_no_delete")
    return db


def test_a_forged_entry_with_a_valid_self_hash_still_breaks_the_chain(tmp_path):
    from toroka_enterprise.audit import _digest
    log = AuditLog(tmp_path / "a.db")
    for i in range(4):
        log.append("u", "investigator", "case.view", str(i))
    db = _bypass(tmp_path / "a.db")
    seq, ts, role, action, target, detail, prev = db.execute("SELECT seq, ts, role, action, target, detail, prev_hash FROM audit WHERE seq=2").fetchone()
    db.execute("UPDATE audit SET actor='forged', hash=? WHERE seq=2", (_digest(prev, seq, ts, "forged", role, action, target, detail),)); db.commit()
    problems = log.verify().problems
    assert any("entry 3" in p and "link" in p for p in problems)


def test_deleting_the_tail_is_only_detectable_against_an_externally_anchored_head_hash(tmp_path):
    log = AuditLog(tmp_path / "a.db")
    for i in range(4):
        log.append("u", "investigator", "case.view", str(i))
    anchored = log.verify().head_hash
    db = _bypass(tmp_path / "a.db")
    db.execute("DELETE FROM audit WHERE seq=4"); db.commit()
    res = log.verify()
    assert res.ok                                  # internally consistent: the chain alone cannot see a deleted tail
    assert res.head_hash != anchored               # ...but the externally stored head hash exposes it


def test_reveal_rejects_substring_pseudonym(store):
    lead_stf10 = {'focus': 'STF-10', 'label': 'REVIEW', 'staff_ref': 'STF-10', 'customer_ref': None}
    cid = store.open_from_lead(SYS, lead_stf10)
    with pytest.raises(ValueError, match='pseudonym does not appear'):
        store.request_reveal(INV, cid, 'STF-1', 'Reason with more than 20 chars here')
