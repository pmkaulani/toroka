import pytest

from toroka_enterprise.audit import AuditLog
from toroka_enterprise.casework import CaseStore, Principal, generate_key


class _Racer:
    """Wraps the sqlite connection and lets a 'concurrent consumer' win just before our UPDATE."""

    def __init__(self, real, rid):
        self._real, self._rid, self.fired = real, rid, False

    def __enter__(self):
        return self._real.__enter__()

    def __exit__(self, *a):
        return self._real.__exit__(*a)

    def __getattr__(self, name):
        return getattr(self._real, name)

    def execute(self, sql, *args):
        if sql.startswith("UPDATE reveals SET status='used'") and not self.fired:
            self.fired = True
            self._real.execute("UPDATE reveals SET status='used' WHERE id=?", (self._rid,))
        return self._real.execute(sql, *args)


def _approved_reveal(tmp_path):
    store = CaseStore(tmp_path / "cases.db", AuditLog(tmp_path / "audit.db"), generate_key())
    system, inv, auth = Principal("sys", "system"), Principal("alice", "investigator"), Principal("bob", "authoriser")
    store.store_vault(system, {"STF-1": "emp-123"})
    cid = store.open_from_lead(system, {"focus": "STF-1", "label": "x", "staff_ref": "STF-1"})
    rid = store.request_reveal(inv, cid, "STF-1", "need to confirm the employee identity")
    store.approve_reveal(auth, rid)
    return store, inv, rid


def test_reveal_cannot_be_used_twice_even_if_another_consumer_wins_the_race(tmp_path):
    store, inv, rid = _approved_reveal(tmp_path)
    store._db = _Racer(store._db, rid)
    with pytest.raises(PermissionError):
        store.reveal(inv, rid)


def test_normal_single_use_still_works(tmp_path):
    store, inv, rid = _approved_reveal(tmp_path)
    assert store.reveal(inv, rid) == "emp-123"
    with pytest.raises(PermissionError):
        store.reveal(inv, rid)
