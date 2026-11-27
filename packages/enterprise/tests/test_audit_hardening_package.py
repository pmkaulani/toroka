"""Regression tests for enterprise package audit hardening items 6 & 8."""
from __future__ import annotations

import concurrent.futures

import pytest

from toroka_enterprise.audit import AuditLog
from toroka_enterprise.casework import CaseStore, Principal, generate_key
from toroka_enterprise.pseudonym import Pseudonymiser


def test_audit_log_optional_hmac_key_and_key_length(tmp_path):
    with pytest.raises(ValueError, match="at least 32 bytes"):
        AuditLog(tmp_path / "bad.db", hmac_key=b"short")

    key = b"enterprise-hmac-audit-log-key-32b"
    log = AuditLog(tmp_path / "hmac.db", hmac_key=key)
    log.append("alice", "investigator", "case.view", "1")
    log.append("alice", "investigator", "case.note", "1", {"note": "checked"})
    assert log.verify().ok is True

    # Verifying the HMAC-signed log with a different key or unkeyed verifier must fail
    wrong_verifier = AuditLog(tmp_path / "hmac.db", hmac_key=b"different-hmac-audit-log-key-32b!")
    assert wrong_verifier.verify().ok is False
    unkeyed_verifier = AuditLog(tmp_path / "hmac.db")
    assert unkeyed_verifier.verify().ok is False


def test_pseudonymiser_case_normalization_preserves_display_value():
    ps = Pseudonymiser("k" * 40)
    upper = ps.ref("stf", "S0042")
    lower = ps.ref("stf", " s0042 ")
    assert upper == lower
    assert ps.vault[upper] == "S0042"


def test_case_store_vault_prevents_silent_overwrite(tmp_path):
    store = CaseStore(tmp_path / "c.db", AuditLog(tmp_path / "a.db"), generate_key())
    sys_p = Principal("svc", "system")

    store.store_vault(sys_p, {"STF-1": "EMP-0042"})
    # Idempotent re-store with identical identity (any case) succeeds
    store.store_vault(sys_p, {"STF-1": "emp-0042"})

    # Attempting to overwrite pseudonym with a different identity raises ValueError
    with pytest.raises(ValueError, match="vault collision"):
        store.store_vault(sys_p, {"STF-1": "EMP-9999"})


def test_case_store_concurrent_access_thread_safe(tmp_path):
    audit = AuditLog(tmp_path / "a.db")
    store = CaseStore(tmp_path / "c.db", audit, generate_key())
    sys_p = Principal("svc", "system")
    inv_p = Principal("alice", "investigator")

    cid = store.open_from_lead(sys_p, {"focus": "STF-T1", "label": "HIGH", "staff_ref": "STF-T1"})

    def worker(i: int):
        store.add_note(inv_p, cid, f"Concurrent investigation note #{i}")
        return store.view_case(inv_p, cid)["id"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(worker, range(24)))

    assert all(r == cid for r in results)
    assert len(store.view_case(inv_p, cid)["notes"]) == 24
    assert audit.verify().ok is True
