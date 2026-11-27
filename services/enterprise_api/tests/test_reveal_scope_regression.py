"""An identity reveal may only be requested for a pseudonym that belongs to the case (review 2026-11)."""
import pytest

from toroka_enterprise_api.auth import EnterprisePrincipal

INST = "toroka-default-installation"
ALICE = EnterprisePrincipal(subject="investigator.alice", roles=frozenset({"investigator"}), issuer="test-idp")


def _case(svc, focus, snapshot=None):
    return svc.create_case(ALICE, installation_id=INST, label="x", focus=focus, snapshot=snapshot or {},
                           manifest_id="m", assign_to_subject="investigator.alice")


def test_unrelated_pseudonym_is_rejected_and_audited(test_case_service, test_reveal_service):
    case = _case(test_case_service, "STF-IN-CASE")
    with pytest.raises(ValueError, match="does not appear"):
        test_reveal_service.request_reveal(ALICE, case_id=case.id, pseudonym="STF-SOMEONE-ELSE",
                                           reason="Looks interesting to me, please reveal.")
    from toroka_enterprise_api.persistence.models import AuditRecord
    rows = test_reveal_service.db.query(AuditRecord).filter(AuditRecord.action == "reveal_denied_out_of_scope").all()
    assert len(rows) == 1


def test_focus_and_composite_focus_parts_are_allowed(test_case_service, test_reveal_service):
    case = _case(test_case_service, "STF-A/CUS-B")
    for pseudo in ("STF-A", "CUS-B", "STF-A/CUS-B"):
        test_reveal_service.request_reveal(ALICE, case_id=case.id, pseudonym=pseudo,
                                           reason="Confirm identity before referral.")


def test_evidence_subject_is_allowed(test_case_service, test_reveal_service):
    snap = {"result": {"risk_evidence": [{"subject": "ACC-777"}], "supporting_evidence": [{"subject": "BEN-9"}]}}
    case = _case(test_case_service, "STF-FOCUS", snap)
    for pseudo in ("ACC-777", "BEN-9"):
        test_reveal_service.request_reveal(ALICE, case_id=case.id, pseudonym=pseudo,
                                           reason="Confirm identity before referral.")
