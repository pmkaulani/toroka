"""Unit and domain tests for Phase 9: Fraud DNA & Institutional Memory Engine."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import pytest

from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise.intelligence.memory import (
    CaseFingerprint,
    ControlWeaknessType,
    InstitutionalPattern,
    PatternStatus,
    PatternValidationPolicy,
    approve_pattern,
    build_case_fingerprint,
    compare_fingerprints,
    detect_control_weaknesses,
    discover_candidate_patterns,
    evaluate_pattern,
    match_case_against_patterns,
    reinstate_pattern,
    reject_pattern,
    retire_pattern,
    retrieve_similar_historical_cases,
    suspend_pattern,
)


def _dt(seconds_offset: int = 0) -> datetime:
    base = datetime(2026, 11, 16, 10, 0, 0, tzinfo=timezone.utc)
    return base + timedelta(seconds=seconds_offset)


# =============================================================================
# 1. Fingerprint Determinism & Zero-PII Boundary
# =============================================================================


def test_fingerprint_determinism_and_event_ordering():
    """Events supplied in arbitrary order must yield identical, deterministic fingerprints."""
    e1 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-001",
        event_type="customer_record_access",
        event_time=_dt(0),
        actor="emp_pseudo_123",
        subject="cust_pseudo_999",
        source_system="crm_support",
    )
    e2 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-002",
        event_type="beneficiary_change",
        event_time=_dt(120),  # 2 minutes later
        actor="emp_pseudo_123",
        subject="cust_pseudo_999",
        source_system="core_banking",
    )
    e3 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-003",
        event_type="transfer_initiated",
        event_time=_dt(300),  # 5 minutes later
        actor="emp_pseudo_123",
        subject="cust_pseudo_999",
        source_system="payments",
    )

    fp_forward = build_case_fingerprint("CASE-101", "inst-1", [e1, e2, e3])
    fp_reversed = build_case_fingerprint("CASE-101", "inst-1", [e3, e1, e2])

    assert fp_forward.features == fp_reversed.features
    assert fp_forward.total_events == 3
    assert fp_forward.source_systems == ("core_banking", "crm_support", "payments")
    assert fp_forward.features["event.customer_record_access"] == "present"
    assert fp_forward.features["event.beneficiary_change"] == "present"
    assert fp_forward.features["event.transfer_initiated"] == "present"
    assert fp_forward.features["sequence.customer_record_access_to_beneficiary_change"] == "present_1m-15m"
    assert fp_forward.features["sequence.beneficiary_change_to_transfer_initiated"] == "present_1m-15m"


def test_zero_pii_boundary_in_fingerprint_features():
    """Verify that raw employee or customer identities never appear in features."""
    raw_name = "John Doe"
    raw_acct = "ACC-0987654321"
    e1 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-001",
        event_type="beneficiary_change",
        event_time=_dt(0),
        actor=raw_name,
        subject=raw_acct,
        source_system="core_banking",
    )

    fp = build_case_fingerprint("CASE-PII", "inst-1", [e1])

    # Ensure no PII in feature keys or values
    for k, v in fp.features.items():
        assert raw_name not in k
        assert raw_name not in v
        assert raw_acct not in k
        assert raw_acct not in v


# =============================================================================
# 2. Sequence Extraction & Entity Linkage Requirement
# =============================================================================


def test_unlinked_events_do_not_produce_sequence():
    """Events occurring close in time but WITHOUT an entity link must NOT generate a sequence."""
    e1 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-1",
        event_type="customer_record_access",
        event_time=_dt(0),
        actor="emp_A",
        subject="cust_X",
        source_system="crm_support",
    )
    e2 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-2",
        event_type="beneficiary_change",
        event_time=_dt(30),  # 30 seconds later, but completely unrelated actor and subject!
        actor="emp_B",
        subject="cust_Y",
        source_system="core_banking",
    )

    fp = build_case_fingerprint("CASE-UNLINKED", "inst-1", [e1, e2])
    # Sequence should be absent because both sources were observed, but no entity link
    assert fp.features["sequence.customer_record_access_to_beneficiary_change"] == "absent"


def test_missing_source_preserves_unknown_dimensions():
    """When a source system is missing from telemetry, its dimensions must be unknown, not absent."""
    e1 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-1",
        event_type="beneficiary_change",
        event_time=_dt(0),
        actor="emp_A",
        subject="cust_A",
        source_system="core_banking",
    )

    fp = build_case_fingerprint("CASE-PARTIAL", "inst-1", [e1])

    # Core banking is observed, so account_restricted (which maps to core_banking) is absent
    assert fp.features["event.account_restricted"] == "absent"
    # Identity access is NOT observed in telemetry, so password_reset must be unknown
    assert fp.features["event.password_reset"] == "unknown"
    assert fp.features["event.mfa_disabled"] == "unknown"
    assert fp.features["sequence.password_reset_to_beneficiary_change"] == "unknown"


# =============================================================================
# 3. Control Weakness Memory
# =============================================================================


def test_detect_control_weaknesses():
    """Detect customer authorization gap, access governance weakness, and delayed detection."""
    e1 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-1",
        event_type="privileged_login",
        event_time=_dt(0),
        actor="admin_1",
        source_system="identity_access",
    )
    e2 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-2",
        event_type="beneficiary_change",
        event_time=_dt(60),
        actor="admin_1",
        subject="acc_target",
        source_system="core_banking",
    )
    e3 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-3",
        event_type="transfer_initiated",
        event_time=_dt(120),
        actor="admin_1",
        subject="acc_target",
        source_system="payments",
    )
    e4 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-4",
        event_type="customer_complaint",
        event_time=_dt(10000),  # hours later
        subject="acc_target",
        source_system="crm_support",
    )

    weaknesses = detect_control_weaknesses([e1, e2, e3, e4])
    types = {w.weakness_type for w in weaknesses}

    assert ControlWeaknessType.CUSTOMER_AUTHORISATION_EVIDENCE_GAP in types
    assert ControlWeaknessType.ACCESS_GOVERNANCE_WEAKNESS in types
    assert ControlWeaknessType.DELAYED_DETECTION_OPPORTUNITY in types


# =============================================================================
# 4. Explainable Similarity & Separation from Coverage
# =============================================================================


def test_similarity_and_coverage_separation():
    """Similarity index and comparison coverage must be calculated independently."""
    e1 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-1",
        event_type="beneficiary_change",
        event_time=_dt(0),
        actor="emp_1",
        subject="acc_1",
        source_system="core_banking",
    )
    # Case A has only core_banking
    fp_a = build_case_fingerprint("CASE-A", "inst-1", [e1])

    # Case B has all 5 sources
    e2 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-2",
        event_type="beneficiary_change",
        event_time=_dt(0),
        actor="emp_2",
        subject="acc_2",
        source_system="core_banking",
    )
    e3 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-3",
        event_type="privileged_login",
        event_time=_dt(0),
        actor="emp_2",
        source_system="identity_access",
    )
    e4 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-4",
        event_type="transfer_initiated",
        event_time=_dt(0),
        actor="emp_2",
        subject="acc_2",
        source_system="payments",
    )
    e5 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-5",
        event_type="customer_record_access",
        event_time=_dt(0),
        actor="emp_2",
        subject="acc_2",
        source_system="crm_support",
    )
    e6 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="ev-6",
        event_type="role_change",
        event_time=_dt(0),
        actor="emp_2",
        source_system="hr_system",
    )
    fp_b = build_case_fingerprint("CASE-B", "inst-1", [e2, e3, e4, e5, e6])

    sim = compare_fingerprints(fp_a, fp_b)

    # Coverage should reflect only dimensions where both are known
    assert 0.0 < sim.comparison_coverage < 1.0
    # On the comparable dimensions that both have, beneficiary_change matches
    assert "event.beneficiary_change" in sim.matched_features
    assert sim.similarity_index is not None


def test_cross_installation_comparison_prohibited():
    """Comparing fingerprints from different installations must be rejected."""
    fp_a = build_case_fingerprint("CASE-1", "inst-bank-A", [])
    fp_b = build_case_fingerprint("CASE-2", "inst-bank-B", [])

    with pytest.raises(ValueError, match="Cross-installation comparison prohibited"):
        compare_fingerprints(fp_a, fp_b)


# =============================================================================
# 5. Pattern Validation Governance & Maker-Checker
# =============================================================================


def test_pattern_validation_thresholds_and_maker_checker():
    """Candidate pattern must satisfy validation policy and dual-control approval."""
    pattern = InstitutionalPattern(
        pattern_id="PAT-001",
        installation_id="inst-1",
        version=1,
        title="Beneficiary Manipulation",
        description="Access followed by beneficiary change and fund transfer",
        feature_signature={"sequence.customer_record_access_to_beneficiary_change": "present"},
        confirmed_fraud_case_ids=("CASE-1", "CASE-2"),
        confirmed_legitimate_case_ids=(),  # Missing legitimate counterexamples!
        independent_source_systems=("core_banking", "crm_support"),
        status=PatternStatus.CANDIDATE,
        created_by="investigator_alice",
        created_at=datetime.now(timezone.utc),
        curator="investigator_alice",
    )

    # 1. Validation evaluation fails due to missing legitimate comparisons
    eval_res = evaluate_pattern(pattern)
    assert not eval_res.eligible_for_review
    assert any("confirmed legitimate" in b for b in eval_res.blockers)

    # 2. Add confirmed legitimate comparison
    valid_pattern = InstitutionalPattern(
        pattern_id=pattern.pattern_id,
        installation_id=pattern.installation_id,
        version=pattern.version,
        title=pattern.title,
        description=pattern.description,
        feature_signature=pattern.feature_signature,
        confirmed_fraud_case_ids=pattern.confirmed_fraud_case_ids,
        confirmed_legitimate_case_ids=("CASE-LEGIT-1",),
        independent_source_systems=pattern.independent_source_systems,
        status=PatternStatus.CANDIDATE,
        created_by=pattern.created_by,
        created_at=pattern.created_at,
        curator=pattern.curator,
    )
    eval_res2 = evaluate_pattern(valid_pattern)
    assert eval_res2.eligible_for_review

    # 3. Maker-checker enforcement: Curator cannot approve own pattern
    with pytest.raises(ValueError, match="Maker-checker violation"):
        approve_pattern(
            valid_pattern,
            reviewer_subject="investigator_alice",
            rationale="Approved by creator",
        )

    # 4. Independent authoriser can approve
    approved = approve_pattern(
        valid_pattern,
        reviewer_subject="authoriser_bob",
        rationale="Sufficient fraud evidence and legitimate comparison confirmed.",
    )
    assert approved.status == PatternStatus.VALIDATED
    assert approved.reviewer == "authoriser_bob"


def test_pattern_lifecycle_transitions():
    """Verify suspend, reinstate, and retire transitions."""
    now = datetime.now(timezone.utc)
    pat = InstitutionalPattern(
        pattern_id="PAT-LC",
        installation_id="inst-1",
        version=1,
        title="Test Lifecycle",
        description="Description",
        feature_signature={"event.beneficiary_change": "present"},
        confirmed_fraud_case_ids=("C1", "C2"),
        confirmed_legitimate_case_ids=("C3",),
        independent_source_systems=("core_banking", "payments"),
        status=PatternStatus.VALIDATED,
        created_by="curator_1",
        created_at=now,
        curator="curator_1",
        reviewer="authoriser_1",
        reviewed_at=now,
    )

    suspended = suspend_pattern(pat, actor_subject="admin_user", rationale="Stale telemetry")
    assert suspended.status == PatternStatus.SUSPENDED

    reinstated = reinstate_pattern(suspended, actor_subject="admin_user", rationale="Telemetry verified")
    assert reinstated.status == PatternStatus.VALIDATED

    retired = retire_pattern(reinstated, actor_subject="admin_user", rationale="Replaced by new typology")
    assert retired.status == PatternStatus.RETIRED


# =============================================================================
# 6. Candidate Discovery & Historical Retrieval
# =============================================================================


def test_discover_candidate_patterns_and_matching():
    """Test discovering patterns from adjudicated cases and matching a new investigation."""
    # Case 1 (confirmed fraud)
    e1 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="c1-1",
        event_type="customer_record_access",
        event_time=_dt(0),
        actor="emp_1",
        subject="cust_1",
        source_system="crm_support",
    )
    e2 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="c1-2",
        event_type="beneficiary_change",
        event_time=_dt(60),
        actor="emp_1",
        subject="cust_1",
        source_system="core_banking",
    )
    fp1 = build_case_fingerprint("CASE-FRAUD-1", "inst-1", [e1, e2], adjudicated_label="confirmed_fraud")

    # Case 2 (confirmed fraud)
    e3 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="c2-1",
        event_type="customer_record_access",
        event_time=_dt(0),
        actor="emp_2",
        subject="cust_2",
        source_system="crm_support",
    )
    e4 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="c2-2",
        event_type="beneficiary_change",
        event_time=_dt(120),
        actor="emp_2",
        subject="cust_2",
        source_system="core_banking",
    )
    fp2 = build_case_fingerprint("CASE-FRAUD-2", "inst-1", [e3, e4], adjudicated_label="confirmed_fraud")

    # Case 3 (confirmed legitimate counterexample)
    e5 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="c3-1",
        event_type="customer_record_access",
        event_time=_dt(0),
        actor="emp_3",
        subject="cust_3",
        source_system="crm_support",
    )
    e6 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="c3-2",
        event_type="beneficiary_change",
        event_time=_dt(180),
        actor="emp_3",
        subject="cust_3",
        source_system="core_banking",
    )
    e7 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="c3-3",
        event_type="service_ticket_created",
        event_time=_dt(0),
        subject="cust_3",
        source_system="crm_support",
    )
    fp3 = build_case_fingerprint("CASE-LEGIT-3", "inst-1", [e5, e6, e7], adjudicated_label="confirmed_legitimate")

    # Discover candidate patterns
    candidates = discover_candidate_patterns([fp1, fp2, fp3], installation_id="inst-1")
    assert len(candidates) >= 1
    cand = candidates[0]
    assert cand.status == PatternStatus.CANDIDATE
    assert "CASE-FRAUD-1" in cand.confirmed_fraud_case_ids
    assert "CASE-FRAUD-2" in cand.confirmed_fraud_case_ids
    assert "CASE-LEGIT-3" in cand.confirmed_legitimate_case_ids

    # New investigation to match
    e_new1 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="new-1",
        event_type="customer_record_access",
        event_time=_dt(0),
        actor="emp_new",
        subject="cust_new",
        source_system="crm_support",
    )
    e_new2 = IntelligenceEvent(
        installation_id="inst-1",
        event_id="new-2",
        event_type="beneficiary_change",
        event_time=_dt(90),
        actor="emp_new",
        subject="cust_new",
        source_system="core_banking",
    )
    fp_new = build_case_fingerprint("CASE-NEW-001", "inst-1", [e_new1, e_new2])

    # 1. Historical case retrieval
    similar_cases = retrieve_similar_historical_cases(fp_new, [fp1, fp2, fp3])
    assert len(similar_cases) >= 2
    assert similar_cases[0].similarity_index is not None
    assert similar_cases[0].similarity_index > 0.8

    # 2. Pattern matching
    pattern_matches = match_case_against_patterns(fp_new, [cand])
    assert len(pattern_matches) == 1
    assert pattern_matches[0].similarity_index is not None
    assert pattern_matches[0].similarity_index > 0.8
    assert "Matches" in pattern_matches[0].explanation
