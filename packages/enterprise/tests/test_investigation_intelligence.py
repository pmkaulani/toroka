"""Unit and property tests for Investigation Intelligence domain capabilities."""
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import UUID, uuid4
import pytest

from toroka_enterprise.investigation.contracts import (
    EntityIn,
    EntityKind,
    EvidenceArtifactIn,
    EvidenceSourceType,
    EvidenceState,
    FindingIn,
    RelationshipIn,
    TransactionEventIn,
)
from toroka_enterprise.investigation.evidence import (
    sha256_bytes,
    verify_evidence_bytes,
)
from toroka_enterprise.investigation.money_flow import (
    reconstruct_money_flow,
)
from toroka_enterprise.investigation.referral_pack import (
    ReferralPackBuilder,
)
from toroka_enterprise.investigation.rules import (
    InstitutionPolicyProfile,
    InvestigationRuleEngine,
)
from toroka_enterprise.investigation.tokens import (
    make_installation_token,
    normalize_identifier_by_kind,
)


def test_token_installation_isolation():
    key = b"A" * 32
    raw = "+254 712-345-678"
    inst_1 = "inst-equity-bank"
    inst_2 = "inst-kcb-bank"

    token_1 = make_installation_token(key=key, installation_id=inst_1, entity_kind="phone", raw_identifier=raw)
    token_2 = make_installation_token(key=key, installation_id=inst_2, entity_kind="phone", raw_identifier=raw)

    assert token_1 != token_2
    assert token_1.startswith("te1:phone:")
    assert token_2.startswith("te1:phone:")

    # Stable within same installation
    token_1_again = make_installation_token(key=key, installation_id=inst_1, entity_kind="phone", raw_identifier="0712345678")
    assert token_1 == token_1_again


def test_token_key_length_validation():
    short_key = b"too_short"
    with pytest.raises(ValueError, match="at least 256 bits"):
        make_installation_token(key=short_key, installation_id="inst-1", entity_kind="email", raw_identifier="user@bank.co.ke")


def test_evidence_hash_verification():
    sample_bytes = b"M-PESA statement payload ref: QWE123RTY"
    expected_digest = sha256_bytes(sample_bytes)

    assert verify_evidence_bytes(data=sample_bytes, expected_sha256=expected_digest) is True
    assert verify_evidence_bytes(data=sample_bytes + b"tampered", expected_sha256=expected_digest) is False


def test_evidence_time_order_validation():
    now = datetime.now(timezone.utc)
    # collected_at cannot precede observed_at
    with pytest.raises(ValueError, match="cannot precede observed_at"):
        EvidenceArtifactIn(
            case_id=uuid4(),
            source_type=EvidenceSourceType.BANK_TRANSACTION,
            source_system="CoreLedger",
            observed_at=now,
            collected_at=now - timedelta(hours=1),
            collected_by="investigator@bank.ke",
            source_timezone="Africa/Nairobi",
            sha256="a" * 64,
        )


def test_relationship_requires_evidence_and_no_self_loop():
    now = datetime.now(timezone.utc)
    ent_id = uuid4()
    other_id = uuid4()

    # Self relationship forbidden
    with pytest.raises(ValueError, match="self-relationships are not supported"):
        RelationshipIn(
            source_entity_id=ent_id,
            target_entity_id=ent_id,
            relationship_type="transfers_to",
            evidence_ids=[uuid4()],
            explanation="Self transfer loop attempt",
        )

    # Empty evidence_ids forbidden
    with pytest.raises(ValueError):
        RelationshipIn(
            source_entity_id=ent_id,
            target_entity_id=other_id,
            relationship_type="associated_with",
            evidence_ids=[],
            explanation="Attempt with no evidence",
        )


def test_money_flow_reconstruction_with_reversals():
    now = datetime.now(timezone.utc)
    root_id = uuid4()
    hop1_id = uuid4()
    hop2_id = uuid4()
    ev_id = uuid4()

    txs = [
        TransactionEventIn(
            case_id=uuid4(),
            source_entity_id=root_id,
            destination_entity_id=hop1_id,
            amount=Decimal("150000.00"),
            currency="KES",
            occurred_at=now,
            source_timezone="Africa/Nairobi",
            channel="PESALINK",
            source_system="CoreLedger",
            source_record_ref="TXN-001",
            evidence_id=ev_id,
            event_type="transfer",
        ),
        TransactionEventIn(
            case_id=uuid4(),
            source_entity_id=hop1_id,
            destination_entity_id=hop2_id,
            amount=Decimal("100000.00"),
            currency="KES",
            occurred_at=now + timedelta(minutes=10),
            source_timezone="Africa/Nairobi",
            channel="RTGS",
            source_system="CoreLedger",
            source_record_ref="TXN-002",
            evidence_id=ev_id,
            event_type="transfer",
        ),
        # Partial reversal on hop1
        TransactionEventIn(
            case_id=uuid4(),
            source_entity_id=hop1_id,
            destination_entity_id=hop2_id,
            amount=Decimal("20000.00"),
            currency="KES",
            occurred_at=now + timedelta(minutes=15),
            source_timezone="Africa/Nairobi",
            channel="RTGS",
            source_system="CoreLedger",
            source_record_ref="TXN-003",
            evidence_id=ev_id,
            event_type="reversal",
        ),
    ]

    reconstruction = reconstruct_money_flow(
        transactions=txs,
        root_entity_id=root_id,
        max_hops=3,
    )

    assert len(reconstruction.edges) == 3
    assert reconstruction.currency_totals["KES"] == Decimal("250000.00")
    assert reconstruction.reversal_totals["KES"] == Decimal("20000.00")
    assert reconstruction.net_by_currency["KES"] == Decimal("230000.00")
    assert any(n.is_root for n in reconstruction.nodes if n.entity_id == root_id)


def test_rule_engine_fan_out_lead():
    now = datetime.now(timezone.utc)
    src_id = uuid4()
    ev_id = uuid4()

    txs = [
        TransactionEventIn(
            case_id=uuid4(),
            source_entity_id=src_id,
            destination_entity_id=uuid4(),
            amount=Decimal("50000.00"),
            currency="KES",
            occurred_at=now + timedelta(minutes=i * 5),
            source_timezone="Africa/Nairobi",
            channel="PESALINK",
            source_system="CoreLedger",
            source_record_ref=f"TXN-{i}",
            evidence_id=ev_id,
            event_type="transfer",
        )
        for i in range(4)
    ]

    policy = InstitutionPolicyProfile(
        fan_out_min_destinations=3,
        fan_out_min_total_amount=Decimal("100000.00"),
    )
    engine = InvestigationRuleEngine(policy=policy)
    findings = engine.evaluate_case(transactions=txs, relationships=[], evidence_items=[])

    assert len(findings) >= 1
    fan_out = next(f for f in findings if f.rule_id == "transaction.rapid_fan_out")
    assert fan_out.state == EvidenceState.HYPOTHESIS
    assert "does NOT prove" in fan_out.explanation
    assert len(fan_out.unresolved_questions) > 0


def test_referral_pack_integrity_and_manifest():
    pack_id = uuid4()
    case_id = uuid4()
    inst_id = "inst-test-01"

    summary = {
        "case_id": str(case_id),
        "label": "Case 2026-001",
        "focus": "Suspected business invoice redirection",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    files = ReferralPackBuilder.build_package_files(
        pack_id=pack_id,
        case_id=case_id,
        installation_id=inst_id,
        case_summary=summary,
        entities=[],
        relationships=[],
        transactions=[],
        findings=[],
        evidence_index=[],
        generating_principal="investigator.alice@bank.ke",
        recipient_org="DCI Financial Crimes Unit",
        purpose="Investigation chronology referral",
        legal_basis="Section 31 NPS Act",
    )

    assert "manifest.json" in files
    assert "case-summary.json" in files
    assert "chronology.csv" in files
    assert "integrity/sha256sums.txt" in files

    pack_hash = ReferralPackBuilder.compute_overall_pack_hash(files)
    assert len(pack_hash) == 64

    # Verify sha256sums text matches files
    sums_text = files["integrity/sha256sums.txt"].decode("utf-8")
    for line in sums_text.strip().splitlines():
        h, fname = line.split("  ")
        assert sha256_bytes(files[fname]) == h
