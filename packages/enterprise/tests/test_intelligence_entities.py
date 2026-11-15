"""Tests for intelligence entity references, relationships, and installation scoping."""
from __future__ import annotations

from datetime import datetime, timezone
import pytest

from toroka_enterprise.intelligence.entities import EntityRef, EntityType, Relationship


def test_entity_creation_and_serialization():
    ref = EntityRef(
        installation_id="bank-inst-01",
        entity_type=EntityType.EMPLOYEE,
        entity_id="emp_0012",
        display_id="Staff-12",
    )
    assert ref.entity_type == "employee"
    d = ref.to_dict()
    assert d["installation_id"] == "bank-inst-01"
    assert d["entity_id"] == "emp_0012"
    assert d["display_id"] == "Staff-12"


def test_relationship_provenance_and_validation():
    now = datetime.now(timezone.utc)
    src = EntityRef(
        installation_id="bank-inst-01",
        entity_type=EntityType.EMPLOYEE,
        entity_id="emp_0012",
    )
    tgt = EntityRef(
        installation_id="bank-inst-01",
        entity_type=EntityType.ACCOUNT,
        entity_id="acc_9921",
    )
    rel = Relationship(
        installation_id="bank-inst-01",
        source=src,
        target=tgt,
        relationship_type="accessed",
        first_seen=now,
        last_seen=now,
        confidence=0.95,
        source_system="iam_active_directory",
        source_record_id="audit-log-19283",
        attributes={"session_id": "sess-xyz", "terminal": "term-01"},
    )

    assert rel.relationship_type == "accessed"
    assert rel.confidence == 0.95
    assert rel.source_system == "iam_active_directory"
    assert rel.attributes["session_id"] == "sess-xyz"

    rel_dict = rel.to_dict()
    assert rel_dict["source"]["entity_id"] == "emp_0012"
    assert rel_dict["target"]["entity_id"] == "acc_9921"


def test_relationship_invalid_confidence():
    src = EntityRef(
        installation_id="bank-inst-01",
        entity_type=EntityType.EMPLOYEE,
        entity_id="emp_1",
    )
    tgt = EntityRef(
        installation_id="bank-inst-01",
        entity_type=EntityType.ACCOUNT,
        entity_id="acc_1",
    )
    with pytest.raises(ValueError, match="confidence must be between 0 and 1"):
        Relationship(
            installation_id="bank-inst-01",
            source=src,
            target=tgt,
            relationship_type="owns",
            confidence=1.5,
        )

    with pytest.raises(ValueError, match="confidence must be between 0 and 1"):
        Relationship(
            installation_id="bank-inst-01",
            source=src,
            target=tgt,
            relationship_type="owns",
            confidence=-0.1,
        )


def test_relationship_installation_isolation_defense():
    src_inst_a = EntityRef(
        installation_id="inst-alpha",
        entity_type=EntityType.EMPLOYEE,
        entity_id="emp_same_id",
    )
    tgt_inst_b = EntityRef(
        installation_id="inst-beta",
        entity_type=EntityType.ACCOUNT,
        entity_id="acc_999",
    )

    # Cross-installation linking rejected
    with pytest.raises(ValueError, match="target installation mismatch"):
        Relationship(
            installation_id="inst-alpha",
            source=src_inst_a,
            target=tgt_inst_b,
            relationship_type="accessed",
        )

    with pytest.raises(ValueError, match="source installation mismatch"):
        Relationship(
            installation_id="inst-beta",
            source=src_inst_a,
            target=tgt_inst_b,
            relationship_type="accessed",
        )
