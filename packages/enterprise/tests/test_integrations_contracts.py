"""Tests for canonical bank data contracts, deterministic digests, and feed mapping."""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import pytest
from pydantic import ValidationError

from toroka_enterprise.integrations.contracts import (
    CanonicalEmploymentEventRecord,
    CanonicalRecord,
    CanonicalStaffAccessRecord,
    CanonicalTransactionRecord,
    Provenance,
    RecordType,
    SourceSystem,
)
from toroka_enterprise.integrations.exceptions import SchemaValidationError
from toroka_enterprise.integrations.mapping import (
    map_canonical_to_detector_feeds,
    map_core_banking_transaction,
    map_hr_employee_record,
    parse_timestamp,
)


def test_canonical_transaction_contract():
    prov = Provenance(
        source_system=SourceSystem.CORE_BANKING,
        connector_id="conn-cbs-01",
        source_record_id="TXN-1001",
        source_event_timestamp=datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc),
    )

    rec = CanonicalTransactionRecord(
        installation_id="bank-pilot-01",
        record_id="TXN-1001",
        provenance=prov,
        account_ref="ACC-9988",
        amount=Decimal("150000.50"),
        currency="KES",
        direction="DEBIT",
        transaction_type="TRANSFER",
        narrative="Vendor Settlement",
    )

    assert rec.record_type == RecordType.TRANSACTION
    assert rec.amount == Decimal("150000.50")
    assert rec.direction == "DEBIT"

    digest = rec.compute_digest()
    assert len(digest) == 64
    # Deterministic digest
    assert digest == rec.compute_digest()


def test_canonical_record_extra_fields_forbidden():
    prov = Provenance(
        source_system=SourceSystem.CORE_BANKING,
        connector_id="conn-cbs-01",
        source_record_id="TXN-1002",
        source_event_timestamp=datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc),
    )
    with pytest.raises(ValidationError):
        CanonicalTransactionRecord(
            installation_id="bank-pilot-01",
            record_id="TXN-1002",
            provenance=prov,
            account_ref="ACC-9988",
            amount=Decimal("500"),
            direction="DEBIT",
            transaction_type="POSTING",
            unauthorized_extra_field="malicious_injection",  # type: ignore
        )


def test_parse_timestamp_formats():
    # ISO string
    t1 = parse_timestamp("2026-11-15T14:30:00Z")
    assert t1.year == 2026 and t1.tzinfo == timezone.utc

    # Standard banking YYYY-MM-DD HH:MM:SS
    t2 = parse_timestamp("2026-11-15 14:30:00")
    assert t2.hour == 14 and t2.tzinfo == timezone.utc

    # Unix epoch
    t3 = parse_timestamp(1763217000)
    assert t3.tzinfo == timezone.utc

    # Invalid timestamp
    with pytest.raises(SchemaValidationError):
        parse_timestamp("not-a-timestamp")


def test_map_core_banking_transaction():
    raw = {
        "transaction_id": "CBS-REF-9090",
        "timestamp": "2026-11-15 10:15:00",
        "account_number": "ACC-7711",
        "counterparty": "ACC-8822",
        "amount": "2500000.00",
        "dr_cr": "DR",
        "type": "SALARY",
        "narrative": "Executive Payroll Journal",
        "staff_id": "STF-FIN-01",
    }
    rec = map_core_banking_transaction(raw, installation_id="inst-1", connector_id="cbs-conn")
    assert rec.record_id == "CBS-REF-9090"
    assert rec.direction == "DEBIT"
    assert rec.amount == Decimal("2500000.00")
    assert rec.posting_staff_ref == "STF-FIN-01"


def test_map_canonical_to_detector_feeds():
    prov_txn = Provenance(
        source_system=SourceSystem.CORE_BANKING,
        connector_id="conn-1",
        source_record_id="TX-01",
        source_event_timestamp=datetime(2026, 11, 15, 10, 0, tzinfo=timezone.utc),
    )
    txn = CanonicalTransactionRecord(
        installation_id="inst-1",
        record_id="TX-01",
        provenance=prov_txn,
        account_ref="ACC-100",
        counterparty_ref="ACC-200",
        amount=Decimal("5000"),
        direction="CREDIT",
        transaction_type="POSTING",
        narrative="Manual Journal Adjustment",
        posting_staff_ref="STF-01",
    )

    prov_hr = Provenance(
        source_system=SourceSystem.HR,
        connector_id="conn-2",
        source_record_id="STF-01",
        source_event_timestamp=datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc),
    )
    hr = CanonicalEmploymentEventRecord(
        installation_id="inst-1",
        record_id="STF-01",
        provenance=prov_hr,
        staff_ref="STF-01",
        event_type="JOINED",
        role="Loan Officer",
        department="Credit",
        branch="Mombasa",
        status="ACTIVE",
        salary_account="ACC-STF-SAL-01",
        effective_date=datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc),
    )

    feeds = map_canonical_to_detector_feeds([txn, hr])
    assert len(feeds["postings"]) == 1
    assert feeds["postings"][0]["ref"] == "TX-01"
    assert feeds["postings"][0]["staff_id"] == "STF-01"
    assert feeds["postings"][0]["amount"] == 5000.0

    assert len(feeds["hr_roster"]) == 1
    assert feeds["hr_roster"][0]["staff_id"] == "STF-01"
    assert feeds["hr_roster"][0]["salary_account"] == "ACC-STF-SAL-01"
