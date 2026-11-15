"""Explicit mapping from bank source payloads to canonical integration contracts and detector feeds."""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from .contracts import (
    CanonicalAccountRecord,
    CanonicalCustomerChangeRecord,
    CanonicalEmploymentEventRecord,
    CanonicalPaymentEventRecord,
    CanonicalRecord,
    CanonicalSecurityEventRecord,
    CanonicalStaffAccessRecord,
    CanonicalTransactionRecord,
    Provenance,
    RecordType,
    SourceSystem,
)
from .exceptions import SchemaValidationError


def parse_timestamp(value: Any) -> datetime:
    """Safely parse timestamps from ISO formats, Unix epochs, or common banking date strings."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        v = value.strip()
        # ISO format
        try:
            dt = datetime.fromisoformat(v)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass
        # Common banking format: YYYY-MM-DD HH:MM:SS
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d-%m-%Y %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(v, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    raise SchemaValidationError(f"Cannot parse timestamp value: '{value}'")


def map_core_banking_transaction(
    raw: dict[str, Any],
    *,
    installation_id: str,
    connector_id: str,
) -> CanonicalTransactionRecord:
    """Map raw core banking transaction row into CanonicalTransactionRecord."""
    rec_id = str(raw.get("transaction_id") or raw.get("ref") or raw.get("id") or "").strip()
    if not rec_id:
        raise SchemaValidationError("Core banking transaction missing unique reference ID")

    ts_raw = raw.get("timestamp") or raw.get("ts") or raw.get("booking_date")
    if not ts_raw:
        raise SchemaValidationError("Core banking transaction missing booking timestamp")
    ts = parse_timestamp(ts_raw)

    amount_raw = raw.get("amount")
    if amount_raw is None:
        raise SchemaValidationError("Core banking transaction missing amount")
    try:
        amount = Decimal(str(amount_raw))
    except Exception as exc:
        raise SchemaValidationError(f"Invalid transaction amount: {amount_raw}") from exc

    direction = str(raw.get("direction") or raw.get("dr_cr") or "DEBIT").upper()
    if direction in ("DR", "D"):
        direction = "DEBIT"
    elif direction in ("CR", "C"):
        direction = "CREDIT"
    if direction not in ("DEBIT", "CREDIT"):
        raise SchemaValidationError(f"Invalid transaction direction: {direction}")

    account_ref = str(raw.get("account_number") or raw.get("account_ref") or "").strip()
    if not account_ref:
        raise SchemaValidationError("Core banking transaction missing primary account reference")

    prov = Provenance(
        source_system=SourceSystem.CORE_BANKING,
        connector_id=connector_id,
        source_record_id=rec_id,
        source_event_timestamp=ts,
        raw_metadata={"channel": raw.get("channel", "CORE")},
    )

    return CanonicalTransactionRecord(
        installation_id=installation_id,
        record_id=rec_id,
        provenance=prov,
        account_ref=account_ref,
        counterparty_ref=str(raw.get("counterparty") or raw.get("counter_ref") or "") or None,
        amount=amount,
        currency=str(raw.get("currency") or "KES").upper(),
        direction=direction,
        transaction_type=str(raw.get("type") or raw.get("transaction_type") or "POSTING"),
        narrative=str(raw.get("narrative") or raw.get("description") or ""),
        channel=str(raw.get("channel") or "CORE"),
        status=str(raw.get("status") or "SETTLED").upper(),
        is_reversal=bool(raw.get("is_reversal", False)),
        reversal_of_ref=str(raw.get("reversal_of_ref") or "") or None,
        posting_staff_ref=str(raw.get("staff_id") or raw.get("posting_staff_ref") or "") or None,
        authorization_staff_ref=str(raw.get("auth_staff_id") or "") or None,
        branch_ref=str(raw.get("branch") or "") or None,
    )


def map_hr_employee_record(
    raw: dict[str, Any],
    *,
    installation_id: str,
    connector_id: str,
) -> CanonicalEmploymentEventRecord:
    """Map raw HR roster/event into CanonicalEmploymentEventRecord."""
    staff_id = str(raw.get("staff_id") or raw.get("employee_id") or "").strip()
    if not staff_id:
        raise SchemaValidationError("HR record missing staff ID")

    ts_raw = raw.get("effective_date") or raw.get("date") or raw.get("timestamp") or datetime.now(timezone.utc)
    ts = parse_timestamp(ts_raw)

    prov = Provenance(
        source_system=SourceSystem.HR,
        connector_id=connector_id,
        source_record_id=staff_id,
        source_event_timestamp=ts,
    )

    return CanonicalEmploymentEventRecord(
        installation_id=installation_id,
        record_id=staff_id,
        provenance=prov,
        staff_ref=staff_id,
        event_type=str(raw.get("event_type") or "ROLE_CHANGE"),
        role=str(raw.get("role") or raw.get("job_title") or "Staff"),
        department=str(raw.get("department") or "Operations"),
        branch=str(raw.get("branch") or "HeadOffice"),
        status=str(raw.get("status") or "ACTIVE").upper(),
        salary_account=str(raw.get("salary_account") or "") or None,
        effective_date=ts,
    )


def map_canonical_to_detector_feeds(
    records: list[CanonicalRecord],
) -> dict[str, list[dict[str, Any]]]:
    """Translate canonical records into Toroka's existing detector engine feed datasets.
    
    Returns a dictionary mapping feed names (e.g. 'postings', 'hr_roster', 'audit_log')
    to lists of row dictionaries matching Toroka's runtime specifications.
    """
    feeds: dict[str, list[dict[str, Any]]] = {
        "hr_roster": [],
        "audit_log": [],
        "postings": [],
        "account_changes": [],
    }

    for r in records:
        if isinstance(r, CanonicalTransactionRecord):
            feeds["postings"].append({
                "ts": r.provenance.source_event_timestamp.isoformat(),
                "ref": r.record_id,
                "staff_id": r.posting_staff_ref or "SYSTEM",
                "dr_cr": "DR" if r.direction == "DEBIT" else "CR",
                "amount": float(r.amount),
                "currency": r.currency,
                "source_account": r.account_ref,
                "dest_account": r.counterparty_ref or "",
                "manual": bool(r.posting_staff_ref),
                "narrative": r.narrative,
                "status": r.status,
            })
        elif isinstance(r, CanonicalEmploymentEventRecord):
            feeds["hr_roster"].append({
                "staff_id": r.staff_ref,
                "role": r.role,
                "department": r.department,
                "branch": r.branch,
                "status": r.status.lower(),
                "salary_account": r.salary_account or "",
                "effective_date": r.effective_date.isoformat(),
            })
        elif isinstance(r, CanonicalStaffAccessRecord):
            feeds["audit_log"].append({
                "ts": r.provenance.source_event_timestamp.isoformat(),
                "staff_id": r.staff_ref,
                "action": r.action,
                "target_system": r.system_ref,
                "detail": f"{r.resource_type}:{r.resource_id}",
                "success": r.outcome == "SUCCESS",
            })
        elif isinstance(r, CanonicalCustomerChangeRecord):
            feeds["account_changes"].append({
                "ts": r.provenance.source_event_timestamp.isoformat(),
                "staff_id": r.changed_by_staff_ref,
                "account_id": r.account_ref or r.customer_ref,
                "field_changed": r.field_name,
                "old_val": r.old_value or "",
                "new_val": r.new_value or "",
            })

    return feeds
