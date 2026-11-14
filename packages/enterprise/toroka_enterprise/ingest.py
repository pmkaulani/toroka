"""Batch-extract ingestion: read-only CSV exports -> pseudonymised Dataset + an honest data-quality report.

Batch extracts (SFTP/CSV) are the first integration path: no live connectors into core banking.
A feed that is absent is reported as absent; scenario providers then say 'could not check' instead of 'clean'.
"""
from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta, timezone
from pathlib import Path

from .mapping import Mapping, read_mapped
from .pseudonym import Pseudonymiser
from .schema import (EAT, AuditEvent, Customer, Dataset, Instruction, Payment, Posting, ServiceRequest, Staff,
                     SysAccount, parse_ts)

SPEC: dict[str, tuple[str, ...]] = {
    "hr_roster": ("staff_id", "status", "role", "branch", "end_date", "salary_account"),
    "system_accounts": ("account_id", "staff_id", "system", "status", "is_privileged"),
    "portfolio": ("staff_id", "customer_id"),
    "audit_log": ("ts", "account_id", "action", "customer_id", "approver_account_id"),
    "service_requests": ("request_id", "customer_id", "staff_id", "opened_at", "closed_at", "kind"),
    "instructions": ("instruction_id", "customer_id", "kind", "received_at"),
    "payments": ("payment_id", "ts", "customer_id", "channel", "amount", "beneficiary"),
    "customers": ("customer_id", "status", "dormant_since", "deceased_flag", "is_sensitive"),
    "postings": ("posting_id", "ts", "ledger", "counter_party", "amount", "entered_by_account", "approved_by_account", "manual", "narrative"),
}
REQUIRED = ("audit_log", "system_accounts")
FEED_KEY = {"hr_roster": "hr", "system_accounts": "accounts", "portfolio": "assignments", "audit_log": "audit",
            "service_requests": "crm", "instructions": "instructions", "payments": "payments",
            "customers": "customers", "postings": "postings"}


class IngestError(ValueError):
    pass


@dataclass
class DataQuality:
    rows_read: dict[str, int] = field(default_factory=dict)
    rows_rejected: dict[str, int] = field(default_factory=dict)
    rejected_samples: list[str] = field(default_factory=list)
    feeds_missing: list[str] = field(default_factory=list)
    events_unmapped_accounts: int = 0
    naive_timestamps_assumed_eat: int = 0
    crm_gap_branches: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    unmapped_values: dict[str, dict[str, int]] = field(default_factory=dict)
    ts_format_failures: dict[str, int] = field(default_factory=dict)
    absent_fields: list[str] = field(default_factory=list)
    naive_tz: timezone = EAT

    def to_dict(self) -> dict:
        return {"rows_read": self.rows_read, "rows_rejected": self.rows_rejected, "rejected_samples": self.rejected_samples,
                "feeds_missing": self.feeds_missing, "events_unmapped_accounts": self.events_unmapped_accounts,
                "naive_timestamps_assumed_eat": self.naive_timestamps_assumed_eat,
                "crm_gap_branches": self.crm_gap_branches, "notes": self.notes, "unmapped_values": self.unmapped_values,
                "ts_format_failures": self.ts_format_failures, "absent_fields": self.absent_fields}


def _bool(v: str) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "y"}


def _amount(v: str) -> int:
    text = (str(v) if v is not None else "").strip().replace(",", "")
    return int(round(float(text)))


def _opt_ts(v: str, q: DataQuality):
    return _ts(v, q) if (v or "").strip() else None


def _ts(v: str, q: DataQuality):
    if v and "T" in v.strip() and not any(c in v.strip()[10:] for c in "Z+") and "-" not in v.strip()[11:]:
        q.naive_timestamps_assumed_eat += 1
    elif v and " " in v.strip() and not any(c in v.strip()[10:] for c in "Z+") and "-" not in v.strip()[11:]:
        q.naive_timestamps_assumed_eat += 1
    return parse_ts(v, q.naive_tz)


def _read(directory: Path, name: str, q: DataQuality, mapping: Mapping | None = None):
    if mapping is not None:
        fm = mapping.feeds.get(name)
        if fm is None:
            q.feeds_missing.append(name)
            return None
        return read_mapped(directory, name, fm, q)
    path = directory / f"{name}.csv"
    if not path.exists():
        q.feeds_missing.append(name)
        return None
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        missing = [c for c in SPEC[name] if c not in (reader.fieldnames or [])]
        if missing:
            raise IngestError(f"{name}.csv is missing required columns: {', '.join(missing)}")
        return list(enumerate(reader, start=2))


def ingest_dir(directory: str | Path, pseudonymiser: Pseudonymiser, mapping: Mapping | None = None) -> tuple[Dataset, DataQuality]:
    d, ps, q = Path(directory), pseudonymiser, DataQuality()
    if mapping is not None:
        q.naive_tz = timezone(timedelta(hours=mapping.naive_tz_offset_hours))
    ds = Dataset()
    raw = {name: _read(d, name, q, mapping) for name in SPEC}
    for name in REQUIRED:
        if raw[name] is None:
            raise IngestError(f"required feed {name} not found in {d}")

    def run(name, handler):
        rows = raw[name]
        if rows is None:
            return
        ds.available.add(FEED_KEY[name])
        q.rows_read[name] = len(rows)
        for line, row in rows:
            try:
                handler(row, line)
            except (ValueError, KeyError) as exc:
                q.rows_rejected[name] = q.rows_rejected.get(name, 0) + 1
                if len(q.rejected_samples) < 20:
                    q.rejected_samples.append(f"{name}.csv line {line}: {exc}")

    def hr(r, _):
        s = ps.ref("stf", r["staff_id"])
        if not s:
            raise ValueError("missing staff_id")
        ds.staff[s] = Staff(s, r["status"].strip().lower(), r["role"].strip(), r["branch"].strip(), _opt_ts(r["end_date"], q), ps.ref("cus", r["salary_account"]))

    def acct(r, _):
        a = ps.ref("acc", r["account_id"])
        if not a:
            raise ValueError("missing account_id")
        ds.accounts[a] = SysAccount(a, ps.ref("stf", r["staff_id"]), r["system"].strip(), r["status"].strip().lower(), _bool(r["is_privileged"]))

    def port(r, _):
        s, c = ps.ref("stf", r["staff_id"]), ps.ref("cus", r["customer_id"])
        if not s or not c:
            raise ValueError("missing id")
        ds.assignments.setdefault(s, set()).add(c)

    def audit(r, line):
        a = ps.ref("acc", r["account_id"])
        if not a or not r["action"].strip():
            raise ValueError("missing account_id or action")
        ds.events.append(AuditEvent(_ts(r["ts"], q), a, r["action"].strip().lower(), ps.ref("cus", r["customer_id"]), ps.ref("acc", r["approver_account_id"]), line))

    def crm(r, _):
        c = ps.ref("cus", r["customer_id"])
        if not c:
            raise ValueError("missing customer_id")
        ds.requests.append(ServiceRequest(r["request_id"].strip(), c, ps.ref("stf", r["staff_id"]), _ts(r["opened_at"], q), _opt_ts(r["closed_at"], q), r["kind"].strip().lower()))

    def instr(r, _):
        c = ps.ref("cus", r["customer_id"])
        if not c:
            raise ValueError("missing customer_id")
        ds.instructions.append(Instruction(r["instruction_id"].strip(), c, r["kind"].strip().lower(), _ts(r["received_at"], q)))

    def pay(r, _):
        c = ps.ref("cus", r["customer_id"])
        if not c:
            raise ValueError("missing customer_id")
        ds.payments.append(Payment(r["payment_id"].strip(), _ts(r["ts"], q), c, r["channel"].strip().lower(), _amount(r["amount"]), ps.ref("cus", r["beneficiary"])))

    def cust(r, _):
        c = ps.ref("cus", r["customer_id"])
        if not c:
            raise ValueError("missing customer_id")
        ds.customers[c] = Customer(c, r["status"].strip().lower(), _opt_ts(r["dormant_since"], q), _bool(r["deceased_flag"]), _bool(r["is_sensitive"]))

    def post(r, _):
        ent = ps.ref("acc", r["entered_by_account"])
        if not ent:
            raise ValueError("missing entered_by_account")
        ds.postings.append(Posting(r["posting_id"].strip(), _ts(r["ts"], q), r["ledger"].strip().upper(), ps.ref("cus", r["counter_party"]), _amount(r["amount"]), ent, ps.ref("acc", r["approved_by_account"]), _bool(r["manual"]), r["narrative"].strip().upper()))

    for name, fn in (("hr_roster", hr), ("system_accounts", acct), ("portfolio", port), ("audit_log", audit),
                     ("service_requests", crm), ("instructions", instr), ("payments", pay), ("customers", cust), ("postings", post)):
        run(name, fn)

    ds.absent_fields = set(q.absent_fields)
    for feed, codes in q.unmapped_values.items():
        q.notes.append(f"{feed}: {sum(codes.values())} rows carry codes with no mapping (top: {', '.join(list(codes)[:5])}); detectors cannot see them until mapped.")
    for feed, n in q.ts_format_failures.items():
        q.notes.append(f"{feed}: {n} timestamps did not match the declared format and were rejected.")
    if q.absent_fields:
        q.notes.append("Fields this system does not supply (dependent checks stand down rather than infer risk): " + ", ".join(q.absent_fields))
    ds.reindex()
    q.events_unmapped_accounts = sum(1 for e in ds.events if e.account_ref not in ds.accounts)
    if q.events_unmapped_accounts:
        q.notes.append(f"{q.events_unmapped_accounts} audit events came from accounts missing in system_accounts; they cannot be attributed to staff.")
    if q.naive_timestamps_assumed_eat:
        q.notes.append(f"{q.naive_timestamps_assumed_eat} timestamps carried no UTC offset and were read as East Africa Time (+03:00).")

    # CRM coverage per branch: if a branch's staff almost never appear in service requests, absence of a request proves nothing there.
    if "hr" in ds.available:
        branches = {s.branch for s in ds.staff.values()}
        if "crm" not in ds.available or "service_requests.staff_id" in ds.absent_fields:
            ds.crm_gap_branches = set(branches)
            q.notes.append("No usable CRM feed (missing, or tickets carry no handler): access justification cannot be assessed anywhere; findings will say so.")
        else:
            with_req = {r.staff_ref for r in ds.requests if r.staff_ref}
            for b in branches:
                members = [s.staff_ref for s in ds.staff.values() if s.branch == b and s.status == "active"]
                if members and sum(1 for m in members if m in with_req) / len(members) < 0.5:
                    ds.crm_gap_branches.add(b)
        q.crm_gap_branches = sorted(ds.crm_gap_branches)
        if ds.crm_gap_branches:
            q.notes.append("CRM coverage is low for: " + ", ".join(sorted(ds.crm_gap_branches)) + ". Access-justification findings are downgraded to context there.")
    return ds, q
