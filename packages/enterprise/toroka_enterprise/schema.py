"""Normalised, pseudonymised records and the indexed Dataset that scenario providers read."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

EAT = timezone(timedelta(hours=3))  # Kenya observes no DST; applied to exports that carry no UTC offset

SENSITIVE_ACTIONS = frozenset({"contact_change", "mobile_change", "card_issue", "beneficiary_add", "limit_change", "account_reactivate"})


def parse_ts(value: str, naive_tz: timezone = EAT) -> datetime:
    text = (value or "").strip()
    if not text:
        raise ValueError("empty timestamp")
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=naive_tz)
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class Staff:
    staff_ref: str
    status: str                 # active | terminated
    role: str
    branch: str
    end_date: datetime | None = None
    salary_account_ref: str | None = None


@dataclass(frozen=True, slots=True)
class SysAccount:
    account_ref: str
    staff_ref: str | None       # None = generic / shared / unmapped account
    system: str
    status: str                 # active | disabled
    is_privileged: bool = False


@dataclass(frozen=True, slots=True)
class AuditEvent:
    ts: datetime
    account_ref: str
    action: str
    customer_ref: str | None
    approver_ref: str | None = None
    row: int = 0                # source row, kept for provenance


@dataclass(frozen=True, slots=True)
class ServiceRequest:
    request_id: str
    customer_ref: str
    staff_ref: str | None
    opened_at: datetime
    closed_at: datetime | None
    kind: str


@dataclass(frozen=True, slots=True)
class Instruction:
    instruction_id: str
    customer_ref: str
    kind: str
    received_at: datetime
    # Actual source-system entry time; it may be later than customer receipt.
    recorded_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class Payment:
    payment_id: str
    ts: datetime
    customer_ref: str
    channel: str
    amount: int                 # minor currency units (e.g. cents)
    beneficiary_ref: str | None
    direction: str = "debit"    # debit (money out) | credit (money in) | unknown
    currency: str = "KES"


@dataclass(frozen=True, slots=True)
class Customer:
    customer_ref: str
    status: str                 # active | dormant | closed
    dormant_since: datetime | None
    deceased_flag: bool
    is_sensitive: bool


@dataclass(frozen=True, slots=True)
class Posting:
    posting_id: str
    ts: datetime
    ledger: str                 # e.g. SUSPENSE, DISPUTE, PAYROLL
    counter_ref: str | None
    amount: int                 # minor currency units (e.g. cents)
    entered_by_ref: str
    approved_by_ref: str | None
    manual: bool
    narrative: str
    currency: str = "KES"


@dataclass
class Dataset:
    currency: str = "KES"       # base currency for the dataset
    staff: dict[str, Staff] = field(default_factory=dict)
    accounts: dict[str, SysAccount] = field(default_factory=dict)
    assignments: dict[str, set[str]] = field(default_factory=dict)
    events: list[AuditEvent] = field(default_factory=list)
    requests: list[ServiceRequest] = field(default_factory=list)
    instructions: list[Instruction] = field(default_factory=list)
    payments: list[Payment] = field(default_factory=list)
    customers: dict[str, Customer] = field(default_factory=dict)
    postings: list[Posting] = field(default_factory=list)
    available: set[str] = field(default_factory=set)       # feeds actually supplied
    crm_gap_branches: set[str] = field(default_factory=set)
    absent_fields: set[str] = field(default_factory=set)   # canonical columns the source system does not supply at all
    feed_quality: dict[str, dict] = field(default_factory=dict)
    degraded_feeds: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.reindex()

    def reindex(self) -> None:
        self.accounts_by_staff: dict[str, list[str]] = defaultdict(list)
        for acc in self.accounts.values():
            if acc.staff_ref:
                self.accounts_by_staff[acc.staff_ref].append(acc.account_ref)
        self.events_by_staff: dict[str, list[AuditEvent]] = defaultdict(list)
        self.events_by_customer: dict[str, list[AuditEvent]] = defaultdict(list)
        for ev in sorted(self.events, key=lambda e: e.ts):
            staff = self.staff_of(ev.account_ref)
            if staff:
                self.events_by_staff[staff].append(ev)
            if ev.customer_ref:
                self.events_by_customer[ev.customer_ref].append(ev)
        self.requests_by_customer: dict[str, list[ServiceRequest]] = defaultdict(list)
        for r in self.requests:
            self.requests_by_customer[r.customer_ref].append(r)
        self.instructions_by_customer: dict[str, list[Instruction]] = defaultdict(list)
        for i in self.instructions:
            self.instructions_by_customer[i.customer_ref].append(i)
        self.payments_by_customer: dict[str, list[Payment]] = defaultdict(list)
        for p in self.payments:
            self.payments_by_customer[p.customer_ref].append(p)
        self.postings_by_staff: dict[str, list[Posting]] = defaultdict(list)
        for p in self.postings:
            staff = self.staff_of(p.entered_by_ref)
            if staff:
                self.postings_by_staff[staff].append(p)
        self.roster_salary_accounts = {s.salary_account_ref for s in self.staff.values() if s.salary_account_ref}

    def staff_of(self, account_ref: str | None) -> str | None:
        acc = self.accounts.get(account_ref) if account_ref else None
        return acc.staff_ref if acc else None

    def branch_of(self, staff_ref: str) -> str | None:
        s = self.staff.get(staff_ref)
        return s.branch if s else None
