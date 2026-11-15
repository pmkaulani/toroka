#!/usr/bin/env python3
"""Apply the Toroka Enterprise hardening patch to a clean repository checkout.

Run from the Toroka repository root:
    python apply_toroka_enterprise_hardening.py --check
    python apply_toroka_enterprise_hardening.py

The script preserves each file's existing newline style and refuses to proceed if
its expected source anchors are missing or already partially modified.
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
from pathlib import Path

ROOT = Path.cwd()


def read(path: str) -> str:
    p = ROOT / path
    if not p.is_file():
        raise RuntimeError(f"Required repository file not found: {path}")
    # newline='' is important: some current Enterprise files use CRCRLF.
    with p.open("r", encoding="utf-8", newline="") as f:
        return f.read()


def write(path: str, content: str) -> None:
    p = ROOT / path
    with p.open("w", encoding="utf-8", newline="") as f:
        f.write(content)


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"Expected one occurrence for {label}; found {count}")
    return text.replace(old, new, 1)


def replace_class(text: str, class_name: str, next_class: str, replacement: str) -> str:
    start_pattern = re.compile(rf"(?m)^class {re.escape(class_name)}(?=\s*:)" )
    end_pattern = re.compile(rf"(?m)^class {re.escape(next_class)}(?=\s*:)" )
    starts = list(start_pattern.finditer(text))
    if len(starts) != 1:
        raise RuntimeError(f"Expected exactly one class {class_name}; found {len(starts)}")
    start = starts[0].start()
    ends = list(end_pattern.finditer(text, starts[0].end()))
    if len(ends) != 1:
        raise RuntimeError(f"Expected exactly one following class {next_class}; found {len(ends)}")
    end = ends[0].start()
    return text[:start] + replacement.rstrip() + "\n\n\n" + text[end:]


def transform_pseudonym(text: str) -> str:
    text = replace_once(
        text,
        'PREFIX = {"stf": "STF", "acc": "ACC", "cus": "CUS"}',
        '''# Separate namespaces prevent a customer ID from colliding with a bank
# account, beneficiary, vendor, device or other operational identity.
PREFIX = {
    "stf": "STF",
    "acc": "ACC",
    "cus": "CUS",
    "bank_account": "BAC",
    "beneficiary": "BEN",
    "vendor": "VEN",
    "device": "DEV",
    "service_account": "SVC",
    "branch": "BRN",
    "gl_account": "GLA",
}''',
        "pseudonym namespaces",
    )
    text = replace_once(
        text,
        'digest = hmac.new(self._secret, f"toroka-ent:{kind}:{value}".encode(), hashlib.sha256).hexdigest()[:12]',
        '# Keep 128 bits of the keyed digest; 48 bits is too short for large-scale correlation.\n'
        '        digest = hmac.new(self._secret, f"toroka-ent:{kind}:{value}".encode(), hashlib.sha256).hexdigest()[:32]',
        "pseudonym digest length",
    )
    return text


def transform_schema(text: str) -> str:
    text = replace_once(
        text,
        'SENSITIVE_ACTIONS = frozenset({"contact_change", "card_issue", "beneficiary_add", "limit_change", "account_reactivate"})',
        'SENSITIVE_ACTIONS = frozenset({"contact_change", "mobile_change", "card_issue", "beneficiary_add", "limit_change", "account_reactivate"})',
        "mobile-change taxonomy",
    )
    # Restrict the field edit to the Instruction class.
    start = text.index("class Instruction:")
    end = text.index("class Payment:", start)
    block = text[start:end]
    block = replace_once(block, "    received_at: datetime", "    received_at: datetime\n    # Actual source-system entry time; it may be later than customer receipt.\n    recorded_at: datetime | None = None", "instruction recorded_at")
    text = text[:start] + block + text[end:]
    text = replace_once(
        text,
        '    absent_fields: set[str] = field(default_factory=set)   # canonical columns the source system does not supply at all',
        '    absent_fields: set[str] = field(default_factory=set)   # canonical columns the source system does not supply at all\n'
        '    feed_quality: dict[str, dict] = field(default_factory=dict)\n'
        '    degraded_feeds: set[str] = field(default_factory=set)',
        "dataset feed health fields",
    )
    return text


def transform_mapping(text: str) -> str:
    text = replace_once(text, '"instructions": {"received_at"}', '"instructions": {"received_at", "recorded_at"}', "instruction timestamps")
    text = replace_once(
        text,
        '"customers": {"dormant_since", "deceased_flag", "is_sensitive"}',
        '"instructions": {"recorded_at"}, "customers": {"dormant_since", "deceased_flag", "is_sensitive"}',
        "optional recorded_at mapping",
    )
    return text


def transform_ingest(text: str) -> str:
    text = replace_once(text, "from .mapping import Mapping, read_mapped", "from .mapping import OPTIONAL, Mapping, read_mapped", "optional mapping import")
    text = replace_once(
        text,
        '"instructions": ("instruction_id", "customer_id", "kind", "received_at"),',
        '"instructions": ("instruction_id", "customer_id", "kind", "received_at", "recorded_at"),',
        "instruction feed schema",
    )
    text = replace_once(text, '    absent_fields: list[str] = field(default_factory=list)', '    absent_fields: list[str] = field(default_factory=list)\n    feed_health: dict[str, dict] = field(default_factory=dict)', "data quality feed health")
    text = replace_once(
        text,
        '"ts_format_failures": self.ts_format_failures, "absent_fields": self.absent_fields}',
        '"ts_format_failures": self.ts_format_failures, "absent_fields": self.absent_fields,\n                "feed_health": self.feed_health}',
        "data quality serialization",
    )
    text = replace_once(
        text,
        'missing = [c for c in SPEC[name] if c not in (reader.fieldnames or [])]',
        'missing = [c for c in SPEC[name] if c not in (reader.fieldnames or []) and c not in OPTIONAL.get(name, set())]',
        "canonical optional column check",
    )
    text = replace_once(
        text,
        '        return list(enumerate(reader, start=2))',
        '''        rows = []
        for line, row in enumerate(reader, start=2):
            for column in OPTIONAL.get(name, set()):
                row.setdefault(column, "")
            rows.append((line, row))
        return rows''',
        "normalise missing optional columns",
    )
    text = replace_once(
        text,
        'ds.staff[s] = Staff(s, r["status"].strip().lower(), r["role"].strip(), r["branch"].strip(), _opt_ts(r["end_date"], q), ps.ref("cus", r["salary_account"]))',
        'ds.staff[s] = Staff(s, r["status"].strip().lower(), r["role"].strip(), r["branch"].strip(), _opt_ts(r["end_date"], q), ps.ref("bank_account", r["salary_account"]))',
        "salary account identity namespace",
    )
    text = replace_once(
        text,
        'ds.instructions.append(Instruction(r["instruction_id"].strip(), c, r["kind"].strip().lower(), _ts(r["received_at"], q)))',
        'ds.instructions.append(Instruction(r["instruction_id"].strip(), c, r["kind"].strip().lower(), _ts(r["received_at"], q), _opt_ts(r["recorded_at"], q)))',
        "instruction timestamps ingestion",
    )
    text = replace_once(
        text,
        'ds.payments.append(Payment(r["payment_id"].strip(), _ts(r["ts"], q), c, r["channel"].strip().lower(), _amount(r["amount"]), ps.ref("cus", r["beneficiary"])))',
        'ds.payments.append(Payment(r["payment_id"].strip(), _ts(r["ts"], q), c, r["channel"].strip().lower(), _amount(r["amount"]), ps.ref("bank_account", r["beneficiary"])))',
        "payment beneficiary identity namespace",
    )
    old_post = 'ds.postings.append(Posting(r["posting_id"].strip(), _ts(r["ts"], q), r["ledger"].strip().upper(), ps.ref("cus", r["counter_party"]), _amount(r["amount"]), ent, ps.ref("acc", r["approved_by_account"]), _bool(r["manual"]), r["narrative"].strip().upper()))'
    new_post = '''ledger = r["ledger"].strip().upper()
        # Payroll counterparties are destination bank accounts; suspense/dispute
        # counterparties are customer/CIF references in the current model.
        counter_kind = "bank_account" if ledger == "PAYROLL" else "cus"
        counter_ref = ps.ref(counter_kind, r["counter_party"])
        ds.postings.append(Posting(r["posting_id"].strip(), _ts(r["ts"], q), ledger, counter_ref, _amount(r["amount"]), ent, ps.ref("acc", r["approved_by_account"]), _bool(r["manual"]), r["narrative"].strip().upper()))'''
    text = replace_once(text, old_post, new_post, "ledger-specific counterparty namespace")
    quality_block = '''    # A feed file can exist while a material part of it is unusable. Reflect
    # rejected rows, unmapped codes and timestamp failures in detector coverage.
    for feed, total in q.rows_read.items():
        rejected = q.rows_rejected.get(feed, 0)
        unmapped = sum(q.unmapped_values.get(feed, {}).values())
        ts_failures = q.ts_format_failures.get(feed, 0)
        rejection_rate = rejected / total if total else 0.0
        degraded = rejection_rate >= 0.05 or unmapped > 0 or ts_failures > 0
        feed_key = FEED_KEY[feed]
        q.feed_health[feed] = {
            "rows_read": total,
            "rows_rejected": rejected,
            "rejection_rate": round(rejection_rate, 4),
            "unmapped_values": unmapped,
            "timestamp_failures": ts_failures,
            "status": "degraded" if degraded else "ready",
        }
        ds.feed_quality[feed_key] = q.feed_health[feed]
        if degraded:
            ds.degraded_feeds.add(feed_key)
            q.notes.append(
                f"{feed}: feed coverage is DEGRADED ({rejected}/{total} rejected rows, "
                f"{unmapped} unmapped values, {ts_failures} timestamp failures)."
            )

'''
    text = replace_once(text, '    ds.absent_fields = set(q.absent_fields)', quality_block + '    ds.absent_fields = set(q.absent_fields)', "feed quality calculation")
    return text


INSTRUCTION_NEAR = '''def instruction_near(ds: Dataset, rules: Rules, customer: str, ts: datetime, kinds: frozenset[str] | None = None):
    window = timedelta(hours=rules.instruction_window_hours)
    for instruction in ds.instructions_by_customer.get(customer, []):
        # received_at is the time the customer supplied the instruction.
        # recorded_at is source-system entry time and cannot retroactively
        # authorise an earlier operation.
        age = ts - instruction.received_at
        if (kinds is None or instruction.kind in kinds) and timedelta(0) <= age <= window:
            return instruction
    return None
'''

ACCOUNT_LIFECYCLE = '''class AccountLifecycle(_Provider):
    name = "account_lifecycle"
    requires = frozenset({"audit", "customers", "instructions"})
    KINDS = frozenset({"reactivation", "account_reactivation"})

    def run(self, f: Focus) -> list[Evidence]:
        ds, r = self.ds, self.rules
        events = [e for e in ds.events_by_customer.get(f.customer_ref, [])
                  if e.action == "account_reactivate" and ds.staff_of(e.account_ref) == f.staff_ref]
        customer = ds.customers.get(f.customer_ref)
        if not events or not customer:
            return []
        event = events[0]
        dormant = customer.status == "dormant" or (customer.dormant_since is not None and customer.dormant_since <= event.ts)
        if not dormant:
            return []

        refs = [f"audit_log:{event.row}"]
        out = []
        if customer.deceased_flag:
            out.append(_ev("Customer master", "customer_master", "customer_master", "risk",
                           "A dormant account flagged as belonging to a deceased customer was reactivated.",
                           "Deceased and dormant accounts are a repeat target in public insider cases.",
                           4, 0.9, 0.85, event.ts,
                           ["The flag depends on the death record having reached the bank."], f.label(), refs))

        instruction = instruction_near(ds, r, f.customer_ref, event.ts, self.KINDS)
        if instruction:
            out.append(_ev("Customer instruction register", "customer_instruction", "customer_instruction", "support",
                           "Reactivation is backed by a customer instruction received before the operation.",
                           "A documented prior request is the normal basis for reactivation.",
                           3, 0.9, 0.85, instruction.received_at,
                           ["Instruction authenticity was not independently verified."], f.label(),
                           refs + [f"instructions:{instruction.instruction_id}"]))
        else:
            out.append(_ev("Customer instruction register", "customer_instruction", "customer_instruction", "risk",
                           "Dormant account reactivated with no matching prior customer instruction.",
                           "Account-state changes are a high-risk step that payment monitoring never sees.",
                           4, 0.9, 0.8, event.ts,
                           ["An instruction entered after the operation is not proof of prior authorisation."], f.label(), refs))

        approver_staff = ds.staff_of(event.approver_ref)
        if "audit_log.approver_account_id" in ds.absent_fields:
            out.append(_ev("Approval records", "approvals", "bank_audit_log", "context",
                           "This system supplies no approver on audit events, so maker-checker could not be assessed.",
                           "Absence of an approver field is not evidence of an unapproved action.",
                           1, 0.5, 0.5, event.ts, ["Supply the approver field to enable this check."], f.label(), refs))
        elif event.approver_ref is None:
            out.append(_ev("Approval records", "approvals", "bank_audit_log", "risk",
                           "No approver is recorded for the reactivation.",
                           "Maker-checker is the control meant to catch a single actor.",
                           3, 0.85, 0.8, event.ts, ["Approval may be recorded in a system not supplied."], f.label(), refs))
        elif approver_staff == f.staff_ref:
            out.append(_ev("Approval records", "approvals", "bank_audit_log", "risk",
                           "The reactivation was approved from the same staff member's account.",
                           "Self-approval defeats maker-checker.", 3, 0.9, 0.85, event.ts, [], f.label(), refs))
        elif approver_staff is None:
            out.append(_ev("Approval identity mapping", "approval_identity_mapping", "bank_audit_log", "context",
                           "An approver account is recorded but cannot be mapped to a staff identity.",
                           "The approval identity and authority are unknown; it must not be counted as independent approval.",
                           1, 0.5, 0.5, event.ts,
                           ["Resolve the approver account against the authoritative IAM/HR source."], f.label(), refs))
        else:
            out.append(_ev("Approval records", "approvals", "bank_audit_log", "context",
                           "An approver account mapped to a different staff identity is recorded.",
                           "A different staff identity does not establish authority, delegation, reporting-line independence or absence of collusion.",
                           1, 0.6, 0.6, event.ts,
                           ["Validate the approver against the bank's role and delegated-authority matrix."], f.label(), refs))
        return out
'''

CHANGE_THEN_MONEY = '''class ChangeThenMoney(_Provider):
    name = "change_then_money"
    requires = frozenset({"audit", "payments", "instructions"})
    INSTRUCTION_KINDS = {
        "contact_change": frozenset({"contact_change", "mobile_change"}),
        "mobile_change": frozenset({"contact_change", "mobile_change"}),
        "card_issue": frozenset({"card_issue", "card_request"}),
        "beneficiary_add": frozenset({"beneficiary_add", "beneficiary_change", "payee_add"}),
        "limit_change": frozenset({"limit_change", "limit_update"}),
        "account_reactivate": frozenset({"reactivation", "account_reactivation"}),
    }

    def run(self, f: Focus) -> list[Evidence]:
        ds, r = self.ds, self.rules
        changes = [e for e in ds.events_by_customer.get(f.customer_ref, [])
                   if e.action in SENSITIVE_ACTIONS and ds.staff_of(e.account_ref) == f.staff_ref]
        if not changes:
            return []

        # Match each operation to its own instruction type. One valid contact
        # instruction must not explain a separate card or beneficiary action.
        unexplained = [
            event for event in changes
            if not instruction_near(
                ds, r, f.customer_ref, event.ts,
                self.INSTRUCTION_KINDS.get(event.action, frozenset({event.action})),
            )
        ]
        if not unexplained:
            return []

        trigger = min(unexplained, key=lambda event: event.ts)
        after = [payment for payment in ds.payments_by_customer.get(f.customer_ref, [])
                 if trigger.ts <= payment.ts <= trigger.ts + timedelta(days=r.sequence_days)]
        if not after:
            return []

        total = sum(payment.amount for payment in after)
        return [_ev(
            "Payment and ATM feed", "payments", "payment_record", "risk",
            f"{len(changes)} sensitive change(s) by one user, at least one without a matching prior customer instruction, were followed by {len(after)} payments associated with the same customer (KSh {total:,}) within {r.sequence_days} days.",
            "A payment sequence following an unexplained account change merits review; this customer-level correlation does not prove that funds went to a newly added beneficiary.",
            4, 0.9, 0.75, after[0].ts,
            ["A sequence is a lead, not proof; the customer may have made the payments."], f.label(),
            [f"audit_log:{event.row}" for event in changes[:5]] + [f"payments:{payment.payment_id}" for payment in after[:5]],
        )]
'''

POSTING_INTEGRITY = '''class PostingIntegrity(_Provider):
    name = "suspense_posting_integrity"
    applies = "staff"
    requires = frozenset({"postings"})
    requires_fields = frozenset({"postings.approved_by_account"})

    def run(self, f: Focus) -> list[Evidence]:
        ds, r = self.ds, self.rules
        posts = [p for p in ds.postings_by_staff.get(f.staff_ref, [])
                 if p.manual and p.ledger in SUSPENSE_LEDGERS]
        if not posts:
            return []

        missing_approval = [p for p in posts if p.approved_by_ref is None]
        unresolved_approval = [p for p in posts if p.approved_by_ref is not None and ds.staff_of(p.approved_by_ref) is None]
        self_approved = [p for p in posts if p.approved_by_ref is not None and ds.staff_of(p.approved_by_ref) == f.staff_ref]
        failing = missing_approval + self_approved
        refs = [f"postings:{p.posting_id}" for p in (failing + unresolved_approval + posts)[:8]]

        if not failing:
            if unresolved_approval:
                return [_ev("Ledger approval mapping", "ledger_approval_mapping", "ledger_record", "context",
                            f"{len(unresolved_approval)} of {len(posts)} manual suspense/dispute postings have approver IDs that could not be mapped to a staff identity.",
                            "The approver's identity and authority could not be established; this is not evidence of independent approval.",
                            1, 0.5, 0.5, unresolved_approval[0].ts,
                            ["Resolve the approver account against the authoritative IAM/HR source before assessing maker-checker."],
                            f.label(), [f"postings:{p.posting_id}" for p in unresolved_approval[:8]])]
            return [_ev("Ledger approval records", "ledger_approval_mapping", "ledger_record", "context",
                        f"All {len(posts)} manual suspense/dispute postings have an approver account mapped to a different staff identity.",
                        "A different staff identity is recorded, but role authority, delegation, reporting-line conflicts and collusion were not checked.",
                        1, 0.6, 0.6, posts[0].ts,
                        ["Do not treat a different staff ID as proof that the approver was authorised or independent."], f.label(), refs)]

        total = sum(p.amount for p in failing)
        out = [_ev("Ledger", "ledger", "ledger_record", "risk",
                   f"{len(failing)} of {len(posts)} manual postings out of suspense/dispute ledgers (KSh {total:,}) were unapproved or self-approved.",
                   "Suspense and dispute accounts hold money awaiting resolution and recur across insider cases.",
                   4, 0.9, 0.85, failing[0].ts,
                   ["Approval may be recorded outside the supplied ledger extract."], f.label(), refs)]

        if unresolved_approval:
            out.append(_ev("Ledger approval mapping", "ledger_approval_mapping", "ledger_record", "context",
                           f"{len(unresolved_approval)} additional postings have approver IDs that could not be mapped to a staff identity.",
                           "Their approval independence and authority remain unknown.", 1, 0.5, 0.5, unresolved_approval[0].ts,
                           ["Resolve approver IDs against the authoritative IAM/HR source."], f.label(),
                           [f"postings:{p.posting_id}" for p in unresolved_approval[:8]]))

        # This follow-on join is valid only where counter_party is mapped to a
        # customer/CIF. Bank-account contra fields need an authoritative bridge.
        window = timedelta(days=r.posting_followon_days)
        moved = [(p, q) for p in failing for q in ds.payments_by_customer.get(p.counter_ref or "", [])
                 if p.ts <= q.ts <= p.ts + window]
        if moved:
            out.append(_ev("Payment and ATM feed", "payments", "payment_record", "risk",
                           f"Payments were recorded against customer/CIF references within {r.posting_followon_days} days of {len({p.posting_id for p, _ in moved})} flagged postings.",
                           "Rapid onward movement may be relevant, but the customer/CIF join is not proof of account-level fund tracing.",
                           4, 0.9, 0.75, moved[0][1].ts,
                           ["Confirm the posting counterparty and payment account relationship from an authoritative account master."],
                           f.label(), [f"payments:{q.payment_id}" for _, q in moved[:6]]))
        return out
'''


def transform_scenarios(text: str) -> str:
    start = text.index("def instruction_near(")
    end = text.index("class _Provider:", start)
    text = text[:start] + INSTRUCTION_NEAR + "\n\n\n" + text[end:]
    text = replace_once(text, 'if e.action == "contact_change" and ds.staff_of(e.account_ref) == f.staff_ref]',
                        'if e.action in {"contact_change", "mobile_change"} and ds.staff_of(e.account_ref) == f.staff_ref]',
                        "mobile-change event detection")
    text = replace_class(text, "AccountLifecycle(_Provider)", "ChangeThenMoney(_Provider)", ACCOUNT_LIFECYCLE)
    text = replace_class(text, "ChangeThenMoney(_Provider)", "PostingIntegrity(_Provider)", CHANGE_THEN_MONEY)
    text = replace_class(text, "PostingIntegrity(_Provider)", "PayrollBeneficiary(_Provider)", POSTING_INTEGRITY)
    return text


def transform_coverage(text: str) -> str:
    block = '''    detector_feeds = {
        "access_justification": {"audit", "assignments", "crm"},
        "bulk_unjustified_browsing": {"audit", "assignments", "crm"},
        "auth_channel_change": {"audit", "instructions"},
        "account_lifecycle": {"audit", "customers", "instructions"},
        "change_then_money": {"audit", "payments", "instructions"},
        "suspense_posting_integrity": {"postings", "payments"},
        "payroll_beneficiary_integrity": {"postings", "hr"},
        "entitlement_integrity": {"accounts", "hr"},
    }
    for row in rows:
        affected = sorted(detector_feeds.get(row["detector"], set()) & ds.degraded_feeds)
        if affected and row["status"] != "blind":
            row["status"] = "degraded"
            row["reason"] += "; input quality degraded for: " + ", ".join(affected)
'''
    return replace_once(text, '    return rows', block + '    return rows', "coverage feed quality downgrade")


def transform_replay(text: str) -> str:
    text = replace_once(text, '    def instruction(self, cust, kind, ts):', '    def instruction(self, cust, kind, ts, recorded_at=None):', "synthetic instruction signature")
    text = replace_once(
        text,
        'self.rows["instructions"].append({"instruction_id": f"I{self.n[\'ins\']:06d}", "customer_id": cust, "kind": kind, "received_at": _t(ts)})',
        'self.rows["instructions"].append({"instruction_id": f"I{self.n[\'ins\']:06d}", "customer_id": cust, "kind": kind,\n                                           "received_at": _t(ts), "recorded_at": _t(recorded_at) if recorded_at else ""})',
        "synthetic instruction recorded_at field",
    )
    text = replace_once(text, '        after = k < 5   # hard negative: instruction logged AFTER the change (still inside the 48h window)\n'
                        '        b.instruction(c, "contact_change", ts + timedelta(hours=rng.randint(10, 36)) if after else ts - timedelta(hours=rng.randint(1, 30)))',
                        '        after = k < 5   # hard negative: instruction is entered into the system AFTER the change\n'
                        '        received = ts - timedelta(hours=rng.randint(1, 30))\n'
                        '        recorded = ts + timedelta(hours=rng.randint(10, 36)) if after else received\n'
                        '        b.instruction(c, "contact_change", received, recorded_at=recorded)',
                        "synthetic delayed-entry instruction fixture")
    return text


def transform_foreign(text: str) -> str:
    text = replace_once(text,
        '"instructions": {"instruction_id": "INSTR_REF", "customer_id": "CIF_NO", "kind": "INSTR_TYPE", "received_at": "RECV_TS"}',
        '"instructions": {"instruction_id": "INSTR_REF", "customer_id": "CIF_NO", "kind": "INSTR_TYPE", "received_at": "RECV_TS", "recorded_at": "ENTRY_TS"}',
        "foreign style A recorded_at")
    text = replace_once(text,
        '"instructions": {"instruction_id": "instr_no", "customer_id": "client_no", "kind": "instr_kind", "received_at": "received_epoch"}',
        '"instructions": {"instruction_id": "instr_no", "customer_id": "client_no", "kind": "instr_kind", "received_at": "received_epoch", "recorded_at": "entered_epoch"}',
        "foreign style B recorded_at")
    return text


def transform_ingest_tests(text: str) -> str:
    text = replace_once(text,
        '    assert a.ref("stf", "S1") == a.ref("stf", "S1") != a.ref("cus", "S1") != b.ref("stf", "S1")',
        '    assert a.ref("stf", "S1") == a.ref("stf", "S1") != a.ref("cus", "S1") != b.ref("stf", "S1")\n'
        '    assert a.ref("bank_account", "S1") != a.ref("cus", "S1")\n'
        '    assert len(a.ref("bank_account", "S1").split("-", 1)[1]) == 32\n'
        '    assert a.ref("bank_account", "S1") == a.ref("bank_account", "S1")',
        "pseudonym regression tests")
    text += '''


def test_rejected_rows_and_unmapped_codes_degrade_feed_health(tmp_path):
    f = base_feeds()
    f["audit_log"] = [
        {"ts": ts(hours=i), "account_id": "A-S2", "action": "profile_view", "customer_id": "C-X"}
        for i in range(18)
    ] + [
        {"ts": "not-a-date", "account_id": "A-S2", "action": "profile_view", "customer_id": "C-X"}
        for _ in range(2)
    ]
    ds, q, _, _ = scan(tmp_path, f)
    assert q.feed_health["audit_log"]["status"] == "degraded"
    assert q.feed_health["audit_log"]["rejection_rate"] == 0.1
    assert "audit" in ds.degraded_feeds
    from toroka_enterprise.coverage import coverage_report
    coverage = {row["detector"]: row for row in coverage_report(ds)}
    assert coverage["access_justification"]["status"] == "degraded"
'''
    return text


def transform_scenario_tests(text: str) -> str:
    text = replace_once(text, 'from toroka_enterprise.scenarios import Rules',
                        'from toroka_enterprise.scenarios import Rules, AuthChannelChange, Focus, PostingIntegrity',
                        "scenario test imports")
    text = replace_once(text,
        'f["instructions"] = [{"instruction_id": "I1", "customer_id": "C-X", "kind": "contact_change", "received_at": ts(hours=-2)}]',
        'f["instructions"] = [{"instruction_id": "I1", "customer_id": "C-X", "kind": "contact_change", "received_at": ts(hours=-2)},\n'
        '                              {"instruction_id": "I2", "customer_id": "C-X", "kind": "card_issue", "received_at": ts(hours=-2)}]',
        "valid matching instructions for each OTP change")
    text += '''


def test_instruction_received_after_operation_does_not_retroactively_authorise_it(tmp_path):
    f = base_feeds()
    f["audit_log"] = [{"ts": ts(), "account_id": "A-S2", "action": "contact_change", "customer_id": "C-X"}]
    f["instructions"] = [{"instruction_id": "I-LATE", "customer_id": "C-X", "kind": "contact_change",
                          "received_at": ts(hours=1), "recorded_at": ts(hours=2)}]
    ds, _, _, ps = scan(tmp_path, f)
    evs = AuthChannelChange(ds, Rules()).run(Focus(ps.ref("stf", "S2"), ps.ref("cus", "C-X")))
    assert any(e.polarity == "risk" for e in evs)


def test_unresolved_approver_is_context_not_independent_approval(tmp_path):
    f = base_feeds()
    f["postings"] = [{"posting_id": "L-UNKNOWN", "ts": ts(), "ledger": "SUSPENSE", "counter_party": "C-X",
                      "amount": "10000", "entered_by_account": "A-S1", "approved_by_account": "A-NOT-IN-ACCOUNT-FEED",
                      "manual": "true", "narrative": "OTHER"}]
    ds, _, _, ps = scan(tmp_path, f)
    evs = PostingIntegrity(ds, Rules()).run(Focus(ps.ref("stf", "S1")))
    assert evs and all(e.polarity == "context" for e in evs)
    assert any("could not be mapped" in e.summary for e in evs)
'''
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="validate all expected source anchors without writing")
    args = parser.parse_args()

    expected_root = ROOT / "packages/enterprise/toroka_enterprise"
    if not expected_root.is_dir():
        print("Run this script from the Toroka repository root (packages/enterprise was not found).", file=sys.stderr)
        return 2

    transforms = {
        "packages/enterprise/toroka_enterprise/pseudonym.py": transform_pseudonym,
        "packages/enterprise/toroka_enterprise/schema.py": transform_schema,
        "packages/enterprise/toroka_enterprise/mapping.py": transform_mapping,
        "packages/enterprise/toroka_enterprise/ingest.py": transform_ingest,
        "packages/enterprise/toroka_enterprise/scenarios.py": transform_scenarios,
        "packages/enterprise/toroka_enterprise/coverage.py": transform_coverage,
        "packages/enterprise/toroka_enterprise/replay.py": transform_replay,
        "packages/enterprise/toroka_enterprise/foreign.py": transform_foreign,
        "packages/enterprise/tests/test_ingest_and_pseudonym.py": transform_ingest_tests,
        "packages/enterprise/tests/test_scenarios.py": transform_scenario_tests,
    }

    try:
        updated = {path: transform(read(path)) for path, transform in transforms.items()}
    except Exception as exc:
        print(f"Patch validation failed; no files were changed: {exc}", file=sys.stderr)
        return 1

    if args.check:
        print(f"Patch anchors validated for {len(updated)} files. No files changed.")
        return 0

    backup = ROOT / ".toroka-enterprise-hardening-backup"
    if backup.exists():
        print(f"Backup directory already exists: {backup}. Move it before applying again.", file=sys.stderr)
        return 2
    backup.mkdir()
    try:
        for path in updated:
            destination = backup / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / path, destination)
        for path, content in updated.items():
            write(path, content)
    except Exception:
        for path in updated:
            original = backup / path
            if original.exists():
                shutil.copy2(original, ROOT / path)
        raise

    print(f"Applied Enterprise hardening changes to {len(updated)} files.")
    print(f"Original files backed up to: {backup}")
    print("Next: run `python -m pytest -q packages/enterprise/tests` and the full test suite.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
