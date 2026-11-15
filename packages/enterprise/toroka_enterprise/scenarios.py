"""Scenario providers: each encodes one recurring insider pattern from public cases as an evidence check.



Every provider returns typed Evidence with source_group (independence), record_refs (provenance) and limitations.

Rule hits are observations, not verified facts: nothing here calls anyone guilty.

"""

from __future__ import annotations



from dataclasses import dataclass

from datetime import datetime, timedelta, timezone



from toroka_core.evidence.models import Evidence, InvestigationRequest



from .schema import SENSITIVE_ACTIONS, Dataset



SUSPENSE_LEDGERS = frozenset({"SUSPENSE", "DISPUTE"})





@dataclass(frozen=True, slots=True)

class Focus:

    staff_ref: str

    customer_ref: str | None = None



    def label(self) -> str:

        return f"{self.staff_ref}/{self.customer_ref}" if self.customer_ref else self.staff_ref





@dataclass(frozen=True, slots=True)

class Rules:

    instruction_window_hours: int = 48

    request_grace_days: int = 3

    sequence_days: int = 7

    posting_followon_days: int = 3

    bulk_unjustified_threshold: int = 15

    bulk_window_days: int = 60





def _ev(source: str, group: str, category: str, polarity: str, summary: str, why: str, strength: int,

        reliability: float, confidence: float, at: datetime, limits: list[str], subject: str, refs: list[str]) -> Evidence:

    return Evidence(source=source, source_group=group, category=category, polarity=polarity, summary=summary,

                    why_it_matters=why, strength=strength, reliability=reliability, confidence=confidence,

                    subject=subject, observed_at=at, verified=False, limitations=limits, metadata={"record_refs": refs})





def justified_by_request(ds: Dataset, rules: Rules, staff: str, customer: str, ts: datetime):

    grace = timedelta(days=rules.request_grace_days)

    for r in ds.requests_by_customer.get(customer, []):

        if r.staff_ref == staff and r.opened_at <= ts and (r.closed_at is None or r.closed_at + grace >= ts):

            return r

    return None





def instruction_near(ds: Dataset, rules: Rules, customer: str, ts: datetime, kinds: frozenset[str] | None = None):
    window = timedelta(hours=rules.instruction_window_hours)
    for instruction in ds.instructions_by_customer.get(customer, []):
        # received_at is the time the customer supplied the instruction.
        # recorded_at is source-system entry time and cannot retroactively
        # authorise an earlier operation.
        age = ts - instruction.received_at
        if (kinds is None or instruction.kind in kinds) and timedelta(0) <= age <= window:
            return instruction
    return None



class _Provider:

    name = "base"

    requires: frozenset[str] = frozenset()

    requires_fields: frozenset[str] = frozenset()   # canonical columns that must be supplied (not merely non-empty)

    applies = "pair"   # pair = (staff, customer) focus; staff = staff-level focus



    def __init__(self, ds: Dataset, rules: Rules):

        self.ds, self.rules = ds, rules



    @property

    def is_configured(self) -> bool:

        return self.requires <= self.ds.available and not (self.requires_fields & self.ds.absent_fields)



    def investigate(self, request: InvestigationRequest) -> list[Evidence]:

        return self.run(request.context["focus"])



    def run(self, focus: Focus) -> list[Evidence]:  # pragma: no cover

        raise NotImplementedError





class AccessJustification(_Provider):

    name = "access_justification"

    requires = frozenset({"audit", "assignments"})



    def run(self, f: Focus) -> list[Evidence]:

        ds, r = self.ds, self.rules

        evs = [e for e in ds.events_by_customer.get(f.customer_ref, []) if ds.staff_of(e.account_ref) == f.staff_ref]

        if not evs:

            return []

        first, refs, cust = evs[0], [f"audit_log:{e.row}" for e in evs[:5]], ds.customers.get(f.customer_ref)

        if f.customer_ref in ds.assignments.get(f.staff_ref, set()):

            return [_ev("HR/portfolio assignments", "hr_portfolio", "hr_record", "support",

                        "Customer is in the staff member's assigned portfolio.",

                        "An assignment is a legitimate reason to open a profile. It does not justify every change.",

                        2, 0.85, 0.85, first.ts, ["Assignment data may be stale."], f.label(), refs)]

        if ds.branch_of(f.staff_ref) in ds.crm_gap_branches:

            return [_ev("CRM service records", "crm", "service_record", "context",

                        "Access justification could not be assessed: service-request data is incomplete for this branch.",

                        "Missing tickets prove nothing where the CRM is not integrated.", 1, 0.5, 0.5, first.ts,

                        ["Resolve the CRM integration gap before treating unticketed access as a signal."], f.label(), refs)]

        req = justified_by_request(ds, r, f.staff_ref, f.customer_ref, first.ts)

        if req:

            return [_ev("CRM service records", "crm", "service_record", "support",

                        "Access is explained by an open service request assigned to the same staff member.",

                        "An independent record gives a legitimate explanation. It lowers, not erases, concern.",

                        3, 0.85, 0.85, req.opened_at, ["Request content was not inspected."], f.label(), refs + [f"service_requests:{req.request_id}"])]

        strength = 4 if (cust and cust.is_sensitive) else 3

        sens = " The profile is flagged sensitive." if strength == 4 else ""

        return [_ev("Core banking audit log", "core_banking_audit", "bank_audit_log", "risk",

                    "Customer profile opened with no assignment and no matching service request." + sens,

                    "Business-purpose access is the control that catches snooping and data-selling insiders.",

                    strength, 0.9, 0.8, first.ts, ["Assignment data may be stale; a missing CRM link can be an integration gap."], f.label(), refs)]





class BulkBrowsing(_Provider):

    name = "bulk_unjustified_browsing"

    applies = "staff"

    requires = frozenset({"audit", "assignments"})



    def run(self, f: Focus) -> list[Evidence]:

        ds, r = self.ds, self.rules

        port = ds.assignments.get(f.staff_ref, set())

        unj = [(e.ts, e.customer_ref, e.row) for e in ds.events_by_staff.get(f.staff_ref, [])

               if e.action == "profile_view" and e.customer_ref and e.customer_ref not in port

               and not justified_by_request(ds, r, f.staff_ref, e.customer_ref, e.ts)]

        best, best_win = 0, []

        for i, (ts, _c, _r) in enumerate(unj):

            win = [x for x in unj[i:] if x[0] <= ts + timedelta(days=r.bulk_window_days)]

            n = len({x[1] for x in win})

            if n > best:

                best, best_win = n, win

        if best < r.bulk_unjustified_threshold:

            return []

        refs = [f"audit_log:{x[2]}" for x in best_win[:8]]

        if ds.branch_of(f.staff_ref) in ds.crm_gap_branches:

            return [_ev("CRM service records", "crm", "service_record", "context",

                        f"{best} unassigned profiles were opened, but service-request data is incomplete for this branch.",

                        "Cannot separate snooping from unrecorded walk-in service.", 1, 0.5, 0.5, best_win[0][0],

                        ["Resolve the CRM integration gap first."], f.label(), refs)]

        sensitive = sum(1 for c in {x[1] for x in best_win} if ds.customers.get(c) and ds.customers[c].is_sensitive)

        strength = 4 if (sensitive or best >= 3 * r.bulk_unjustified_threshold) else 3

        extra = f" {sensitive} are flagged sensitive." if sensitive else ""

        return [_ev("Core banking audit log", "core_banking_audit", "bank_audit_log", "risk",

                    f"{best} customer profiles outside the portfolio and without a matching service request were opened within {r.bulk_window_days} days.{extra}",

                    "Volume of unjustified lookups is the pattern behind data-selling and curiosity-access cases.",

                    strength, 0.9, 0.8, best_win[0][0], ["Roles with broad legitimate reach (e.g. branch managers) need portfolio data that reflects it."], f.label(), refs)]





class AuthChannelChange(_Provider):

    name = "auth_channel_change"

    requires = frozenset({"audit", "instructions"})

    KINDS = frozenset({"contact_change", "mobile_change"})



    def run(self, f: Focus) -> list[Evidence]:

        ds, r = self.ds, self.rules

        evs = [e for e in ds.events_by_customer.get(f.customer_ref, [])

               if e.action in {"contact_change", "mobile_change"} and ds.staff_of(e.account_ref) == f.staff_ref]

        if not evs:

            return []

        unbacked = [e for e in evs if not instruction_near(ds, r, f.customer_ref, e.ts, self.KINDS)]

        if unbacked:

            e = unbacked[0]

            return [_ev("Customer instruction register", "customer_instruction", "customer_instruction", "risk",

                        "Registered contact details changed with no matching customer instruction.",

                        "Changing where authentication messages are delivered is the highest-risk account event.",

                        4, 0.9, 0.8, e.ts, ["The instruction may be held offline and not yet digitised."], f.label(), [f"audit_log:{e.row}"])]

        e = evs[0]

        i = instruction_near(ds, r, f.customer_ref, e.ts, self.KINDS)

        return [_ev("Customer instruction register", "customer_instruction", "customer_instruction", "support",

                    "Registered contact change is backed by a customer instruction on file.",

                    "Instruction-to-change matching is the cheapest check on authentication-redirection fraud.",

                    3, 0.9, 0.85, i.received_at, ["Instruction authenticity was not independently verified."], f.label(),

                    [f"audit_log:{e.row}", f"instructions:{i.instruction_id}"])]





class AccountLifecycle(_Provider):
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


class ChangeThenMoney(_Provider):
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


class PostingIntegrity(_Provider):
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


class PayrollBeneficiary(_Provider):

    name = "payroll_beneficiary_integrity"

    applies = "staff"

    requires = frozenset({"postings", "hr"})

    requires_fields = frozenset({"hr_roster.salary_account"})      # without it every salary posting would look like a non-employee



    def run(self, f: Focus) -> list[Evidence]:

        ds = self.ds

        bad = [p for p in ds.postings_by_staff.get(f.staff_ref, [])

               if p.manual and p.narrative == "SALARY" and p.counter_ref not in ds.roster_salary_accounts]

        if not bad:

            return []

        total = sum(p.amount for p in bad)

        return [_ev("HR roster", "hr_roster", "hr_record", "risk",

                    f"{len(bad)} manual salary postings (KSh {total:,}) went to accounts that match no employee on the HR roster.",

                    "Payments disguised as salary to non-employees match the alleged salary-ledger diversion pattern.",

                    4, 0.9, 0.8, bad[0].ts,

                    ["Contractors, former staff final pay and garnishee payments can legitimately be absent from the roster."], f.label(),

                    [f"postings:{p.posting_id}" for p in bad[:8]])]





class EntitlementIntegrity(_Provider):

    name = "entitlement_integrity"

    applies = "staff"

    requires = frozenset({"accounts"})



    def run(self, f: Focus) -> list[Evidence]:

        ds, out = self.ds, []

        accs = [ds.accounts[a] for a in ds.accounts_by_staff.get(f.staff_ref, []) if ds.accounts[a].status == "active"]

        by_system: dict[str, list] = {}

        for a in accs:

            by_system.setdefault(a.system, []).append(a)

        for system, group in by_system.items():

            if len(group) < 2:

                continue

            refs = [f"system_accounts:{a.account_ref}" for a in group]

            fallback_ts = ds.events[0].ts if ds.events else datetime.now(timezone.utc)

            at = ds.events_by_staff[f.staff_ref][0].ts if ds.events_by_staff.get(f.staff_ref) else fallback_ts

            if sum(1 for a in group if a.is_privileged) == 1:

                out.append(_ev("IAM", "iam_hr", "iam_record", "context", f"Two active {system} profiles: one standard, one privileged.",

                               "A separate admin profile is a common legitimate pattern.", 1, 0.7, 0.7, at,

                               ["Confirm the privileged profile is approved."], f.label(), refs))

            else:

                out.append(_ev("IAM", "iam_hr", "iam_record", "risk", f"{len(group)} active {system} profiles are linked to one staff identity.",

                               "Duplicate profiles let one person act as two, which undermines segregation of duties.", 3, 0.9, 0.8, at,

                               ["Shared-role or migration artefacts can create duplicates."], f.label(), refs))

        s = ds.staff.get(f.staff_ref)

        if "hr" in ds.available and s and s.status == "terminated" and s.end_date:

            after = [e for e in ds.events_by_staff.get(f.staff_ref, []) if e.ts > s.end_date]

            if after:

                out.append(_ev("HR roster and audit log", "iam_hr", "iam_record", "risk",

                               f"{len(after)} audit events occurred after the recorded employment end date.",

                               "Activity by a leaver's account is either an access-removal failure or credential misuse.", 4, 0.9, 0.85, after[0].ts,

                               ["The end date may be entered late; confirm with HR before drawing conclusions."], f.label(), [f"audit_log:{e.row}" for e in after[:6]]))

        return out





def build_providers(ds: Dataset, rules: Rules) -> tuple[list[_Provider], list[_Provider]]:

    all_providers = [AccessJustification(ds, rules), BulkBrowsing(ds, rules), AuthChannelChange(ds, rules),

                     AccountLifecycle(ds, rules), ChangeThenMoney(ds, rules), PostingIntegrity(ds, rules),

                     PayrollBeneficiary(ds, rules), EntitlementIntegrity(ds, rules)]

    return [p for p in all_providers if p.applies == "pair"], [p for p in all_providers if p.applies == "staff"]

