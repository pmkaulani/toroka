"""Detector coverage: what can this bank's data actually let each detector see?

This is the honest answer to 'does it work on any system': it works to the extent the system exposes the events and fields a detector
needs. Statuses: ready | degraded (runs with reduced strength) | check (data present but no relevant events: a mapping gap or a
quiet period) | blind (cannot run: feed or field missing).
"""
from __future__ import annotations

from collections import Counter

from .scenarios import SUSPENSE_LEDGERS
from .schema import SENSITIVE_ACTIONS, Dataset


def coverage_report(ds: Dataset) -> list[dict]:
    acts = Counter(e.action for e in ds.events)
    av, absent = ds.available, ds.absent_fields
    rows: list[dict] = []

    def add(name, status, reason, needs):
        rows.append({"detector": name, "status": status, "reason": reason, "needs": needs})

    def need(feeds=(), fields=()):
        miss = [f for f in feeds if f not in av] + [f for f in fields if f in absent]
        return miss

    def count_note(action):
        return f"{acts.get(action, 0):,} '{action}' events"

    miss = need(["audit", "assignments"])
    if miss:
        add("access_justification", "blind", "missing feed(s): " + ", ".join(miss), ["audit_log", "portfolio"])
    elif not any(e.customer_ref for e in ds.events):
        add("access_justification", "check", "no audit events reference a customer", ["audit_log.customer_id"])
    elif "crm" not in av or "service_requests.staff_id" in absent:
        add("access_justification", "degraded", "no usable CRM tickets: unassigned access can only be shown as context", ["service_requests"])
    else:
        add("access_justification", "ready", count_note("profile_view") + " seen", [])
    add("bulk_unjustified_browsing", *(("blind", "missing feed(s): " + ", ".join(need(["audit", "assignments"]))) if need(["audit", "assignments"])
        else (("check", "no profile_view events: map the bank's enquiry/view codes") if not acts.get("profile_view") else ("ready", count_note("profile_view")))), [])
    m = need(["audit", "instructions"])
    add("auth_channel_change", *(("blind", "missing feed(s): " + ", ".join(m)) if m else (("check", "no contact_change events: map the bank's contact/mobile update codes") if not acts.get("contact_change") else ("ready", count_note("contact_change")))), [])
    m = need(["audit", "customers", "instructions"])
    dormant = sum(1 for c in ds.customers.values() if c.status == "dormant" or c.dormant_since)
    if m:
        add("account_lifecycle", "blind", "missing feed(s): " + ", ".join(m), [])
    elif not acts.get("account_reactivate") or not dormant:
        add("account_lifecycle", "check", f"{acts.get('account_reactivate', 0)} reactivation events, {dormant} dormant customers: map reactivation codes and dormancy", [])
    elif "audit_log.approver_account_id" in absent:
        add("account_lifecycle", "degraded", "no approver on audit events: maker-checker cannot be assessed", ["audit_log.approver_account_id"])
    else:
        add("account_lifecycle", "ready", count_note("account_reactivate"), [])
    m = need(["audit", "payments", "instructions"])
    kinds = sum(1 for a in SENSITIVE_ACTIONS if acts.get(a))
    add("change_then_money", *(("blind", "missing feed(s): " + ", ".join(m)) if m else (("check", f"only {kinds} sensitive action type(s) mapped; the sequence needs at least two") if kinds < 2 else ("ready", f"{kinds} sensitive action types mapped"))), [])
    m = need(["postings"], ["postings.approved_by_account"])
    susp = sum(1 for p in ds.postings if p.manual and p.ledger in SUSPENSE_LEDGERS)
    add("suspense_posting_integrity", *(("blind", "missing: " + ", ".join(m)) if m else (("check", "no manual postings in SUSPENSE/DISPUTE ledgers: map the bank's suspense GL codes") if not susp else ("ready", f"{susp:,} manual suspense/dispute postings"))), [])
    m = need(["postings", "hr"], ["hr_roster.salary_account"])
    sal = sum(1 for p in ds.postings if p.manual and p.narrative == "SALARY")
    add("payroll_beneficiary_integrity", *(("blind", "missing: " + ", ".join(m)) if m else (("check", "no manual SALARY postings: map the payroll narrative/code") if not sal else ("ready", f"{sal:,} manual salary postings"))), [])
    m = need(["accounts"])
    add("entitlement_integrity", *(("blind", "missing feed(s): accounts") if m else (("degraded", "no HR roster: leaver activity cannot be checked") if "hr" not in av else ("ready", f"{len(ds.accounts):,} system accounts"))), [])
    return rows


def render(rows: list[dict]) -> str:
    mark = {"ready": "READY   ", "degraded": "DEGRADED", "check": "CHECK   ", "blind": "BLIND   "}
    return "\n".join(f"  {mark[r['status']]} {r['detector']:30} {r['reason']}" for r in rows)
