"""Detector coverage and readiness engine: what can this bank's data actually let each scenario detector see?

Evaluates detector dependencies from the central data contract registry.
Statuses:
  READY    - All material required feeds and fields are available and usable.
  DEGRADED - Detector can operate, but supporting data is missing or data quality has material issues.
  CHECK    - Feeds and fields are present, but relevant action codes or event types were not observed.
  BLIND    - Material required feed or field is unavailable; cannot assess scenario.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from .data_contract import CONTRACT_VERSION, DETECTOR_DEPENDENCIES
from .ingest import FEED_KEY
from .scenarios import SUSPENSE_LEDGERS
from .schema import SENSITIVE_ACTIONS, Dataset


class ReadinessStatus(str):
    """Case-insensitive string status matching 'ready', 'READY', 'degraded', 'DEGRADED', etc."""

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, str):
            return self.upper() == other.upper()
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(self.upper())


READY = ReadinessStatus("ready")
DEGRADED = ReadinessStatus("degraded")
CHECK = ReadinessStatus("check")
BLIND = ReadinessStatus("blind")


DETECTOR_RUNTIME_FEEDS: dict[str, set[str]] = {
    "access_justification": {"audit", "assignments", "crm"},
    "bulk_unjustified_browsing": {"audit", "assignments", "crm", "customers"},
    "auth_channel_change": {"audit", "instructions", "assignments"},
    "account_lifecycle": {"audit", "customers", "instructions"},
    "change_then_money": {"audit", "payments", "instructions"},
    "suspense_posting_integrity": {"postings", "payments"},
    "payroll_beneficiary_integrity": {"postings", "hr"},
    "entitlement_integrity": {"accounts", "hr", "audit"},
}


def coverage_report(ds: Dataset) -> list[dict[str, Any]]:
    acts = Counter(e.action for e in ds.events)
    av, absent = ds.available, ds.absent_fields
    rows: list[dict[str, Any]] = []

    for dep in DETECTOR_DEPENDENCIES:
        det_id = dep.detector_id

        # 1. Check required feeds
        missing_req_feeds = [f for f in dep.required_feeds if FEED_KEY[f] not in av]

        # 2. Check required fields
        missing_req_fields = [f for f in dep.required_fields if f in absent]

        # 3. Check supporting feeds and fields
        missing_supp_feeds = [f for f in dep.supporting_feeds if FEED_KEY[f] not in av]
        missing_supp_fields = [f for f in dep.supporting_fields if f in absent]

        # 4. Check feed degradation
        detector_feeds = DETECTOR_RUNTIME_FEEDS.get(det_id, {FEED_KEY[f] for f in dep.required_feeds})
        degraded_feeds = sorted(detector_feeds & ds.degraded_feeds)

        remediation_hints: list[str] = []

        if missing_req_feeds or missing_req_fields:
            status = BLIND
            reasons = []
            if missing_req_feeds:
                reasons.append("missing feed(s): " + ", ".join(missing_req_feeds))
                for f in missing_req_feeds:
                    if f in dep.remediation_hints:
                        remediation_hints.append(dep.remediation_hints[f])
            if missing_req_fields:
                reasons.append("missing required field(s): " + ", ".join(missing_req_fields))
                for f in missing_req_fields:
                    if f in dep.remediation_hints:
                        remediation_hints.append(dep.remediation_hints[f])
            explanation = "; ".join(reasons)
            needs = list(missing_req_feeds) + list(missing_req_fields)

        else:
            # Check for CHECK state (data present, but unobserved actions or events)
            check_reason: str | None = None
            needs = []

            if det_id == "access_justification":
                if not any(e.customer_ref for e in ds.events):
                    check_reason = "no audit events reference a customer"
                    needs = ["audit_log.customer_id"]
                elif not acts.get("profile_view"):
                    check_reason = "no profile_view events: map the bank's enquiry/view codes"
                    needs = ["audit_log.action=profile_view"]
            elif det_id == "bulk_unjustified_browsing":
                if not acts.get("profile_view"):
                    check_reason = "no profile_view events: map the bank's enquiry/view codes"
                    needs = ["audit_log.action=profile_view"]
            elif det_id == "auth_channel_change":
                if not acts.get("contact_change") and not acts.get("mobile_change"):
                    check_reason = "no contact_change events: map the bank's contact/mobile update codes"
                    needs = ["audit_log.action=contact_change"]
            elif det_id == "account_lifecycle":
                dormant = sum(1 for c in ds.customers.values() if c.status == "dormant" or c.dormant_since)
                reactivations = acts.get("account_reactivate", 0)
                if not reactivations or not dormant:
                    check_reason = f"{reactivations} reactivation events, {dormant} dormant customers: map reactivation codes and dormancy"
                    needs = ["audit_log.action=account_reactivate", "customers.status=dormant"]
            elif det_id == "change_then_money":
                kinds = sum(1 for a in SENSITIVE_ACTIONS if acts.get(a))
                if kinds < 2:
                    check_reason = f"only {kinds} sensitive action type(s) mapped; the sequence needs at least two"
                    needs = ["Map at least two sensitive action codes in audit_log.action"]
            elif det_id == "suspense_posting_integrity":
                susp = sum(1 for p in ds.postings if p.manual and p.ledger in SUSPENSE_LEDGERS)
                if not susp:
                    check_reason = "no manual postings in SUSPENSE/DISPUTE ledgers: map the bank's suspense GL codes"
                    needs = ["postings.ledger=SUSPENSE/DISPUTE"]
            elif det_id == "payroll_beneficiary_integrity":
                sal = sum(1 for p in ds.postings if p.manual and p.narrative == "SALARY")
                if not sal:
                    check_reason = "no manual SALARY postings: map the payroll narrative/code"
                    needs = ["postings.narrative=SALARY"]
            elif det_id == "entitlement_integrity":
                if not ds.accounts:
                    check_reason = "no system accounts recorded"
                    needs = ["system_accounts"]

            if check_reason:
                status = CHECK
                explanation = check_reason
                remediation_hints.extend(needs)
            else:
                # Check for DEGRADED state
                degraded_reasons = []

                if det_id == "access_justification":
                    if "crm" not in av or "service_requests.staff_id" in absent:
                        degraded_reasons.append("no usable CRM tickets: unassigned access can only be shown as context")
                        needs = ["service_requests"]
                        if "service_requests" in dep.remediation_hints:
                            remediation_hints.append(dep.remediation_hints["service_requests"])
                elif det_id == "account_lifecycle":
                    if "audit_log.approver_account_id" in absent:
                        degraded_reasons.append("no approver on audit events: maker-checker cannot be assessed")
                        needs = ["audit_log.approver_account_id"]
                        if "audit_log.approver_account_id" in dep.remediation_hints:
                            remediation_hints.append(dep.remediation_hints["audit_log.approver_account_id"])
                elif det_id == "entitlement_integrity":
                    if "hr" not in av:
                        degraded_reasons.append("no HR roster: leaver activity cannot be checked")
                        needs = ["hr_roster"]
                    elif "system_accounts.is_privileged" in absent:
                        degraded_reasons.append("no is_privileged flag: cannot distinguish admin profiles from duplicates")
                        needs = ["system_accounts.is_privileged"]
                        if "system_accounts.is_privileged" in dep.remediation_hints:
                            remediation_hints.append(dep.remediation_hints["system_accounts.is_privileged"])
                elif det_id == "suspense_posting_integrity":
                    if "postings.counter_party" in absent:
                        degraded_reasons.append("no counterparty on postings: cash-out correlation is unavailable")
                        needs = ["postings.counter_party"]
                elif det_id == "payroll_beneficiary_integrity":
                    if "postings.counter_party" in absent:
                        degraded_reasons.append("no counterparty on postings: cannot match beneficiary accounts")
                        needs = ["postings.counter_party"]

                if degraded_feeds:
                    degraded_reasons.append("input quality degraded for: " + ", ".join(degraded_feeds))
                    for f in degraded_feeds:
                        remediation_hints.append(f"Resolve data quality issues in {f} feed (high row rejection or unmapped values).")

                if degraded_reasons:
                    status = DEGRADED
                    explanation = "; ".join(degraded_reasons)
                else:
                    status = READY
                    if det_id in ("access_justification", "bulk_unjustified_browsing"):
                        explanation = f"{acts.get('profile_view', 0):,} 'profile_view' events seen"
                    elif det_id == "auth_channel_change":
                        explanation = f"{acts.get('contact_change', 0):,} 'contact_change' events"
                    elif det_id == "account_lifecycle":
                        explanation = f"{acts.get('account_reactivate', 0):,} 'account_reactivate' events"
                    elif det_id == "change_then_money":
                        kinds = sum(1 for a in SENSITIVE_ACTIONS if acts.get(a))
                        explanation = f"{kinds} sensitive action types mapped"
                    elif det_id == "suspense_posting_integrity":
                        susp = sum(1 for p in ds.postings if p.manual and p.ledger in SUSPENSE_LEDGERS)
                        explanation = f"{susp:,} manual suspense/dispute postings"
                    elif det_id == "payroll_beneficiary_integrity":
                        sal = sum(1 for p in ds.postings if p.manual and p.narrative == "SALARY")
                        explanation = f"{sal:,} manual salary postings"
                    elif det_id == "entitlement_integrity":
                        explanation = f"{len(ds.accounts):,} system accounts"
                    else:
                        explanation = "Ready"

        rows.append({
            "detector": det_id,
            "detector_id": det_id,
            "label": dep.label,
            "status": status,
            "reason": explanation,
            "explanation": explanation,
            "needs": needs,
            "remediation": remediation_hints or needs,
            "required_feeds": list(dep.required_feeds),
            "missing_required_feeds": missing_req_feeds,
            "missing_required_fields": missing_req_fields,
            "degraded_feeds": list(degraded_feeds),
            "missing_supporting_feeds": missing_supp_feeds,
            "missing_supporting_fields": missing_supp_fields,
            "contract_version": CONTRACT_VERSION,
        })

    return rows


def render(rows: list[dict[str, Any]]) -> str:
    mark = {"ready": "READY   ", "degraded": "DEGRADED", "check": "CHECK   ", "blind": "BLIND   "}
    return "\n".join(
        f"  {mark.get(str(r['status']).lower(), str(r['status'])[:8]):8} {r['detector']:30} {r['explanation']}"
        for r in rows
    )
