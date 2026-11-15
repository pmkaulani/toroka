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


def coverage_report(ds: Dataset) -> list[dict[str, Any]]:
    acts = Counter(e.action for e in ds.events)
    av, absent = ds.available, ds.absent_fields
    rows: list[dict[str, Any]] = []

    for dep in DETECTOR_DEPENDENCIES:
        det_id = dep.detector_id

        # 1. Check required feeds & fields from registry
        missing_req_feeds = [f for f in dep.required_feeds if FEED_KEY[f] not in av]
        missing_req_fields = [f for f in dep.required_fields if f in absent]

        # 2. Check supporting feeds & fields from registry
        missing_supp_feeds = [f for f in dep.supporting_feeds if FEED_KEY[f] not in av]
        missing_supp_fields = [f for f in dep.supporting_fields if f in absent]

        # 3. Derive runtime feeds dynamically from registry
        detector_feeds = {FEED_KEY[f] for f in dep.required_feeds + dep.supporting_feeds if f in FEED_KEY}
        degraded_feeds = sorted(detector_feeds & ds.degraded_feeds)

        remediation_hints: list[str] = []
        needs: list[str] = []

        # Check for unobserved actions / events (CHECK conditions)
        check_reason: str | None = None
        check_needs: list[str] = []

        if det_id == "access_justification":
            if not any(e.customer_ref for e in ds.events):
                check_reason = "no audit events reference a customer"
                check_needs = ["audit_log.customer_id"]
            elif not acts.get("profile_view"):
                check_reason = "no profile_view events: map the bank's enquiry/view codes"
                check_needs = ["audit_log.action=profile_view"]
        elif det_id == "bulk_unjustified_browsing":
            if not acts.get("profile_view"):
                check_reason = "no profile_view events: map the bank's enquiry/view codes"
                check_needs = ["audit_log.action=profile_view"]
        elif det_id == "auth_channel_change":
            if not acts.get("contact_change") and not acts.get("mobile_change"):
                check_reason = "no contact_change events: map the bank's contact/mobile update codes"
                check_needs = ["audit_log.action=contact_change"]
        elif det_id == "account_lifecycle":
            dormant = sum(1 for c in ds.customers.values() if c.status == "dormant" or c.dormant_since)
            reactivations = acts.get("account_reactivate", 0)
            if not reactivations or not dormant:
                check_reason = f"{reactivations} reactivation events, {dormant} dormant customers: map reactivation codes and dormancy"
                check_needs = ["audit_log.action=account_reactivate", "customers.status=dormant"]
        elif det_id == "change_then_money":
            kinds = sum(1 for a in SENSITIVE_ACTIONS if acts.get(a))
            if kinds == 0:
                check_reason = "no sensitive action events mapped in audit_log.action"
                check_needs = ["audit_log.action=" + "/".join(sorted(SENSITIVE_ACTIONS))]
        elif det_id == "suspense_posting_integrity":
            susp = sum(1 for p in ds.postings if p.manual and p.ledger in SUSPENSE_LEDGERS)
            if not susp:
                check_reason = "no manual postings in SUSPENSE/DISPUTE ledgers: map the bank's suspense GL codes"
                check_needs = ["postings.ledger=SUSPENSE/DISPUTE"]
        elif det_id == "payroll_beneficiary_integrity":
            sal = sum(1 for p in ds.postings if p.manual and p.narrative == "SALARY")
            if not sal:
                check_reason = "no manual SALARY postings: map the payroll narrative/code"
                check_needs = ["postings.narrative=SALARY"]
        elif det_id == "entitlement_integrity":
            if not ds.accounts:
                check_reason = "no system accounts recorded"
                check_needs = ["system_accounts"]

        # 1. BLIND takes top precedence
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

        # 2. DEGRADED takes second precedence
        elif missing_supp_feeds or missing_supp_fields or degraded_feeds:
            status = DEGRADED
            degraded_reasons = []

            for f in missing_supp_feeds:
                label = f"{f} (CRM)" if f == "service_requests" else (f"{f} (HR)" if f == "hr_roster" else f)
                degraded_reasons.append(f"missing supporting feed: {label}")
                if f in dep.remediation_hints:
                    remediation_hints.append(dep.remediation_hints[f])

            for f in missing_supp_fields:
                label = f"{f} (CRM)" if "service_requests" in f else (f"{f} (approver)" if "approver" in f else (f"{f} (is_privileged)" if "is_privileged" in f else f))
                degraded_reasons.append(f"missing supporting field: {label}")
                if f in dep.remediation_hints:
                    remediation_hints.append(dep.remediation_hints[f])

            if degraded_feeds:
                degraded_reasons.append("input quality degraded for: " + ", ".join(degraded_feeds))
                for f in degraded_feeds:
                    remediation_hints.append(f"Resolve data quality issues in {f} feed (high row rejection or unmapped values).")

            needs = list(missing_supp_feeds) + list(missing_supp_fields)
            if check_reason:
                degraded_reasons.append(check_reason)
                remediation_hints.extend(check_needs)
            explanation = "; ".join(degraded_reasons)

        # 3. CHECK takes third precedence
        elif check_reason:
            status = CHECK
            explanation = check_reason
            remediation_hints.extend(check_needs)
            needs = check_needs

        # 4. READY
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
