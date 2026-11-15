"""Data quality assessment and detector readiness integration."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from toroka_enterprise.coverage import BLIND, CHECK, DEGRADED, READY
from toroka_enterprise.data_contract import DETECTOR_DEPENDENCIES, FEED_KEY

from .contracts import (
    CanonicalEmploymentEventRecord,
    CanonicalRecord,
    CanonicalStaffAccessRecord,
    CanonicalTransactionRecord,
)


@dataclass(frozen=True, slots=True)
class QualityIssue:
    field: str
    severity: str  # "error", "warning", "info"
    code: str
    message: str
    record_index: int | None = None


@dataclass(frozen=True, slots=True)
class QualityReport:
    total_records: int
    valid_records: int
    rejected_records: int
    issues: tuple[QualityIssue, ...]
    field_counts: dict[str, int]


@dataclass(frozen=True, slots=True)
class DetectorImpactReport:
    detector_id: str
    label: str
    status: str  # "ready", "degraded", "check", "blind"
    reasons: list[str]
    missing_required_fields: list[str]
    missing_supporting_fields: list[str]


def assess_canonical_batch(records: list[CanonicalRecord]) -> QualityReport:
    """Assess field-level data quality, completeness, and anomalies across a batch of canonical records."""
    issues: list[QualityIssue] = []
    valid = 0
    rejected = 0
    now = datetime.now(timezone.utc)
    field_counts: dict[str, int] = {}

    for idx, r in enumerate(records):
        rec_valid = True

        if not r.record_id or not r.record_id.strip():
            issues.append(QualityIssue(
                field="record_id",
                severity="error",
                code="MISSING_RECORD_ID",
                message=f"Record at index {idx} has empty record_id",
                record_index=idx,
            ))
            rec_valid = False

        if not r.provenance or not r.provenance.source_event_timestamp:
            issues.append(QualityIssue(
                field="source_event_timestamp",
                severity="error",
                code="MISSING_TIMESTAMP",
                message=f"Record at index {idx} missing event timestamp",
                record_index=idx,
            ))
            rec_valid = False
        elif r.provenance.source_event_timestamp > now:
            issues.append(QualityIssue(
                field="source_event_timestamp",
                severity="warning",
                code="FUTURE_TIMESTAMP",
                message=f"Record at index {idx} timestamp is in the future",
                record_index=idx,
            ))

        if isinstance(r, CanonicalTransactionRecord):
            field_counts["transaction.amount"] = field_counts.get("transaction.amount", 0) + 1
            if r.amount <= Decimal("0"):
                issues.append(QualityIssue(
                    field="amount",
                    severity="error",
                    code="NON_POSITIVE_AMOUNT",
                    message=f"Transaction {r.record_id} has non-positive amount: {r.amount}",
                    record_index=idx,
                ))
                rec_valid = False

            if not r.account_ref:
                issues.append(QualityIssue(
                    field="account_ref",
                    severity="error",
                    code="MISSING_ACCOUNT_REF",
                    message=f"Transaction {r.record_id} has no primary account reference",
                    record_index=idx,
                ))
                rec_valid = False

            if r.currency not in ("KES", "USD", "EUR", "GBP", "UGX", "TZS"):
                issues.append(QualityIssue(
                    field="currency",
                    severity="warning",
                    code="UNRECOGNIZED_CURRENCY",
                    message=f"Transaction {r.record_id} uses uncommon currency code: {r.currency}",
                    record_index=idx,
                ))

        elif isinstance(r, CanonicalEmploymentEventRecord):
            field_counts["hr.staff_ref"] = field_counts.get("hr.staff_ref", 0) + 1
            if not r.staff_ref:
                issues.append(QualityIssue(
                    field="staff_ref",
                    severity="error",
                    code="MISSING_STAFF_REF",
                    message=f"HR record {r.record_id} has no staff reference",
                    record_index=idx,
                ))
                rec_valid = False

        elif isinstance(r, CanonicalStaffAccessRecord):
            field_counts["audit.staff_ref"] = field_counts.get("audit.staff_ref", 0) + 1
            if not r.staff_ref:
                issues.append(QualityIssue(
                    field="staff_ref",
                    severity="error",
                    code="MISSING_STAFF_REF",
                    message=f"Access log {r.record_id} has no staff reference",
                    record_index=idx,
                ))
                rec_valid = False

        if rec_valid:
            valid += 1
        else:
            rejected += 1

    return QualityReport(
        total_records=len(records),
        valid_records=valid,
        rejected_records=rejected,
        issues=tuple(issues),
        field_counts=field_counts,
    )


def assess_detector_readiness_from_integration(
    available_feeds: set[str],
    absent_fields: set[str],
) -> list[DetectorImpactReport]:
    """Evaluate detector readiness against currently ingested feeds and fields.
    
    Seamlessly integrates with Toroka's central Phase 2 detector dependency registry.
    Ensures missing bank feeds reduce scenario visibility ('BLIND' or 'DEGRADED')
    without falsely raising fraud risk scores.
    """
    reports: list[DetectorImpactReport] = []

    for dep in DETECTOR_DEPENDENCIES:
        # Determine missing required feeds & fields
        missing_req_feeds = [f for f in dep.required_feeds if FEED_KEY.get(f) not in available_feeds]
        missing_req_fields = [f for f in dep.required_fields if f in absent_fields]

        # Determine missing supporting feeds & fields
        missing_supp_feeds = [f for f in dep.supporting_feeds if FEED_KEY.get(f) not in available_feeds]
        missing_supp_fields = [f for f in dep.supporting_fields if f in absent_fields]

        reasons: list[str] = []
        if missing_req_feeds:
            reasons.append(f"Missing required feeds: {', '.join(missing_req_feeds)}")
        if missing_req_fields:
            reasons.append(f"Missing required fields: {', '.join(missing_req_fields)}")

        if missing_req_feeds or missing_req_fields:
            status = BLIND
        elif missing_supp_feeds or missing_supp_fields:
            if missing_supp_feeds:
                reasons.append(f"Missing supporting feeds: {', '.join(missing_supp_feeds)}")
            if missing_supp_fields:
                reasons.append(f"Missing supporting fields: {', '.join(missing_supp_fields)}")
            status = DEGRADED
        else:
            status = READY

        reports.append(DetectorImpactReport(
            detector_id=dep.detector_id,
            label=dep.label,
            status=str(status),
            reasons=reasons,
            missing_required_fields=missing_req_fields,
            missing_supporting_fields=missing_supp_fields,
        ))

    return reports
