"""Versioned bank data contract and detector dependency registry."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

from .ingest import FEED_KEY, REQUIRED, SPEC
from .mapping import OPTIONAL

CONTRACT_VERSION = "2.0.0"


@dataclass(frozen=True, slots=True)
class FieldMetadata:
    name: str
    data_type: str
    required_for_ingestion: bool
    optional: bool
    description: str
    pii_classification: str
    is_timestamp: bool = False
    notes: str = ""


@dataclass(frozen=True, slots=True)
class FeedMetadata:
    feed: str
    runtime_key: str
    required_feed: bool
    description: str
    example_csv_headers: list[str]
    fields: list[FieldMetadata]


@dataclass(frozen=True, slots=True)
class DetectorDependency:
    detector_id: str
    label: str
    description: str
    required_feeds: list[str]
    required_fields: list[str]
    supporting_feeds: list[str]
    supporting_fields: list[str]
    remediation_hints: dict[str, str] = field(default_factory=dict)


# Authoritative field metadata for every canonical column in SPEC
FIELD_METADATA: dict[str, dict[str, dict[str, Any]]] = {
    "hr_roster": {
        "staff_id": {
            "data_type": "string",
            "description": "Unique bank employee / staff identifier.",
            "pii_classification": "staff_identifier",
            "is_timestamp": False,
        },
        "status": {
            "data_type": "string",
            "description": "Employment status (e.g. active, suspended, terminated).",
            "pii_classification": "operational_status",
            "is_timestamp": False,
        },
        "role": {
            "data_type": "string",
            "description": "Job title, department or operational role of the employee.",
            "pii_classification": "job_role",
            "is_timestamp": False,
        },
        "branch": {
            "data_type": "string",
            "description": "Branch code or organizational unit where the employee is assigned.",
            "pii_classification": "branch_identifier",
            "is_timestamp": False,
        },
        "end_date": {
            "data_type": "timestamp",
            "description": "Employment termination or resignation date if applicable.",
            "pii_classification": "employment_history",
            "is_timestamp": True,
            "notes": "Used to detect post-termination activity by former employees.",
        },
        "salary_account": {
            "data_type": "string",
            "description": "Employee personal bank account receiving salary credits.",
            "pii_classification": "bank_account_identifier",
            "is_timestamp": False,
            "notes": "Used to verify whether payroll journal credits go to legitimate staff accounts.",
        },
    },
    "system_accounts": {
        "account_id": {
            "data_type": "string",
            "description": "System username or user login identifier.",
            "pii_classification": "system_account_identifier",
            "is_timestamp": False,
        },
        "staff_id": {
            "data_type": "string",
            "description": "Staff ID of the employee who owns or uses this system account.",
            "pii_classification": "staff_identifier",
            "is_timestamp": False,
        },
        "system": {
            "data_type": "string",
            "description": "Target system name (e.g. core_banking, crm, active_directory).",
            "pii_classification": "system_name",
            "is_timestamp": False,
        },
        "status": {
            "data_type": "string",
            "description": "System account status (e.g. active, disabled, locked).",
            "pii_classification": "operational_status",
            "is_timestamp": False,
        },
        "is_privileged": {
            "data_type": "boolean",
            "description": "Flag indicating administrative, supervisor, or elevated permissions.",
            "pii_classification": "entitlement_flag",
            "is_timestamp": False,
            "notes": "Distinguishes legitimate standard/admin profile pairs from duplicate accounts.",
        },
    },
    "portfolio": {
        "staff_id": {
            "data_type": "string",
            "description": "Staff ID of the relationship manager, branch officer, or portfolio owner.",
            "pii_classification": "staff_identifier",
            "is_timestamp": False,
        },
        "customer_id": {
            "data_type": "string",
            "description": "Customer/CIF identifier assigned to the staff member's portfolio.",
            "pii_classification": "customer_identifier",
            "is_timestamp": False,
        },
    },
    "audit_log": {
        "ts": {
            "data_type": "timestamp",
            "description": "Timestamp when the audit action occurred.",
            "pii_classification": "timestamp",
            "is_timestamp": True,
        },
        "account_id": {
            "data_type": "string",
            "description": "System user account identifier performing the action.",
            "pii_classification": "system_account_identifier",
            "is_timestamp": False,
        },
        "action": {
            "data_type": "string",
            "description": "Canonical action code (e.g. profile_view, contact_change, account_reactivate).",
            "pii_classification": "action_code",
            "is_timestamp": False,
        },
        "customer_id": {
            "data_type": "string",
            "description": "Customer/CIF identifier subject to the action.",
            "pii_classification": "customer_identifier",
            "is_timestamp": False,
        },
        "approver_account_id": {
            "data_type": "string",
            "description": "Supervisor/checker account ID approving the action, if applicable.",
            "pii_classification": "system_account_identifier",
            "is_timestamp": False,
            "notes": "Essential for assessing maker-checker controls on sensitive account operations.",
        },
    },
    "service_requests": {
        "request_id": {
            "data_type": "string",
            "description": "CRM customer ticket or service inquiry reference.",
            "pii_classification": "ticket_identifier",
            "is_timestamp": False,
        },
        "customer_id": {
            "data_type": "string",
            "description": "Customer/CIF identifier who raised the service request.",
            "pii_classification": "customer_identifier",
            "is_timestamp": False,
        },
        "staff_id": {
            "data_type": "string",
            "description": "Staff ID assigned to resolve the service request.",
            "pii_classification": "staff_identifier",
            "is_timestamp": False,
            "notes": "Enables matching profile lookups to an open ticket assigned to the user.",
        },
        "opened_at": {
            "data_type": "timestamp",
            "description": "Timestamp when the service request was opened.",
            "pii_classification": "timestamp",
            "is_timestamp": True,
        },
        "closed_at": {
            "data_type": "timestamp",
            "description": "Timestamp when the service request was closed, if completed.",
            "pii_classification": "timestamp",
            "is_timestamp": True,
        },
        "kind": {
            "data_type": "string",
            "description": "Category or type of customer inquiry.",
            "pii_classification": "request_type",
            "is_timestamp": False,
        },
    },
    "instructions": {
        "instruction_id": {
            "data_type": "string",
            "description": "Unique mandate, signed letter, or customer instruction reference.",
            "pii_classification": "instruction_identifier",
            "is_timestamp": False,
        },
        "customer_id": {
            "data_type": "string",
            "description": "Customer/CIF identifier authorizing the request.",
            "pii_classification": "customer_identifier",
            "is_timestamp": False,
        },
        "kind": {
            "data_type": "string",
            "description": "Instruction type (e.g. contact_change, reactivation, card_issue).",
            "pii_classification": "instruction_type",
            "is_timestamp": False,
        },
        "received_at": {
            "data_type": "timestamp",
            "description": "Timestamp when the customer mandate was verified and received.",
            "pii_classification": "timestamp",
            "is_timestamp": True,
            "notes": "Authoritative timing boundary: cannot authorize operations that occurred prior to receipt.",
        },
        "recorded_at": {
            "data_type": "timestamp",
            "description": "Timestamp when the instruction was digitized into the core system.",
            "pii_classification": "timestamp",
            "is_timestamp": True,
        },
    },
    "payments": {
        "payment_id": {
            "data_type": "string",
            "description": "Payment transaction reference.",
            "pii_classification": "transaction_identifier",
            "is_timestamp": False,
        },
        "ts": {
            "data_type": "timestamp",
            "description": "Payment posting/execution timestamp.",
            "pii_classification": "timestamp",
            "is_timestamp": True,
        },
        "customer_id": {
            "data_type": "string",
            "description": "Debited customer/CIF identifier.",
            "pii_classification": "customer_identifier",
            "is_timestamp": False,
        },
        "channel": {
            "data_type": "string",
            "description": "Transaction channel (e.g. mobile, internet_banking, branch, atm).",
            "pii_classification": "payment_channel",
            "is_timestamp": False,
        },
        "amount": {
            "data_type": "integer",
            "description": "Transaction amount in integer minor currency units (e.g. cents, where 100 = 1.00 KES).",
            "pii_classification": "financial_amount",
            "is_timestamp": False,
            "notes": "Exact decimal precision is preserved using integer minor units without binary floating-point representation.",
        },
        "beneficiary": {
            "data_type": "string",
            "description": "Destination bank account, phone number, or target counterparty.",
            "pii_classification": "counterparty_identifier",
            "is_timestamp": False,
        },
        "direction": {
            "data_type": "string",
            "description": "Transaction flow direction: 'debit' (outbound money movement), 'credit' (inbound deposit), or 'unknown'.",
            "pii_classification": "transaction_flow",
            "is_timestamp": False,
            "notes": "Detector-critical field for change-then-money. Unconfirmed or credit transactions are excluded from outbound money investigations.",
        },
    },
    "customers": {
        "customer_id": {
            "data_type": "string",
            "description": "Customer master / CIF reference.",
            "pii_classification": "customer_identifier",
            "is_timestamp": False,
        },
        "status": {
            "data_type": "string",
            "description": "Relationship status (e.g. active, dormant, deceased, closed).",
            "pii_classification": "customer_status",
            "is_timestamp": False,
        },
        "dormant_since": {
            "data_type": "timestamp",
            "description": "Date/time when the account entered dormancy.",
            "pii_classification": "timestamp",
            "is_timestamp": True,
        },
        "deceased_flag": {
            "data_type": "boolean",
            "description": "True if customer is flagged deceased in core records.",
            "pii_classification": "vital_status",
            "is_timestamp": False,
        },
        "is_sensitive": {
            "data_type": "boolean",
            "description": "True if customer is marked PEP, VIP, or high-risk watchlist.",
            "pii_classification": "risk_classification",
            "is_timestamp": False,
        },
    },
    "postings": {
        "posting_id": {
            "data_type": "string",
            "description": "General ledger journal entry reference.",
            "pii_classification": "journal_identifier",
            "is_timestamp": False,
        },
        "ts": {
            "data_type": "timestamp",
            "description": "Accounting journal entry timestamp.",
            "pii_classification": "timestamp",
            "is_timestamp": True,
        },
        "ledger": {
            "data_type": "string",
            "description": "Ledger category (e.g. SUSPENSE, DISPUTE, PAYROLL, GL).",
            "pii_classification": "ledger_code",
            "is_timestamp": False,
        },
        "counter_party": {
            "data_type": "string",
            "description": "Beneficiary account or target customer/CIF receiving funds.",
            "pii_classification": "counterparty_identifier",
            "is_timestamp": False,
        },
        "amount": {
            "data_type": "integer",
            "description": "Journal amount in integer minor currency units (e.g. cents, where 100 = 1.00 KES).",
            "pii_classification": "financial_amount",
            "is_timestamp": False,
            "notes": "Exact decimal precision is preserved using integer minor units without binary floating-point representation.",
        },
        "entered_by_account": {
            "data_type": "string",
            "description": "Maker user account that created or keyed the journal.",
            "pii_classification": "system_account_identifier",
            "is_timestamp": False,
        },
        "approved_by_account": {
            "data_type": "string",
            "description": "Checker user account that authorized the journal entry.",
            "pii_classification": "system_account_identifier",
            "is_timestamp": False,
            "notes": "Required to verify maker-checker separation on suspense and manual postings.",
        },
        "manual": {
            "data_type": "boolean",
            "description": "True if manual entry; False if automated batch or interface posting.",
            "pii_classification": "operational_flag",
            "is_timestamp": False,
        },
        "narrative": {
            "data_type": "string",
            "description": "Journal narrative or reference description (e.g. SALARY, SUSPENSE REVERSAL).",
            "pii_classification": "journal_narrative",
            "is_timestamp": False,
        },
    },
}

FEED_DESCRIPTIONS: dict[str, str] = {
    "hr_roster": "HR employee master: status, role, branch assignment, termination dates, and salary accounts.",
    "system_accounts": "System user registry mapping operational user logins to staff identities and privilege levels.",
    "portfolio": "Relationship manager and branch customer portfolio assignments.",
    "audit_log": "Chronological core-banking and channel audit trail of staff actions, views, and approvals.",
    "service_requests": "CRM customer support tickets and service inquiries justifying customer profile lookups.",
    "instructions": "Customer mandate and instruction register verifying authorization for sensitive account changes.",
    "payments": "Outbound and internal payment transactions linked to customers.",
    "customers": "Customer master record with dormancy, deceased flags, and sensitivity tags.",
    "postings": "General ledger journals, manual suspense/dispute movements, and payroll entries.",
}

# Formal detector dependency registry
DETECTOR_DEPENDENCIES: tuple[DetectorDependency, ...] = (
    DetectorDependency(
        detector_id="access_justification",
        label="Access Justification",
        description="Surfaces customer profile lookups outside the staff member's assigned portfolio without a corresponding CRM service request.",
        required_feeds=["audit_log", "portfolio", "system_accounts"],
        required_fields=[
            "audit_log.ts",
            "audit_log.account_id",
            "audit_log.action",
            "audit_log.customer_id",
            "portfolio.staff_id",
            "portfolio.customer_id",
            "system_accounts.account_id",
            "system_accounts.staff_id",
        ],
        supporting_feeds=["service_requests", "customers"],
        supporting_fields=[
            "service_requests.staff_id",
            "customers.is_sensitive",
        ],
        remediation_hints={
            "portfolio": "Export portfolio relationship manager assignments (RM_ASSIGNMENTS).",
            "service_requests": "Export CRM tickets to allow unassigned access to be justified by active customer requests.",
            "service_requests.staff_id": "Map the staff/handler field in CRM tickets to enable ticket-to-user attribution.",
            "system_accounts": "Supply system_accounts to attribute audit logins to staff.",
        },
    ),
    DetectorDependency(
        detector_id="bulk_unjustified_browsing",
        label="Bulk Unjustified Browsing",
        description="Detects high-volume customer profile viewing across unassigned customers within rolling inspection windows.",
        required_feeds=["audit_log", "portfolio", "system_accounts"],
        required_fields=[
            "audit_log.ts",
            "audit_log.account_id",
            "audit_log.action",
            "audit_log.customer_id",
            "portfolio.staff_id",
            "portfolio.customer_id",
            "system_accounts.account_id",
            "system_accounts.staff_id",
        ],
        supporting_feeds=["service_requests", "customers"],
        supporting_fields=[
            "service_requests.staff_id",
            "customers.is_sensitive",
        ],
        remediation_hints={
            "customers.is_sensitive": "Supply customer sensitivity flags (VIP/PEP) to highlight high-risk browsing targets.",
            "service_requests": "Supply CRM service requests to distinguish legitimate mass service work from snooping.",
            "system_accounts": "Supply system_accounts to attribute audit logins to staff.",
        },
    ),
    DetectorDependency(
        detector_id="auth_channel_change",
        label="Authentication & Channel Change",
        description="Detects registered contact or mobile credential updates performed without a verified customer instruction mandate.",
        required_feeds=["audit_log", "instructions", "system_accounts"],
        required_fields=[
            "audit_log.ts",
            "audit_log.account_id",
            "audit_log.action",
            "audit_log.customer_id",
            "instructions.customer_id",
            "instructions.kind",
            "instructions.received_at",
            "system_accounts.account_id",
            "system_accounts.staff_id",
        ],
        supporting_feeds=["instructions"],
        supporting_fields=[
            "instructions.recorded_at",
            "audit_log.approver_account_id",
        ],
        remediation_hints={
            "instructions": "Supply customer instruction register (CUSTOMER_INSTRUCTIONS) to verify contact update mandates.",
            "audit_log.approver_account_id": "Include approver account ID on audit events to verify dual-control authorization.",
            "system_accounts": "Supply system_accounts to attribute audit logins to staff.",
        },
    ),
    DetectorDependency(
        detector_id="account_lifecycle",
        label="Dormant & Deceased Account Lifecycle",
        description="Detects reactivation of dormant or deceased customer accounts without documented customer instruction or checker authorization.",
        required_feeds=["audit_log", "customers", "instructions", "system_accounts"],
        required_fields=[
            "audit_log.ts",
            "audit_log.account_id",
            "audit_log.action",
            "audit_log.customer_id",
            "customers.customer_id",
            "customers.status",
            "instructions.customer_id",
            "instructions.kind",
            "instructions.received_at",
            "system_accounts.account_id",
            "system_accounts.staff_id",
        ],
        supporting_feeds=["audit_log", "customers"],
        supporting_fields=[
            "audit_log.approver_account_id",
            "customers.dormant_since",
            "customers.deceased_flag",
        ],
        remediation_hints={
            "audit_log.approver_account_id": "Include approver account ID on audit events to verify dual control / maker-checker.",
            "customers.deceased_flag": "Provide deceased flags on customer master to catch unauthorized reactivation of deceased accounts.",
            "system_accounts": "Supply system_accounts to attribute audit logins to staff.",
        },
    ),
    DetectorDependency(
        detector_id="change_then_money",
        label="Change Followed by Money Movement",
        description="Detects sensitive profile modifications (contacts, reactivation) quickly followed by outbound customer payments.",
        required_feeds=["audit_log", "payments", "instructions", "system_accounts"],
        required_fields=[
            "audit_log.ts",
            "audit_log.account_id",
            "audit_log.action",
            "audit_log.customer_id",
            "payments.payment_id",
            "payments.ts",
            "payments.customer_id",
            "payments.amount",
            "instructions.customer_id",
            "instructions.kind",
            "instructions.received_at",
            "system_accounts.account_id",
            "system_accounts.staff_id",
        ],
        supporting_feeds=["payments"],
        supporting_fields=[
            "payments.direction",
            "payments.beneficiary",
            "payments.channel",
        ],
        remediation_hints={
            "payments": "Supply payment transactions feed (PAYMENTS_FEED) to link profile changes with fund outflow.",
            "payments.direction": "Include transaction direction (debit/credit) to exclude incoming customer deposits from cash-out analysis.",
            "payments.beneficiary": "Include payment beneficiary accounts to strengthen destination fund correlation.",
            "system_accounts": "Supply system_accounts to attribute audit logins to staff.",
        },
    ),
    DetectorDependency(
        detector_id="suspense_posting_integrity",
        label="Suspense & Dispute Posting Integrity",
        description="Detects manual general ledger postings out of suspense/dispute accounts with missing or self-approved maker-checker authorization.",
        required_feeds=["postings", "system_accounts"],
        required_fields=[
            "postings.posting_id",
            "postings.ts",
            "postings.ledger",
            "postings.amount",
            "postings.entered_by_account",
            "postings.approved_by_account",
            "postings.manual",
            "postings.narrative",
            "system_accounts.account_id",
            "system_accounts.staff_id",
        ],
        supporting_feeds=["postings", "payments"],
        supporting_fields=[
            "postings.counter_party",
            "payments.customer_id",
        ],
        remediation_hints={
            "postings.approved_by_account": "Include approving account ID on general ledger journals to evaluate maker-checker segregation.",
            "postings.counter_party": "Provide posting counterparty references to link suspense movements to customer cash-outs.",
            "system_accounts": "Supply system_accounts to attribute posting maker accounts to staff.",
        },
    ),
    DetectorDependency(
        detector_id="payroll_beneficiary_integrity",
        label="Payroll Beneficiary Integrity",
        description="Detects manual payroll postings directed to beneficiary accounts that do not belong to legitimate employees on the HR roster.",
        required_feeds=["postings", "hr_roster", "system_accounts"],
        required_fields=[
            "postings.posting_id",
            "postings.ts",
            "postings.ledger",
            "postings.amount",
            "postings.entered_by_account",
            "postings.manual",
            "postings.narrative",
            "postings.counter_party",
            "hr_roster.staff_id",
            "hr_roster.status",
            "hr_roster.salary_account",
            "system_accounts.account_id",
            "system_accounts.staff_id",
        ],
        supporting_feeds=["hr_roster", "postings"],
        supporting_fields=[],
        remediation_hints={
            "hr_roster.salary_account": "Map employee salary bank account numbers in HR roster to verify payroll destinations.",
            "postings.counter_party": "Supply contra counterparty account numbers on payroll postings to match employee salary accounts.",
            "system_accounts": "Supply system_accounts to attribute posting maker accounts to staff.",
        },
    ),
    DetectorDependency(
        detector_id="entitlement_integrity",
        label="Entitlement & Leaver Integrity",
        description="Detects duplicate operational profiles on the same system, unauthorized privilege escalation, and activity after employment termination.",
        required_feeds=["system_accounts"],
        required_fields=[
            "system_accounts.account_id",
            "system_accounts.staff_id",
            "system_accounts.system",
            "system_accounts.status",
        ],
        supporting_feeds=["hr_roster", "system_accounts", "audit_log"],
        supporting_fields=[
            "system_accounts.is_privileged",
            "hr_roster.status",
            "hr_roster.end_date",
            "audit_log.ts",
            "audit_log.account_id",
        ],
        remediation_hints={
            "system_accounts.is_privileged": "Supply is_privileged flag to distinguish approved admin/standard profile pairs from duplicate accounts.",
            "hr_roster.end_date": "Supply employee termination dates to detect lingering access and post-termination activity.",
        },
    ),
)


def validate_registry() -> None:
    """Validate that every detector dependency and feed/field metadata is consistent with SPEC."""
    for feed, fields in SPEC.items():
        if feed not in FIELD_METADATA:
            raise ValueError(f"Feed '{feed}' has no entry in FIELD_METADATA")
        for f in fields:
            if f not in FIELD_METADATA[feed]:
                raise ValueError(f"Field '{feed}.{f}' has no metadata in FIELD_METADATA")

    for detector in DETECTOR_DEPENDENCIES:
        for feed in detector.required_feeds + detector.supporting_feeds:
            if feed not in SPEC:
                raise ValueError(
                    f"{detector.detector_id}: invalid feed dependency '{feed}' not in SPEC"
                )
        for qualified in detector.required_fields + detector.supporting_fields:
            feed, separator, field_name = qualified.partition(".")
            if not separator or feed not in SPEC or field_name not in SPEC[feed]:
                raise ValueError(
                    f"{detector.detector_id}: invalid field dependency '{qualified}'"
                )


def contract_dict() -> dict[str, Any]:
    """Generate the bank-facing machine-readable data contract."""
    validate_registry()
    feeds: dict[str, Any] = {}
    for feed, fields in sorted(SPEC.items()):
        optional = OPTIONAL.get(feed, set())
        field_records = []
        for f in fields:
            meta = FIELD_METADATA[feed][f]
            field_records.append({
                "name": f,
                "data_type": meta["data_type"],
                "required_for_ingestion": f not in optional,
                "optional": f in optional,
                "description": meta["description"],
                "pii_classification": meta["pii_classification"],
                "is_timestamp": meta.get("is_timestamp", False),
                "notes": meta.get("notes", ""),
            })
        feeds[feed] = {
            "runtime_key": FEED_KEY[feed],
            "required_feed": feed in REQUIRED,
            "description": FEED_DESCRIPTIONS.get(feed, ""),
            "example_csv_header": ",".join(fields),
            "fields": field_records,
        }

    return {
        "contract_version": CONTRACT_VERSION,
        "feeds": feeds,
        "detectors": [asdict(d) for d in DETECTOR_DEPENDENCIES],
    }


def contract_markdown() -> str:
    """Generate a clean, human-readable bank data contract specification."""
    c = contract_dict()
    md = [
        f"# Toroka Enterprise — Bank Data Contract (v{c['contract_version']})",
        "",
        "This specification details the canonical data feeds, required and optional columns, PII classifications, and scenario detector dependencies required for Toroka Enterprise insider-risk investigations.",
        "",
        "---",
        "",
        "## 1. Canonical Feeds Overview",
        "",
        "| Feed | Runtime Key | Ingest Required | Description |",
        "|---|---|:---:|---|",
    ]
    for feed, info in c["feeds"].items():
        req_badge = "Required" if info["required_feed"] else "Optional"
        md.append(f"| `{feed}` | `{info['runtime_key']}` | {req_badge} | {info['description']} |")

    md.extend([
        "",
        "---",
        "",
        "## 2. Feed Schemas & Field Catalog",
        "",
    ])

    for feed, info in c["feeds"].items():
        req_text = "Required feed" if info["required_feed"] else "Optional feed"
        md.extend([
            f"### Feed: `{feed}` ({req_text})",
            f"**Runtime Key:** `{info['runtime_key']}`  ",
            f"**Description:** {info['description']}  ",
            f"**Example CSV Header:** `{info['example_csv_header']}`",
            "",
            "| Field | Type | Required | PII / Classification | Description | Notes |",
            "|---|---|:---:|---|---|---|",
        ])
        for f in info["fields"]:
            req_str = "Yes" if f["required_for_ingestion"] else "No (optional)"
            ts_str = " (Timestamp)" if f["is_timestamp"] else ""
            notes = f["notes"] or "-"
            md.append(f"| `{f['name']}` | `{f['data_type']}`{ts_str} | {req_str} | `{f['pii_classification']}` | {f['description']} | {notes} |")
        md.append("")

    md.extend([
        "---",
        "",
        "## 3. Detector Dependencies & Readiness Matrix",
        "",
        "Toroka evaluates detector readiness based on the presence and quality of required and supporting data feeds.",
        "",
        "| Detector ID | Scenario Name | Required Feeds | Required Fields | Supporting Feeds / Fields |",
        "|---|---|---|---|---|",
    ])
    for d in c["detectors"]:
        req_f = ", ".join(f"`{f}`" for f in d["required_feeds"])
        req_cols = "<br>".join(f"`{c}`" for c in d["required_fields"])
        supp = "<br>".join(f"`{c}`" for c in d["supporting_fields"]) or "None"
        md.append(f"| `{d['detector_id']}` | **{d['label']}** | {req_f} | {req_cols} | {supp} |")

    md.extend([
        "",
        "### Detector Readiness States",
        "",
        "- **READY**: All required feeds and fields are present and meet data quality thresholds.",
        "- **DEGRADED**: Required feeds are present, but supporting fields are missing or data quality is degraded (e.g. unmapped codes, row rejections).",
        "- **CHECK**: Feeds are present, but relevant action codes or event types were not observed in the dataset (potential mapping gap or quiet period).",
        "- **BLIND**: A required feed or material field is absent, preventing scenario assessment.",
        "",
    ])
    return "\n".join(md)


def contract_fingerprint() -> str:
    """Generate a deterministic SHA-256 fingerprint of the canonical data contract."""
    contract = contract_dict()
    # Serialize canonically without timestamps or non-deterministic elements
    payload = json.dumps(contract, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
