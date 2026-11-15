"""Versioned canonical bank data contracts and integration models."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal
from enum import StrEnum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SourceSystem(StrEnum):
    CORE_BANKING = "core_banking"
    PAYMENTS = "payments"
    MOBILE_MONEY = "mobile_money"
    AML = "aml"
    SIEM = "siem"
    IAM = "iam"
    HR = "hr"
    CRM = "crm"
    CBS_AUDIT = "cbs_audit"


class RecordType(StrEnum):
    TRANSACTION = "transaction"
    ACCOUNT = "account"
    STAFF_ACCESS = "staff_access"
    CUSTOMER_CHANGE = "customer_change"
    PAYMENT_EVENT = "payment_event"
    SECURITY_EVENT = "security_event"
    EMPLOYMENT_EVENT = "employment_event"
    AML_ALERT = "aml_alert"


class Provenance(BaseModel):
    """Cryptographic provenance and lineage for ingested bank records."""
    model_config = ConfigDict(extra="forbid")

    source_system: SourceSystem
    connector_id: str
    connector_version: str = "1.0.0"
    source_record_id: str
    source_event_timestamp: datetime
    ingestion_timestamp: datetime = Field(default_factory=utc_now)
    source_schema_version: str = "1.0"
    canonical_schema_version: str = "1.0.0"
    payload_digest: str = ""
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


class CanonicalRecord(BaseModel):
    """Base class for all normalized Toroka Enterprise integration records."""
    model_config = ConfigDict(extra="forbid")

    installation_id: str
    record_id: str
    record_type: RecordType
    provenance: Provenance

    def compute_digest(self) -> str:
        """Compute deterministic SHA-256 digest of record payload excluding mutable digest."""
        data = self.model_dump(mode="json")
        if "provenance" in data and "payload_digest" in data["provenance"]:
            data["provenance"]["payload_digest"] = ""
        encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class CanonicalTransactionRecord(CanonicalRecord):
    """Canonical representation of core banking and ledger postings."""
    record_type: RecordType = RecordType.TRANSACTION

    account_ref: str
    counterparty_ref: str | None = None
    amount: Decimal
    currency: str = "KES"
    direction: str  # DEBIT or CREDIT
    transaction_type: str  # TRANSFER, POSTING, WITHDRAWAL, DEPOSIT, SALARY
    narrative: str = ""
    channel: str = "CORE"
    status: str = "SETTLED"  # PENDING, SETTLED, REVERSED, FAILED
    is_reversal: bool = False
    reversal_of_ref: str | None = None
    posting_staff_ref: str | None = None
    authorization_staff_ref: str | None = None
    branch_ref: str | None = None


class CanonicalAccountRecord(CanonicalRecord):
    """Canonical account and customer reference mapping."""
    record_type: RecordType = RecordType.ACCOUNT

    account_id: str
    customer_ref: str
    account_type: str  # SAVINGS, CURRENT, INTERNAL, SUSPENSE, LOAN
    status: str = "ACTIVE"  # ACTIVE, DORMANT, FROZEN, CLOSED
    currency: str = "KES"
    opened_at: datetime | None = None
    last_activity_at: datetime | None = None
    branch_ref: str | None = None


class CanonicalStaffAccessRecord(CanonicalRecord):
    """Canonical staff system access and audit trail event."""
    record_type: RecordType = RecordType.STAFF_ACCESS

    staff_ref: str
    system_ref: str
    session_id: str | None = None
    action: str  # LOGIN, LOGOUT, QUERY, UPDATE, EXPORT, DELETE
    resource_type: str  # CUSTOMER_PROFILE, ACCOUNT_LEDGER, JOURNAL, CREDENTIAL
    resource_id: str
    workstation_ip: str | None = None
    outcome: str = "SUCCESS"  # SUCCESS or FAILURE
    failure_reason: str | None = None
    is_privileged: bool = False


class CanonicalCustomerChangeRecord(CanonicalRecord):
    """Canonical customer profile modification (e.g. phone, mandate change)."""
    record_type: RecordType = RecordType.CUSTOMER_CHANGE

    customer_ref: str
    account_ref: str | None = None
    field_name: str  # PHONE_NUMBER, EMAIL, MANDATE, MPESA_LINK, ADDRESS
    old_value: str | None = None
    new_value: str | None = None
    changed_by_staff_ref: str
    authorized_by_staff_ref: str | None = None
    channel: str = "BRANCH"


class CanonicalPaymentEventRecord(CanonicalRecord):
    """Canonical payment, mobile money transfer, or settlement instruction."""
    record_type: RecordType = RecordType.PAYMENT_EVENT

    payment_ref: str
    payment_type: str  # M_PESA, EFT, RTGS, SWIFT, INTERNAL_TRANSFER
    amount: Decimal
    currency: str = "KES"
    sender_ref: str
    receiver_ref: str
    status: str = "SETTLED"  # INITIATED, AUTHORIZED, SETTLED, REVERSED, FAILED
    external_reference: str | None = None


class CanonicalSecurityEventRecord(CanonicalRecord):
    """Canonical SIEM / security monitoring alert."""
    record_type: RecordType = RecordType.SECURITY_EVENT

    event_id: str
    event_type: str  # FAILED_AUTH_BURST, PRIVILEGE_ESCALATION, UNUSUAL_GEO, EXFILTRATION
    severity: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    user_ref: str
    source_ip: str | None = None
    description: str


class CanonicalEmploymentEventRecord(CanonicalRecord):
    """Canonical HR employment lifecycle event."""
    record_type: RecordType = RecordType.EMPLOYMENT_EVENT

    staff_ref: str
    event_type: str  # JOINED, ROLE_CHANGE, SUSPENDED, TERMINATED, LEAVE
    role: str
    department: str
    branch: str
    status: str = "ACTIVE"  # ACTIVE, SUSPENDED, TERMINATED, ON_LEAVE
    salary_account: str | None = None
    effective_date: datetime


class CanonicalAMLAlertRecord(CanonicalRecord):
    """Canonical AML detection platform alert."""
    record_type: RecordType = RecordType.AML_ALERT

    alert_id: str
    rule_id: str
    priority: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    subject_ref: str
    case_ref: str | None = None
    disposition: str = "NEW"
