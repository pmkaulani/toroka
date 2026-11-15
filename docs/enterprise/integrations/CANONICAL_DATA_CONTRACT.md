# Toroka Enterprise — Canonical Bank Data Contract

## 1. Overview & Provenance Model

Every piece of data ingested into Toroka Enterprise is normalized into a strictly validated Canonical Record. The canonical schema is versioned (v2.0.0) and enforces strict validation (`model_config = ConfigDict(extra="forbid")`) to prevent schema drift and silent field truncation.

### 1.1 Provenance Tracking
Every canonical record wraps an immutable `Provenance` header:
- `source_system`: Source platform identifier (`core_banking`, `payment_switch`, `mpesa_bridge`, `aml_monitoring`, `iam_active_directory`, `siem_audit_log`, `cbs_audit_trail`, `crm_customer_service`).
- `connector_id`: Identifier of the specific adapter instance executing ingestion.
- `source_record_id`: Unique identifier assigned by the bank source system.
- `source_event_timestamp`: Primary transaction or event timestamp recorded by the bank system.
- `ingestion_timestamp`: UTC timestamp when Toroka accepted the record.
- `raw_payload_sha256`: SHA-256 hash of the unmapped source record payload for end-to-end auditability.

---

## 2. Canonical Record Types

### 2.1 CanonicalTransactionRecord (`RecordType.TRANSACTION`)
Represents financial movements across customer accounts, internal general ledgers (GL), clearing accounts, and teller drawers.

| Field | Type | Description |
|---|---|---|
| `account_ref` | `str` | Account debited or credited |
| `counterparty_ref` | `str \| None` | Opposing account reference |
| `amount` | `Decimal` | Exact decimal monetary amount |
| `currency` | `str` | ISO 4217 currency code (e.g. `KES`, `USD`) |
| `direction` | `str` | Transaction direction: `DEBIT` or `CREDIT` |
| `transaction_type` | `str` | Transaction classification (e.g. `POSTING`, `TRANSFER`, `REVERSAL`, `FEE`) |
| `narrative` | `str \| None` | Free-text description or transaction remark |
| `posting_staff_ref`| `str \| None` | Identifier of employee or service initiating posting |
| `authoriser_staff_ref`| `str \| None`| Identifier of approving supervisor (maker-checker) |
| `channel` | `str \| None` | Channel code (e.g. `BRANCH`, `MOBILE`, `ATM`, `API`) |
| `branch_code` | `str \| None` | Bank branch or operating unit code |
| `is_manual` | `bool` | True if posting was manually keyed by bank staff |

### 2.2 CanonicalStaffAccessRecord (`RecordType.STAFF_ACCESS`)
Represents employee system sessions, privilege elevations, and operational inquiries.

| Field | Type | Description |
|---|---|---|
| `staff_ref` | `str` | Employee unique identifier |
| `session_id` | `str \| None` | Application session identifier |
| `action_performed` | `str` | Action code (e.g. `VIEW_BALANCE`, `OVERRIDE_LIMIT`, `EXPORT_STATEMENT`) |
| `target_account_ref` | `str \| None` | Customer account queried or manipulated |
| `target_customer_ref`| `str \| None` | Customer profile or CIF accessed |
| `terminal_id` | `str \| None` | Workstation or terminal identifier |
| `ip_address` | `str \| None` | Originating IP address |
| `justification_code` | `str \| None` | Ticket or rationale provided for access |
| `business_justification`| `str \| None`| Free-text operational business reason |

### 2.3 CanonicalCustomerAccountRecord (`RecordType.CUSTOMER_ACCOUNT`)
Represents customer master records, account status transitions, and parameter modifications.

| Field | Type | Description |
|---|---|---|
| `account_ref` | `str` | Account identifier |
| `customer_ref` | `str` | Customer Master Reference (CIF) |
| `account_type` | `str` | Product classification (e.g. `SAVINGS`, `CURRENT`, `FIXED_DEPOSIT`) |
| `status` | `str` | Status: `ACTIVE`, `DORMANT`, `FROZEN`, `BLOCKED`, `CLOSED` |
| `previous_status` | `str \| None` | Pre-transition status code |
| `opened_at` | `datetime \| None` | Account opening timestamp |
| `status_changed_at` | `datetime \| None` | Timestamp of latest status transition |
| `status_changed_by_staff`| `str \| None` | Staff member executing status modification |
| `mobile_number` | `str \| None` | Masked customer contact reference |
| `risk_rating` | `str \| None` | AML/KYC risk rating (e.g. `LOW`, `MEDIUM`, `HIGH`) |

### 2.4 CanonicalAuditLogRecord (`RecordType.AUDIT_LOG`)
Represents tamper-evident application logs, administrative modifications, and security events.

| Field | Type | Description |
|---|---|---|
| `staff_ref` | `str \| None` | Operating actor identifier |
| `event_category` | `str` | Category (e.g. `SECURITY`, `CONFIGURATION`, `PRIVILEGE`, `DATA_ACCESS`) |
| `event_code` | `str` | Standardized event identifier |
| `target_entity_type`| `str \| None` | Target type (e.g. `ACCOUNT`, `USER`, `RULE`, `PROFILE`) |
| `target_entity_id` | `str \| None` | Identifier of affected entity |
| `details` | `dict[str, Any]`| Structured context parameters |

---

## 3. Cryptographic Payload Digest

To guarantee deterministic deduplication, every canonical record computes a SHA-256 digest:
```python
def canonical_digest(payload: dict[str, Any]) -> str:
    # Exclude volatile tracking fields
    filtered = {
        k: v for k, v in payload.items()
        if k not in {"record_id", "installation_id", "provenance"}
    }
    encoded = json.dumps(filtered, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
```
When records arrive from source connectors, identical payloads match existing records and are acknowledged as duplicates without redundant database writes.
