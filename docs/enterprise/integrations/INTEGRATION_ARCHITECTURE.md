# Toroka Enterprise — Bank Integration Architecture

## 1. Executive Summary & Design Principles

Toroka Enterprise is designed to interface with existing commercial bank infrastructure without requiring the replacement or modification of core banking systems (CBS), payment switches, transaction monitoring platforms, or identity directories.

The integration layer adheres to five non-negotiable architectural principles:
1. **Strict Read-Only Access**: Toroka connectors NEVER execute write operations, debit/credit transactions, account status modifications, or privilege escalations in bank production systems. All queries run against approved read-replicas, reporting views, export directories, or read-only service accounts.
2. **Canonical Data Normalization**: Source-specific schemas (e.g. Finacle, Flexcube, T24, BaNCS, custom payment switches) are ingested and immediately translated into standardized, versioned canonical contracts (`packages/enterprise/toroka_enterprise/integrations/contracts.py`).
3. **Idempotent Ingestion & Audited Corrections**: Ingesting duplicate records produces zero side effects. Legitimate corrections from source systems are tracked as new versions (`version = n + 1`, `status = "corrected"`), preserving a tamper-evident audit history of all changes.
4. **Resilient Scenario Degradation**: Incomplete source feeds or connector outages degrade specific insider-risk detectors into `DEGRADED` or `BLIND` states rather than crashing the system or generating false fraud accusations against employees.
5. **Separation of Integration and Casework Credentials**: Operational integration service accounts operate on isolated credentials separate from caseworkers, identity vault decryptors, and system administrators.

---

## 2. High-Level Architecture Diagram

```
+----------------------------------------------------------------------------------------------------+
|                                      COMMERCIAL BANK PERIMETER                                     |
+----------------------------------------------------------------------------------------------------+
|  Core Banking (CBS)   |   Payment Switch / M-PESA   |   IAM / Active Directory   |   SIEM / Audit Logs |
|  [Postgres/Oracle/DB2]|   [Webhook / ISO 8583 REST] |   [HR Roster / LDAP Export]|   [Syslog / Kafka]  |
+----------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼ (TLS 1.3 / mTLS / IP Whitelisted)
+----------------------------------------------------------------------------------------------------+
|                                    TOROKA INTEGRATION GATEWAY                                      |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  +--------------------+  +--------------------+  +--------------------+  +---------------------+   |
|  | BankRestConnector  |  | BankFileConnector  |  |BankDatabaseConnector| |  BankEventConnector |   |
|  | (REST API / Cursors|  | (CSV / JSONL /     |  | (Read-Only Views / |  |  (HMAC-SHA256 Web- |   |
|  |  SSRF Whitelist)   |  |  SFTP Ingestion)   |  |  Offset Batching)  |  |   hook Ingestion)   |   |
|  +--------------------+  +--------------------+  +--------------------+  +---------------------+   |
|                                                                                                    |
|  +----------------------------------------------------------------------------------------------+  |
|  | Ingestion Engine: Deduplication (SHA-256 Digest), Versioned Corrections, Row-Level Cursors   |  |
|  +----------------------------------------------------------------------------------------------+  |
|                                                  │                                                 |
|                                                  ▼                                                 |
|  +----------------------------------------------------------------------------------------------+  |
|  | Canonical Evidence Store (PostgreSQL / Integration Tables)                                   |  |
|  | - enterprise_integration_records (Versioned canonical records with provenance)               |  |
|  | - enterprise_integration_cursors (Row-locked progress tracking)                              |  |
|  | - enterprise_integration_jobs (Sync execution audit)                                         |  |
|  | - enterprise_integration_events_inbox (Replay-protected webhook storage)                     |  |
|  | - enterprise_integration_rejected (Dead-letter queue with reason codes)                       |  |
|  +----------------------------------------------------------------------------------------------+  |
+----------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+----------------------------------------------------------------------------------------------------+
|                               TOROKA ENTERPRISE INVESTIGATION ENGINE                               |
+----------------------------------------------------------------------------------------------------+
|  - Data Quality Assessment & Detector Readiness Mapping (READY, DEGRADED, BLIND)                   |
|  - Correlation Engine & Insider Risk Scenarios (Dormant Activation, Split Postings, etc.)           |
|  - Pseudonymous Casework, Ephemeral Vault Reveals, and Cryptographic Audit Hash Chain               |
+----------------------------------------------------------------------------------------------------+
```

---

## 3. Core Subsystems

### 3.1 Connector Layer
The connector subsystem (`toroka_enterprise.integrations.connectors`) provides four standardized adapters:
- **`BankRestConnector`**: Consumes paginated JSON endpoints via HTTPS. Enforces hostname allowlisting to defend against Server-Side Request Forgery (SSRF), handles HTTP 429 rate-limiting with exponential backoff, and tracks resumption cursors.
- **`BankFileConnector`**: Ingests structured CSV and JSONL files delivered via secure file transfers (SFTP/local mounts). Verifies SHA-256 file checksums prior to processing and maintains sorted directory cursors.
- **`BankDatabaseConnector`**: Connects directly to bank-maintained read-only views (e.g. `vw_core_transactions`, `vw_staff_roster`). Enforces query allowlists to prevent arbitrary SQL execution.
- **`BankEventConnector`**: Ingests push-based webhooks with HMAC-SHA256 signature verification and clock-skew tolerance (default 300 seconds).

### 3.2 Ingestion & Deduplication Pipeline
All ingested source items pass through `ingest_batch()`:
- **Payload Digest**: Computes a deterministic SHA-256 hash across sorted canonical record fields.
- **Duplicate Suppression**: If a record with matching `(installation_id, source_system, source_record_id)` exists with the identical payload digest, it is recognized as an idempotent duplicate and skipped.
- **Versioned Corrections**: If the source record exists but has an altered payload digest, the engine appends a new record version (`version = previous.version + 1`, `status = "corrected"`). Overwrites are strictly prohibited.
- **Rejection Logging**: Ill-formed records failing Pydantic schema validation or timestamp extraction are routed to `enterprise_integration_rejected` with structured reason codes.

### 3.3 Data Quality & Detector Coupling
Ingested canonical records feed the Phase 2 detector readiness assessment (`assess_detector_readiness_from_integration`):
- If critical feeds (`postings`, `hr_roster`) lack mandatory fields (e.g. `salary_account`, `staff_ref`), affected scenarios transition to `DEGRADED` or `BLIND`.
- Missing fields are NEVER interpreted as evidence of fraud. Investigators are notified of data gaps directly on the Enterprise Workbench.
