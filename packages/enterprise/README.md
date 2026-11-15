# Toroka Enterprise (insider-risk investigation, seed)

Decision support for authorised investigators. It surfaces **leads with cited evidence**; it never labels a person.
Built on `toroka_core` (shared with the consumer app): typed evidence, source-independent scoring, injectable profile.

## What exists
| Module | Job |
|---|---|
| `data_contract.py` | Versioned bank data contract and detector dependency registry: field metadata, PII classifications, readiness expectations, Markdown/JSON catalogue generation, deterministic contract hashing |
| `coverage.py`, `discover.py` | Formal readiness engine (READY, DEGRADED, CHECK, BLIND) driven by the central data contract registry; mapping suggester (drafts only) |
| `mapping.py`, `ingest.py`, `schema.py`, `pseudonym.py` | Read-only flat-file extracts from any system via a mapping file -> keyed-HMAC pseudonymised dataset + a **data-quality report** (rejected rows, missing feeds, unmapped accounts, naive timestamps read as EAT, branches with incomplete CRM, absent-field detection) |
| `scenarios.py` | Eight providers: access justification, bulk browsing, contact/authentication change, dormant/deceased reactivation, change-then-money, suspense-posting integrity, payroll beneficiary integrity, entitlement integrity |
| `profile.py` | Insider scoring policy and wording: no time decay on case evidence; **no single rule hit can take the "critical" shortcut**; review-state labels instead of risk verdicts |
| `scan.py` | Candidate focuses -> `EvidenceEngine` -> surfaced leads (PRIORITY REVIEW / REVIEW / CONFLICTING RECORDS) |
| `casework.py`, `audit.py` | RBAC case store, **dual-approval identity reveal** (different user, written reason, single use, 24h expiry), closing requires the alternative explanations considered; hash-chained append-only audit log |
| `manifest.py`, `report.py` | Run manifests, reproduce, and self-contained HTML investigation reports |
| `foreign.py`, `replay.py` | Foreign-shaped test exports; synthetic extracts with injected patterns drawn from public cases, plus hard negatives and an evaluation harness |

## Run
```
export PYTHONPATH=../smart-scam-identifier/packages/core:.     # or TOROKA_CORE_PATH for tests
python -m toroka_enterprise demo            # synthetic end-to-end
python -m pytest -q                         # 66 tests
TOROKA_ENT_SECRET=... TOROKA_ENT_VAULT_KEY=$(python -m toroka_enterprise keygen) \
  python -m toroka_enterprise scan --data ./extracts --out ./out
```
Canonical feeds are specified in `ingest.SPEC` and `data_contract.py`. `audit_log` and `system_accounts` are required; every other feed that is absent is reported as "could not check" or "blind", never as clean.

## Bank Data Contract & Detector Readiness Framework (Phase 2)
The data contract directly answers the bank's core evaluation question:
*“Given the data our systems can provide, which insider-risk scenarios can Toroka actually investigate, which are partially assessable, and which are impossible to assess?”*

### 1. Canonical Feeds & Field Catalog
There are 9 canonical feeds defined centrally in `data_contract.py`, `ingest.SPEC`, and `mapping.OPTIONAL`:
- **`audit_log` (Required)**: Chronological core-banking audit trail (`ts`, `account_id`, `action`, `customer_id`, `approver_account_id`).
- **`system_accounts` (Required)**: User registry (`account_id`, `staff_id`, `system`, `status`, `is_privileged`).
- **`portfolio`**: Relationship manager customer assignments (`staff_id`, `customer_id`).
- **`service_requests`**: CRM tickets justifying profile lookups (`request_id`, `customer_id`, `staff_id`, `opened_at`, `closed_at`, `kind`).
- **`instructions`**: Customer mandate register (`instruction_id`, `customer_id`, `kind`, `received_at`, `recorded_at`).
- **`payments`**: Transaction feed (`payment_id`, `ts`, `customer_id`, `channel`, `amount`, `beneficiary`).
- **`customers`**: Customer master (`customer_id`, `status`, `dormant_since`, `deceased_flag`, `is_sensitive`).
- **`postings`**: General ledger journals (`posting_id`, `ts`, `ledger`, `counter_party`, `amount`, `entered_by_account`, `approved_by_account`, `manual`, `narrative`).
- **`hr_roster`**: Employee master (`staff_id`, `status`, `role`, `branch`, `end_date`, `salary_account`).

### 2. Readiness States
Each scenario detector evaluates to one of four readiness states:
- **`READY`**: All required feeds and fields are present, and data quality meets reliability standards.
- **`DEGRADED`**: The detector can run, but important supporting data is missing (e.g. no CRM tickets to justify lookups, no `approver_account_id` on audit log, no `is_privileged` flag) or the input feed has high row rejection / unmapped codes.
- **`CHECK`**: Feeds and fields are present, but relevant action codes or event types were not observed in the dataset (potential mapping gap or quiet period).
- **`BLIND`**: A material required feed or field is missing (e.g. no `portfolio` assignments, no `postings`, or missing `salary_account` in HR roster).

### 3. Detector-to-Feed Dependency Matrix
| Detector ID | Scenario | Required Feeds | Required Fields | Supporting Feeds / Fields |
|---|---|---|---|---|
| `access_justification` | Access Justification | `audit_log`, `portfolio` | `audit_log.*`, `portfolio.*` | `service_requests.staff_id` |
| `bulk_unjustified_browsing` | Bulk Browsing | `audit_log`, `portfolio` | `audit_log.*`, `portfolio.*` | `customers.is_sensitive`, `service_requests` |
| `auth_channel_change` | Contact / Auth Change | `audit_log`, `instructions` | `audit_log.*`, `instructions.*` | `audit_log.approver_account_id` |
| `account_lifecycle` | Dormant / Deceased Reactivation | `audit_log`, `customers`, `instructions` | `audit_log.*`, `customers.status`, `instructions.*` | `audit_log.approver_account_id`, `customers.deceased_flag` |
| `change_then_money` | Change Followed by Money | `audit_log`, `payments`, `instructions` | `audit_log.*`, `payments.*`, `instructions.*` | `payments.beneficiary`, `payments.channel` |
| `suspense_posting_integrity` | Suspense / Dispute Postings | `postings` | `postings.*`, `postings.approved_by_account` | `postings.counter_party`, `payments` |
| `payroll_beneficiary_integrity` | Payroll Beneficiary Integrity | `postings`, `hr_roster` | `postings.*`, `hr_roster.salary_account` | `postings.counter_party` |
| `entitlement_integrity` | Entitlement & Leaver Activity | `system_accounts` | `system_accounts.*` | `system_accounts.is_privileged`, `hr_roster` |

### 4. How to Generate the Data Contract
Generate the bank-facing data catalogue in Markdown or machine-readable JSON:
```bash
# Print the bank data catalogue to terminal
python -m toroka_enterprise data-contract --format markdown

# Export machine-readable contract specification
python -m toroka_enterprise data-contract --format json --out bank-data-contract.json
```

### 5. How to Validate a Bank's Extracts
Before running a scan or ingestion, run a dry-run validation to test feed coverage, column mapping, and data quality:
```bash
# Terminal summary
python -m toroka_enterprise validate --data ./extracts --mapping mapping.toml

# Machine-readable JSON output for automated pipelines
python -m toroka_enterprise validate --data ./extracts --mapping mapping.toml --json
```

### 6. Absent Field Reporting & Ingest Consistency
Both canonical CSVs (`_read`) and mapped extracts (`read_mapped`) consistently record unsupplied optional fields into `DataQuality.absent_fields` using qualified `feed.field` naming without duplicates. When a material field is absent (e.g. `system_accounts.is_privileged`), scenario detectors stand down or report degraded context rather than manufacturing an unsupported fraud accusation.

## Working on any system (no per-bank code)
The engine never sees a core-banking vendor. A bank's exports are translated into the canonical feeds by a **mapping file** (TOML): per feed, which file/glob, delimiter, encoding, which source column is each canonical column, the timestamp format (`iso`, `epoch_s`, `epoch_ms` or any strptime pattern), and how the bank's codes translate (action codes, suspense GL codes, status flags).
```
python -m toroka_enterprise suggest-mapping --file AUDIT_TRAIL.txt --feed audit_log --out audit.toml   # a DRAFT: confirm every line
python -m toroka_enterprise validate --data ./extracts --mapping mapping.toml                          # reads, reports, writes nothing
python -m toroka_enterprise scan --data ./extracts --mapping mapping.toml --out ./out
```
Three behaviours make this safe on unfamiliar data: **unmapped codes are counted and reported** (never dropped silently); **fields the system does not supply are recorded as absent** and dependent checks stand down instead of inferring risk (no approver column does not mean "unapproved"); and the **coverage report** lists, per detector, READY / DEGRADED / CHECK / BLIND on that bank's data. "Works on any system" therefore means: works to the extent the system exposes the events a detector needs, and says plainly where it does not.

Proof, with limits: two deliberately foreign exports (pipe-delimited with `dd/mm/yyyy` dates and vendor-style codes; tab-delimited with epoch seconds and dotted codes) produce findings identical to the canonical run. Both styles are **invented by me**, so this shows the mechanism works, not that any real vendor's export is covered. The suggester is a heuristic that matched all five audit-log columns on both invented styles; expect to correct it by hand on real exports. Not supported: fixed-width, XML/JSON or direct database reads; files are loaded in memory (very large audit logs need a streaming reader).

## Reproducibility and investigation reports
Every scan writes `run.json`: a **manifest** (SHA-256 of each source file, mapping hash, scoring-policy hash, thresholds, contract version and fingerprint, tool version, key *fingerprint* never the key, ingest time) and a **result digest**. `reproduce` re-runs from the manifest and reports one of: identical; source files differ (named, and described as a different analysis, not a failed reproduction); configuration differs; or inputs and configuration match but the result differs (a non-determinism bug). A source record is cited by feed, file hash and row number; row-level hashes are not stored.
```
TOROKA_ENT_SECRET=... python -m toroka_enterprise reproduce --data ./extracts --mapping mapping.toml --out ./out
python -m toroka_enterprise report --out ./out --lead 1          # or --all; scan/demo also write ./out/reports/*.html
```
Each report is a single self-contained HTML file: assessment, an evidence map by independent source, a chronological table of what the records show, inferences kept separate from facts, what could not be checked, alternative explanations to rule out, next steps, provenance, and a reviewer sign-off block. All bank-supplied strings are HTML-escaped (tested with a hostile record id).

## What the synthetic result does and does not mean
The demo finds 9/9 injected patterns with 0 false review leads (also across 20 seeds). The injected patterns are the ones the providers were written for and the benign data comes from my own generator, so this is a **regression harness, not evidence of real-world performance**. Two things it does show: switching the CRM-gap gating off produces false leads from the one branch whose CRM isn't integrated, so data-quality gating is load-bearing; and the tests fail when guards are removed (mutation-checked).

## Not built / known limits
- No authentication or SSO: callers pass a `Principal`; a bank deployment must supply identities from its IdP.
- Audit chain is tamper-**evident**: deleting the tail is only detectable against a head hash stored outside the DBA's control.
- Batch extracts only; no live connectors, no streaming, no UI. SQLite stores are single-node.
- Shared/generic accounts, third-party (vendor) sessions, cash/vault reconciliation and whistleblower intake are not implemented.
- Thresholds (`Rules`) are defaults to be calibrated against a bank's own adjudicated cases.
- Legal review is required before processing any staff data (Data Protection Act DPIA, employment procedure, FRC confidentiality).
