# Toroka Enterprise — Source-to-Canonical Mapping Guide

## 1. Overview & Transformation Pipeline

Different banking platforms represent data in widely disparate formats. The mapping layer (`toroka_enterprise.integrations.mapping`) standardizes dates, amounts, and identifiers before records enter the canonical database.

---

## 2. Robust Timestamp Normalization

The `parse_timestamp()` utility handles multiple banking date representations:
- **ISO 8601 Strings**: `2026-11-15T10:30:00Z`, `2026-11-15T13:30:00+03:00`
- **Standard Banking Database Timestamps**: `2026-11-15 10:30:00`
- **Date-Only Strings**: `2026-11-15` (normalized to midnight UTC)
- **Unix Epoch Seconds**: `1763202600`
- **Unix Epoch Milliseconds**: `1763202600000`

All timestamps are normalized to UTC `datetime` objects with timezone awareness.

---

## 3. Mapping Core Banking Records to Detector Feeds

Once ingested into the canonical database, `map_canonical_to_detector_feeds()` compiles records into the runtime feeds expected by Toroka's investigation scenarios:

| Canonical Record | Toroka Engine Runtime Feed | Engine Entity Type |
|---|---|---|
| `CanonicalTransactionRecord` | `postings` | `Posting` |
| `CanonicalStaffAccessRecord` | `audit_log` | `AuditEntry` |
| `CanonicalCustomerAccountRecord` | `account_changes` | `AccountChange` |
| `CanonicalStaffRecord` | `hr_roster` | `Staff` |

If a feed lacks supporting fields (e.g. `counter_party` in postings or `salary_account` in HR roster), the mapper preserves `None` rather than fabricating values, allowing the scenario engine to degrade gracefully.
