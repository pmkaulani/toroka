# Toroka Enterprise — Ingestion Data Quality & Scenario Readiness

## 1. Overview & Institutional Principle

In enterprise banking investigations, the worst outcome of data integration is generating false accusations of fraud against bank personnel due to missing or misaligned data feeds.

Toroka treats data quality as a governance checkpoint that directly influences scenario execution.

---

## 2. Ingestion Quality Checks

The quality assessment module (`toroka_enterprise.integrations.quality`) performs continuous structural and semantic evaluations:

| Rule Category | Check Description | Error Handling |
|---|---|---|
| Mandatory Field Presence | Validates essential keys (e.g. `amount`, `account_ref`, `staff_ref`) | Rejects record with `MISSING_REQUIRED_FIELD` |
| Amount Sanitization | Detects negative amounts in non-reversal fields, NaN, or non-numeric strings | Rejects record with `INVALID_AMOUNT` |
| Currency Validation | Validates 3-letter uppercase ISO 4217 code | Warning or default to installation currency |
| Timestamp Sanity | Checks for future timestamps (> 24 hours ahead) or invalid dates | Rejects record with `INVALID_TIMESTAMP` |

---

## 3. Coupling to Detector Readiness (Phase 2)

Toroka directly maps ingested quality reports into Phase 2 detector readiness:

```
[Quality Assessment]
        │
        ▼
Evaluate required and supporting fields for each registered scenario:
- Dormant Account Activation (DormantReactivation)
- Split Cash Balancing (SplitCashBalancing)
- Unauthorized Payroll Changes (PayrollBeneficiary)
- Sensitive VIP Inquiries (AccessJustification)
        │
        ├── All required & supporting fields present ──> READY
        ├── Required fields present, supporting missing -> DEGRADED
        └── Required fields missing ───────────────────> BLIND
```

When an investigator reviews an alert, the workbench displays the exact operational mode:
- **`READY`**: Full confidence correlation.
- **`DEGRADED`**: Scenario runs with partial evidence; confidence scores reflect absence of supporting feeds.
- **`BLIND`**: Scenario disabled; explanation provided to Data Steward explaining which bank source feeds must be onboarded.
