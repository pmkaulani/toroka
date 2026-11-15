# Toroka Enterprise — Ingestion Reconciliation & Count Audits

## 1. Overview & Regulatory Mandate

Banking supervisors (e.g. Central Bank of Kenya, Prudential Regulation Authority) require financial institutions to demonstrate complete, unreconciled audit trails for risk monitoring platforms.

Toroka provides an automated reconciliation service (`generate_reconciliation_report`) to verify that no transactions were dropped or lost during transfer between bank systems and Toroka.

---

## 2. Reconciliation Execution & Formula

Reconciliation can be triggered on-demand or scheduled daily at end-of-day:

`POST /api/enterprise/v1/integrations/reconciliation`

```json
{
  "connector_id": "cbs-core-01",
  "expected_source_count": 150000,
  "window_start": "2026-11-15T00:00:00Z",
  "window_end": "2026-11-15T23:59:59Z"
}
```

The service computes:
```
Total Effective Records = Ingested Records (active) + Versioned Corrections + Rejected Records
Discrepancy = Total Effective Records - Expected Source Count
```

### 2.1 Reconciliation Status Codes
- **`reconciled`**: `Discrepancy == 0`. Bank source extraction count exactly matches Toroka's accounting ledger.
- **`discrepancy_detected`**: `Discrepancy != 0`. Visual alert flagged on the Enterprise Workbench with audit note indicating potential network drop or extraction gap.
