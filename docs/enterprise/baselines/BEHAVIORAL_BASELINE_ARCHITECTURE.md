# Behavioral Baseline Architecture

## 1. Executive Summary

Phase 6 introduces the **Adaptive Detection, Behavioral Baselines & Investigation Prioritization Layer** for Toroka Enterprise. While Phase 5 provided cross-system entity resolution and temporal event correlation, Phase 6 provides deterministic capabilities to determine **what constitutes normal behavior for a specific employee, customer, account, branch, device, or system workflow** without resorting to unexplainable black-box machine learning models.

```text
               BANK SOURCE SYSTEMS (Core Banking, IAM, HR, Switch, SIEM, CRM)
                                     │
                                     ▼
                        Phase 4 Canonical Ingestion Gateway
                                     │
                                     ▼
                   ┌──────────────────────────────────────┐
                   │   Baseline Admission Control Guard   │
                   │  (Poisoning & Contamination Defense) │
                   └──────────────────┬───────────────────┘
                                      │ eligible events only
                                      ▼
                   ┌──────────────────────────────────────┐
                   │      Behavioral Baseline Engine      │
                   │  (Profiles, Windows & Distributions) │
                   └──────────────────┬───────────────────┘
                                      │
                                      ▼
                   ┌──────────────────────────────────────┐
                   │    Deviation & Anomaly Calculator    │
                   │ (Median Absolute Deviation / Mod Z)  │
                   └──────────────────┬───────────────────┘
                                      │
                                      ▼
                   ┌──────────────────────────────────────┐
                   │     Investigation Prioritization     │
                   │ (Cross-System Triage & Corroboration)│
                   └──────────────────┬───────────────────┘
                                      │
                                      ▼
                         ENTERPRISE WORKBENCH UI
```

---

## 2. Core Behavioral Dimensions

The behavioral baseline engine captures distributions across nine bounded dimensions:

| Dimension | Description | Typical Unit | Default Window |
| :--- | :--- | :--- | :--- |
| `hourly_activity` | Volume of actions performed per hour of day | Actions / hour | Rolling 30 days |
| `daily_activity` | Total operational volume per business day | Actions / day | Rolling 60 days |
| `transaction_count` | Number of financial postings or payouts generated | Postings / day | Rolling 30 days |
| `transaction_value` | Monetary magnitude of financial postings | Total amount / day | Rolling 60 days |
| `customer_access` | Count of distinct customer profiles viewed or inspected | Profiles / day | Rolling 30 days |
| `beneficiary_changes` | Frequency of modifications to payee or disbursement records | Changes / day | Rolling 90 days |
| `login_frequency` | Authentication events and session starts | Logins / day | Rolling 30 days |
| `device_usage` | Count of distinct physical terminals or MAC/IP pairs used | Terminals / week | Rolling 30 days |
| `branch_activity` | Cross-branch terminal access outside assigned home branch | Branches / week | Rolling 90 days |

---

## 3. Baseline Maturity Lifecycle

A foundational principle of Toroka Enterprise is that **new or newly monitored subjects must not be evaluated with the same certainty as subjects with extensive historical baselines**.

```text
       Sample Count < 10            10 <= Sample Count < 20             Sample Count >= 20
   ┌───────────────────────┐       ┌───────────────────────┐       ┌───────────────────────┐
   │     INSUFFICIENT      │ ────> │      DEVELOPING       │ ────> │        MATURE         │
   │   Confidence: 0.30    │       │   Confidence: 0.60    │       │   Confidence: 0.90    │
   │  Max Severity: LOW    │       │  Max Severity: LOW    │       │  Max Severity: HIGH   │
   └───────────────────────┘       └───────────────────────┘       └───────────────────────┘
```

1. **`INSUFFICIENT` (< 10 samples)**:
   - Initial observation period.
   - Any deviation generated is strictly capped at `LOW` severity.
   - Confidence factor is restricted to 0.30.
   - Explicit reason string: `"Limited-history behavioral deviation"`.

2. **`DEVELOPING` (10–19 samples)**:
   - Intermediate baseline under formation.
   - Maximum severity remains `LOW` to prevent premature false alarms.
   - Confidence factor is 0.60.

3. **`MATURE` (>= 20 samples)**:
   - Established statistical distribution.
   - Deviation magnitude directly drives severity:
     - `|Deviation| >= 6.0` &rarr; `HIGH`
     - `|Deviation| >= 4.0` &rarr; `MEDIUM`
     - `|Deviation| < 4.0` &rarr; `LOW`
   - Confidence factor is 0.90.
   - Explicit reason string: `"Established behavioral deviation"`.

---

## 4. Institutional Safeguard & Non-Accusatory Posture

Toroka Enterprise enforces a strict semantic boundary:
- **`BehavioralAnomaly` != `Fraudulent Behavior`**:
  Anomalies capture statistical deviations from historical patterns (e.g. end-of-quarter volume surges, new responsibilities, system failover workflows).
- **`InvestigationPriority` != `Probability of Fraud`**:
  Prioritization scores (0–100) are operational triage values designed to order investigator review queues, never automated judgments of employee guilt.
