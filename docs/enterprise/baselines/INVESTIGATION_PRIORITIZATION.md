# Investigation Prioritization Framework

## 1. Operational Triage vs. Fraud Probability

A critical architectural distinction in Toroka Enterprise:

> **IMPORTANT INSTITUTIONAL SAFEGUARD**:
> The `priority_score` produced by Toroka Enterprise is an **operational triage metric** designed to help human investigators prioritize limited analytical resources. It is **explicitly NOT a probability of fraud or employee guilt**.

```text
               SIGNAL SEVERITY & CONFIDENCE
                           +
               BEHAVIORAL DEVIATION & MATURITY
                           +
               INDEPENDENT SOURCE CORROBORATION
                           +
               UNRESOLVED CONTRADICTION TRACKING
                           │
                           ▼
               INVESTIGATION PRIORITY (0–100)
```

---

## 2. Prioritization Score Calculation

The priority score $S \in [0, 100]$ combines explainable components:

### 1. Cross-System Correlation Signals
For each signal $i \in \text{Signals}$:
- Critical Severity: $+40.0$ points
- High Severity: $+25.0$ points
- Medium Severity: $+15.0$ points
- Low / Info Severity: $+5.0$ points
- Confidence Contribution: $+\text{Confidence}_i \times 10.0$ points

### 2. Multi-Source Corroboration Bonus
When signals draw evidence across distinct independent systems (e.g. Core Banking + IAM + HR):
$$\text{Corroboration Bonus} = \min((\text{Source Count} - 1) \times 5.0, 15.0)$$
Repeated log copies from a single source (e.g. three replicated SIEM feeds) do **not** trigger corroboration bonuses.

### 3. Behavioral Deviations
For each anomaly $j \in \text{Anomalies}$:
- High Severity: $+20.0$ points
- Medium Severity: $+10.0$ points
- Low Severity: $+3.0$ points

### 4. Review Threshold
Cases with $S \ge 40.0$ are flagged with `requires_review = True` and escalated to priority investigator queues.

---

## 3. Explainability & Reason Strings

Every calculation returns an explicit list of contributing drivers:
- `"Correlation signal: Access Followed By Beneficiary Modification"`
- `"Corroborated across 2 independent sources (core_banking, iam)"`
- `"Established behavioral deviation: beneficiary_changes"`
- `"Note: 1 competing explanation(s) or contradiction(s) require review"`
