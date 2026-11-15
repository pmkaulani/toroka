# Toroka Enterprise — Cross-System Fraud Intelligence Architecture

## 1. Executive Summary & Design Philosophy

Traditional financial-crime and insider-risk platforms operate in silos:
- The Core Banking System (CBS) detects isolated transaction balance discrepancies.
- The Identity & Access Management (IAM) platform flags unusual after-hours logins.
- The Payment Switch detects velocity spikes.
- The HR System tracks leave, resignations, and disciplinary reviews.

Because these platforms do not communicate, investigators are forced to manually reconcile disparate audit dumps, leading to missed insider collusion or rushed false accusations.

**Toroka Enterprise Phase 5 transforms Toroka into a cross-system intelligence layer.** It correlates sequences and relationships across Core Banking + Payments + IAM + HR + AML + SIEM + CRM within bounded temporal windows without disrupting existing banking infrastructure.

---

## 2. Core Architectural Principles

### 2.1 The Non-Accusatory Standard
Toroka strictly forbids generating opaque or accusatory output such as:
> *"Employee X is fraudulent: 94%."*

Instead, Toroka synthesizes:
1. **Observed Facts**: Timestamped, cryptographically verified actions (e.g., teller logged in at 14:02, queried customer CIF at 14:06, changed beneficiary at 14:14).
2. **Correlated Signals**: Deterministic patterns indicating anomalous temporal sequences across independent systems.
3. **Alternative Explanations**: Plausible, legitimate operational reasons (e.g., customer was physically present at the branch, routine teller keying error correction).
4. **Missing Evidence**: Concrete records that investigators must retrieve before making a finding (e.g., CRM service ticket, signed mandate form, dual-control supervisor log).
5. **Competing Hypotheses**: Mutually exclusive explanations tested simultaneously by investigators.
6. **Signal Confidence**: Reflects confidence that the *pattern* occurred as recorded, NOT the probability of an individual's guilt.
7. **Mandatory Human-in-the-Loop Review**: Automated sanctions, employee suspensions, account freezing, or disciplinary actions are strictly forbidden.

---

## 3. Subsystem Architecture

```
+----------------------------------------------------------------------------------------------------+
|                                    BANK SOURCE FEED ADAPTERS                                       |
|     Core Banking (CBS)   │   Payment Switch / M-PESA   │   IAM / Active Directory   │   CRM / Logs     |
+----------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼ (Phase 4 Canonical Ingestion)
+----------------------------------------------------------------------------------------------------+
|                                  INTELLIGENCE NORMALIZATION LAYER                                  |
|   - IntelligenceEvent: event_id, event_type, actor, subject, source_system, provenance_digest      |
|   - EntityRef & Relationship: installation-scoped nodes and edges with provenance & confidence      |
+----------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+----------------------------------------------------------------------------------------------------+
|                                    TEMPORAL CORRELATION ENGINE                                     |
|   - Configurable Bounded Windows (e.g. [-60m, +60m], [-24h, +24h])                                 |
|   - Deterministic Ordering by (event_time, event_id)                                               |
|   - Strict Installation Isolation (cross-tenant joins strictly rejected)                            |
+----------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+----------------------------------------------------------------------------------------------------+
|                                   CORRELATION RULE ENGINE (A-F)                                    |
|   - Rule A: Access Before Sensitive Account Change                                                 |
|   - Rule B: Privileged Login Before Manual/Override Transaction                                    |
|   - Rule C: Role/Permission Change Before Sensitive Activity                                       |
|   - Rule D: Employee Activity Before Reversal or Closure                                           |
|   - Rule E: Customer Complaint Correlated Staff Inquiries                                          |
|   - Rule F: Authentication Anomaly (New IP/Device) With Sensitive Action                           |
+----------------------------------------------------------------------------------------------------+
                                                  │
                                                  ▼
+----------------------------------------------------------------------------------------------------+
|                             INVESTIGATION BUNDLE & CASEWORK INTEGRATION                            |
|   - Competing Hypotheses: H1 (Unauthorized), H2 (Legitimate Service), H3 (Compromised Session)     |
|   - Evidence & Gaps Checklist (Required vs Missing Documents)                                     |
|   - Enterprise Workbench Interactive Timeline & Entity Relationship Graph                           |
+----------------------------------------------------------------------------------------------------+
```
