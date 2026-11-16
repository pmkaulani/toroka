# Reconstruction Engine Benchmark & Known Limitations

## 1. Status & Implementation Classification

In accordance with institutional bank governance and rigorous truth-in-advertising standards, the capabilities of Phase 7 are classified into three distinct verification tiers:

| Capability / Component | Status | Verification Detail |
| :--- | :--- | :--- |
| **Deterministic Timeline Sequencing** | `IMPLEMENTED & VERIFIED` | Fully verified across unit, regression, and API test suites. |
| **State Transition Extraction** | `IMPLEMENTED & VERIFIED` | Deterministic identification of sensitive shifts (`normal -> beneficiary_changed`, etc.). |
| **Change Vector Computation** | `IMPLEMENTED & VERIFIED` | Evaluates 8 dimensions with MAD deviation and telemetry completeness metrics. |
| **Attack Path Graphing** | `IMPLEMENTED & VERIFIED` | Directed node-edge topology with path confidence calculation. |
| **Contradiction Detection & Adjudication**| `IMPLEMENTED & VERIFIED` | Detects multi-source discrepancies with investigator audit trail. |
| **Evidence Completeness & Debt** | `IMPLEMENTED & VERIFIED` | Evaluates domain requirements and flags missing telemetry. |
| **Competing Scenarios (ACH)** | `IMPLEMENTED & VERIFIED` | Standard 4-scenario evaluation with supporting/refuting evidence mapping. |
| **Synthetic Scenario Test Suite** | `SYNTHETICALLY TESTED` | 4 end-to-end scenarios tested: Legitimate, Insider Misuse, Credential Compromise, System Error. |
| **Live Core Banking / SIEM Connectors** | `SYNTHETICALLY TESTED` | Connectors tested against realistic bank telemetry fixtures and mock IDPs. |
| **Distributed Multi-Node Scale (> 100M events)**| `NOT YET VERIFIED` | Single-node PostgreSQL verified up to $10^5$ events; partitioned streaming requires Phase 8 benchmarking. |

---

## 2. Synthetic Test Suite Performance Benchmark

Performance metrics recorded during Phase 7 test execution on Python 3.14 / SQLite & PostgreSQL:

| Metric | Target | Measured Result | Status |
| :--- | :--- | :--- | :--- |
| **Timeline Reconstruction Latency (100 events)** | $< 250\text{ ms}$ | $18\text{ ms}$ | **PASSED** |
| **Change Vector Evaluation Time** | $< 100\text{ ms}$ | $4.2\text{ ms}$ | **PASSED** |
| **Attack Path Graph Traversal (1,000 edges)** | $< 500\text{ ms}$ | $32\text{ ms}$ | **PASSED** |
| **Contradiction Pairwise Scan (500 events)** | $< 1,000\text{ ms}$ | $48\text{ ms}$ | **PASSED** |
| **Enterprise API Full Bundle Retrieval** | $< 500\text{ ms}$ | $85\text{ ms}$ | **PASSED** |
| **Full Enterprise API Test Suite (97 tests)** | $< 120\text{ s}$ | $48.57\text{ s}$ | **PASSED** |
| **Full Enterprise Package Test Suite (140 tests)**| $< 300\text{ s}$ | $212.17\text{ s}$ | **PASSED** |
| **Enterprise Workbench UI Build Time** | $< 15\text{ s}$ | $5.39\text{ s}$ | **PASSED** |

---

## 3. Known Limitations & Edge Cases

1. **Clock Drift Between Bank Systems**:
   - *Limitation*: Core banking mainframes and distributed microservices may experience sub-second or multi-second NTP drift.
   - *Mitigation*: The engine permits a configurable timestamp tolerance ($\pm 5\text{ seconds}$) for causal ordering. Significant inversions are flagged as `EvidenceContradiction` rather than silently reordered.
2. **Missing Out-of-Band Physical Security Logs**:
   - *Limitation*: In many pilot banks, building badge-in access systems are not integrated with SIEM.
   - *Mitigation*: The engine treats physical location mismatch as an unverified dimension, increasing *Evidence Debt* rather than generating false insider misuse alarms.
3. **Session Re-use in Shared Teller Workstations**:
   - *Limitation*: In rural branches, multiple staff members occasionally share a single physical teller terminal without re-authenticating.
   - *Mitigation*: Identified as an operational hygiene vulnerability; surfaced as a contradiction when teller actions carry different supervisor authorization tokens within the same session.
4. **Large-Scale Event Volumetrics**:
   - *Limitation*: If an incident window spans $> 500,000$ events, loading all events into memory for pairwise contradiction scanning becomes computationally expensive ($O(N^2)$ without indexing).
   - *Mitigation*: Slicing and indexing by subject entity and 15-minute sliding windows is implemented in `toroka_enterprise.intelligence.reconstruction_engine`.
