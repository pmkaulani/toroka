# Behavioral Baselines Benchmark & Limitations

## 1. Truth in Advertising Disclosures

In accordance with institutional deployment standards, Toroka Enterprise explicitly discloses the operational status of all Phase 6 capabilities:

| Capability | Status | Evidence / Verification |
| :--- | :--- | :--- |
| **Statistical Baseline Engine** | `IMPLEMENTED` & `SYNTHETICALLY TESTED` | Verified across unit test suite with normal, empty, and outlier samples. |
| **Median Absolute Deviation (MAD)** | `IMPLEMENTED` & `SYNTHETICALLY TESTED` | Mathematical formula verified against Iglewicz-Hoaglin specifications. |
| **Baseline Admission Policy** | `IMPLEMENTED` & `SYNTHETICALLY TESTED` | Adversarial poisoning resistance verified against simulated escalating attacks. |
| **Investigation Prioritization** | `IMPLEMENTED` & `SYNTHETICALLY TESTED` | Multi-source corroboration and deduction logic verified in test suites. |
| **Model Governance Metadata** | `IMPLEMENTED` & `SYNTHETICALLY TESTED` | Seeded in database and exposed via enterprise REST endpoints. |
| **Workbench UI Integration** | `IMPLEMENTED` & `SYNTHETICALLY TESTED` | Built and verified with TypeScript and Vite bundler. |
| **Real Bank Pilot Integration** | `NOT YET VERIFIED` | Requires bank-specific connectivity and governance approval in target environment. |

---

## 2. Retention Policies

Toroka Enterprise does not retain behavioral baseline telemetry indefinitely:

1. **Behavioral Profiles**: Retained while the subject maintains an active banking relationship or employment status; pruned 180 days post-termination.
2. **Behavioral Anomalies**: Scoped to the lifecycle of the associated investigation case (default 7-year regulatory retention for banking fraud investigations).
3. **Admission Logs**: Retained for 90 days for audit and baseline validation purposes.
4. **Governance Records**: Retained permanently for auditability of historical case adjudications.

---

## 3. Known Limitations

1. **Window Cold Start**: A newly monitored subject requires at least 20 historical sample periods to reach the `MATURE` baseline state. During this warmup period, anomalies are damped to `LOW` severity.
2. **Structural Operational Shifts**: Legitimate organizational changes (e.g. employee transfer to a new branch, introduction of new product line) require explicit baseline resets or observation window adjustment.
3. **Clock Skew Sensitivity**: Cross-system correlation depends on NTP time synchronization across contributing bank systems.
