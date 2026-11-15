# Toroka Enterprise — Intelligence Benchmark, Verification Status & Known Limitations

## 1. Truth in Capability: Rigorous Verification Status

In accordance with bank enterprise evaluation standards, Toroka explicitly categorizes the implementation status of its cross-system intelligence capabilities:

| Component | Status | Verification Detail |
|---|---|---|
| Entity Reference & Relationship Model | `IMPLEMENTED` & `SYNTHETICALLY TESTED` | 100% test coverage in `test_intelligence_entities.py` |
| Temporal Correlation Engine | `IMPLEMENTED` & `SYNTHETICALLY TESTED` | Bounded window filtering verified in `test_intelligence_correlation.py` |
| 6 Cross-System Correlation Rules (A–F) | `IMPLEMENTED` & `SYNTHETICALLY TESTED` | All rules verified in `test_intelligence_rules.py` |
| Competing Hypotheses & Bundling | `IMPLEMENTED` & `SYNTHETICALLY TESTED` | Multi-hypothesis testing verified in `test_intelligence_hypotheses.py` |
| Intelligence API Endpoints | `IMPLEMENTED` & `SYNTHETICALLY TESTED` | Endpoints, OIDC auth, and role checks verified in `test_intelligence_api.py` |
| Enterprise Workbench UI | `IMPLEMENTED` & `SYNTHETICALLY TESTED` | TypeScript type-check and Vite production build verified |
| Core Banking Live Connector (Finacle/T24) | `NOT YET VERIFIED` (requires pilot) | Live socket/VPN integration requires bank host environment |
| Real Bank Regulatory Certification | `NOT YET VERIFIED` | Bank pilot evaluation required; no false claims of CBK/PRA approval |

---

## 2. Known Limitations & Scope Boundaries

1. **Synthetic & Sandbox Validation Only**:
   All correlation rules, temporal windows, and hypothesis workflows have been validated against rigorous synthetic test datasets and isolated API test harnesses. They have not yet executed against live production core banking mainframes.
2. **Deterministic Rules vs. Machine Learning**:
   Phase 5 implements deterministic, explainable rule families (A–F). It does NOT include unexplainable deep neural networks or black-box classifiers.
3. **1-Hop Relationship Traversal**:
   Entity relationship queries currently support 1-hop direct connections to prevent runaway relational joins. Deep multi-hop transitive traversals require dedicated graph indexing in future phases.
4. **Data Dependency on Ingestion**:
   If an integration connector is disabled or delayed, correlation rules that depend on that feed will gracefully omit signals rather than guessing. Missing data is NEVER treated as evidence of fraud.
