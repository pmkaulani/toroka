# Detector & Model Governance

## 1. Governance Lifecycle

Toroka Enterprise enforces model risk management principles (aligning with OCC Bulletin 2011-12 / Federal Reserve SR 11-7 guidance on model risk management). Every detection algorithm or statistical detector is tracked with formal governance metadata.

```text
       ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
       │  DETERMINISTIC  │       │  EXPERIMENTAL   │ ────> │    VALIDATED    │
       │ (Rule & Stat)   │       │ (Research Mode) │       │ (Production OK) │
       └─────────────────┘       └─────────────────┘       └────────┬────────┘
                                                                    │
                                                                    ▼
                                                           ┌─────────────────┐
                                                           │     RETIRED     │
                                                           │  (Decommission) │
                                                           └─────────────────┘
```

### Status Definitions

- **`DETERMINISTIC`**: Verified rule-based or closed-form statistical formulas (e.g. Median Absolute Deviation). No hidden latent states.
- **`EXPERIMENTAL`**: Prototype or candidate models undergoing benchmark testing. Barred from driving operational casework or automated alerts without supervision.
- **`VALIDATED`**: Formally reviewed and signed off by Enterprise Investigations and Risk Governance committees.
- **`RETIRED`**: Superseded versions retained solely for retrospective audit and historical replay.

---

## 2. Detection Method Metadata

Each registered detector record in `enterprise_detection_methods` answers:
1. **What generated this?** `method_id`, `description`
2. **Which version?** `version`
3. **What status?** `status`
4. **What training data?** `training_data`
5. **What validation evidence?** `validation_reference`
6. **Who approved it?** `approved_by`
7. **What are its limitations?** `limitations`

---

## 3. Future ML Boundary Protocol

Machine learning models must never bypass the canonical evidence and provenance framework. All future statistical, graph, or ML detectors must implement the standard `Detector` protocol:

```python
class Detector(Protocol):
    detector_id: str
    detector_version: str

    def detect(self, context: DetectionContext) -> DetectionResult:
        ...
```

Every `DetectionResult` is required to return:
- `signals`: tuple of generated correlation signals or anomalies
- `evidence_ids`: explicit links to ingested canonical records
- `explanation`: plain-language reasoning for human review
- `limitations`: explicit disclosure of boundary conditions
