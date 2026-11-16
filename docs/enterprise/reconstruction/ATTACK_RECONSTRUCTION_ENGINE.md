# Toroka Attack Reconstruction Engine

## 1. Executive Summary

Phase 7 introduces the **Toroka Attack Reconstruction Engine**. While conventional fraud systems rely on opaque composite risk scores (e.g., "Risk Score: 87/100"), Toroka provides banks with a deterministic, evidence-backed narrative that answers the investigator's core question: **"Show me exactly how this incident unfolded."**

The Attack Reconstruction Engine does not replace investigator judgement and does not produce automatic legal or disciplinary findings. Instead, it aggregates heterogeneous, cryptographically verified canonical events across IAM, Core Banking, Payment Switches, CRM, SIEM, and HR into a unified causal sequence. Every step links directly to underlying evidence, surfaces critical state transitions, tracks multi-source contradictions, quantifies missing telemetry ("Evidence Debt"), and formulates structured competing hypotheses.

```text
       CANONICAL EVENT STREAM (IAM, Core Banking, Switch, SIEM, HR, CRM)
                                    │
                                    ▼
                ┌──────────────────────────────────────┐
                │   Deterministic Sequencing Engine    │
                │  (Chronological Sorting & Grouping)  │
                └──────────────────┬───────────────────┘
                                   │
                                   ▼
                ┌──────────────────────────────────────┐
                │     State Transition Extraction      │
                │ (Sensitive State Shifts & Sequences) │
                └──────────────────┬───────────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        ▼                          ▼                          ▼
┌────────────────┐        ┌─────────────────┐       ┌───────────────────┐
│ Change Vector  │        │   Attack Path   │       │ Contradictions &  │
│ ("What Changed │        │  (Causal Graph  │       │   Evidence Debt   │
│  vs Baseline") │        │  Node-to-Edge)  │       │ (Source Conflicts)│
└───────┬────────┘        └────────┬────────┘       └─────────┬─────────┘
        │                          │                          │
        └──────────────────────────┼──────────────────────────┘
                                   │
                                   ▼
                ┌──────────────────────────────────────┐
                │    Competing Scenario Generation     │
                │ (Legitimate, Misuse, Compromise, Bug)│
                └──────────────────┬───────────────────┘
                                   │
                                   ▼
                      ENTERPRISE WORKBENCH UI
              (Attack Reconstruction Investigative Pane)
```

---

## 2. Core Architectural Principles

1. **Reconstruction vs. Accusation**:
   Reconstruction organizes physical evidence and state sequences. It never outputs a statement of guilt, a criminal accusation, or a probabilistic fraud score.
2. **Deterministic Sequencing**:
   Reconstruction algorithms produce identical outputs given identical event streams. No non-deterministic neural networks or random seed dependencies are permitted in the reconstruction pipeline.
3. **Zero-PII Boundary**:
   The engine operates strictly on pseudonymized identifiers (`actor`, `subject`, `entity_id`). Real customer names, national identity numbers, and bank account titles remain isolated in the Toroka Vault, accessible only via dual-control maker-checker reveal.
4. **Evidence Provenance Linkage**:
   Every reconstructed step references source system event IDs, timestamps, and SHA-256 integrity digests. Unverifiable assertions are rejected.
5. **Conflict Preservation**:
   When source systems contradict one another (e.g., physical access badge shows Mombasa while core banking session initiates from Nairobi), the engine never silently averages or discards data. It explicitly surfaces the conflict for investigator adjudication.

---

## 3. Data Structures & Flow

### Reconstruction Step (`ReconstructionStep`)
Each chronological event in the reconstructed timeline is represented by a `ReconstructionStep`:

| Field | Type | Description |
| :--- | :--- | :--- |
| `step_index` | `int` | 0-based chronological ordering index |
| `event_id` | `str` | Unique canonical event identifier |
| `event_time` | `datetime` | ISO 8601 UTC timestamp of original event occurrence |
| `source_system` | `str` | Sourcing system (`iam`, `core_banking`, `switch`, `siem`, `hr`, `crm`) |
| `event_type` | `str` | Normalized business event type |
| `actor` | `str \| None` | Pseudonymized acting entity |
| `subject` | `str \| None` | Target entity of action |
| `summary` | `str` | Human-readable explanation of operational step |
| `state_transition`| `str \| None` | State shift identified at this step, if applicable |
| `unusual` | `bool` | Flagged as anomalous relative to historical baseline |
| `evidence_keys` | `tuple[str]` | References to specific raw payload attributes |

### Attack Reconstruction Bundle (`AttackReconstruction`)
The top-level container encapsulating the complete incident reconstruction:

- `reconstruction_id`: Unique identifier of the reconstruction execution.
- `case_id`: Associated enterprise case.
- `steps`: Chronologically ordered tuple of `ReconstructionStep`.
- `transitions`: Sensitive business state shifts detected across the sequence.
- `change_vector`: Multi-dimensional differential between baseline and incident behavior.
- `attack_path`: Directed acyclic graph tracing actor to victim account or transaction.
- `contradictions`: Factual discrepancies between independent source systems.
- `evidence_completeness`: Telemetry coverage and quantified evidence debt.
- `scenarios`: Plausible alternative explanations evaluated against the evidence.

---

## 4. API Endpoints

The Reconstruction Engine is exposed via `/api/enterprise/v1/reconstruction/`:

- `POST /cases/{case_id}/reconstruct`: Deterministically generates and persists a new reconstruction bundle.
- `GET /cases/{case_id}`: Retrieves existing reconstruction bundle.
- `GET /cases/{case_id}/change-vector`: Retrieves the subject Change Vector.
- `GET /cases/{case_id}/attack-path`: Retrieves the attack path graph nodes and edges.
- `GET /cases/{case_id}/contradictions`: Surfaced source contradictions.
- `POST /cases/{case_id}/contradictions/{id}/resolve`: Investigator marks contradiction resolved with rationale.
- `GET /cases/{case_id}/scenarios`: Competing investigation scenarios.
