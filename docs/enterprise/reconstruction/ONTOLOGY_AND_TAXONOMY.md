# Toroka Enterprise Intelligence Ontology & Taxonomy

## 1. Purpose of Standardized Taxonomy

In enterprise financial crimes investigations, terms like "signal", "event", "alert", and "case" are frequently conflated. This lack of precision causes audit confusion, regulatory vulnerability, and inconsistent triage.

This document establishes the authoritative, binding definitions across all phases of the Toroka platform.

---

## 2. Core Ontological Concepts

```text
  ┌─────────────────────────────────────────────────────────────┐
  │                         CASE                                │
  │   (Legal/administrative inquiry with formal jurisdiction)   │
  │                                                             │
  │   ┌─────────────────────────────────────────────────────┐   │
  │   │                RECONSTRUCTION                       │   │
  │   │    (Chronological, causal, multi-source narrative)  │   │
  │   │                                                     │   │
  │   │  ┌───────────────┐  ┌───────────────┐  ┌─────────┐  │   │
  │   │  │   SCENARIO    │  │ CHANGE VECTOR │  │ ATTACK  │  │   │
  │   │  │ (Hypothesis)  │  │ (Diff vs Base)│  │  PATH   │  │   │
  │   │  └───────────────┘  └───────────────┘  └─────────┘  │   │
  │   │                                                     │   │
  │   │  ┌──────────────────────────────────────────────┐   │   │
  │   │  │              STATE TRANSITIONS               │   │   │
  │   │  └──────────────────────────────────────────────┘   │   │
  │   │                                                     │   │
  │   │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │   │
  │   │  │   SIGNAL    │  │   ANOMALY   │  │ CONTRADICT. │  │   │
  │   │  └─────────────┘  └─────────────┘  └─────────────┘  │   │
  │   │                                                     │   │
  │   │  ┌──────────────────────────────────────────────┐   │   │
  │   │  │               RELATIONSHIPS                  │   │   │
  │   │  └──────────────────────────────────────────────┘   │   │
  │   │                                                     │   │
  │   │  ┌──────────────────────────────────────────────┐   │   │
  │   │  │              CANONICAL EVENTS                │   │   │
  │   │  └──────────────────────────────────────────────┘   │   │
  │   └─────────────────────────────────────────────────────┘   │
  └─────────────────────────────────────────────────────────────┘
```

---

## 3. Authoritative Definitions

### 1. EVENT (`IntelligenceEvent`)
- **Definition**: A discrete, timestamped physical occurrence recorded by an operational bank system.
- **Properties**: Immutable, sourced from a specific technical component (`iam`, `core_banking`, etc.), carries an exact timestamp and SHA-256 integrity digest.
- **Example**: *"User emp_10 logged in to workstation WS-102 via Kerberos at 2026-11-15T08:14:02Z."*

### 2. RELATIONSHIP (`Relationship`)
- **Definition**: An established factual link or association between two distinct entities (`source -> target`).
- **Properties**: Directed, carries a relationship type (`owns`, `authenticated`, `accessed`, `transferred_to`), first/last seen timestamps, and confidence score.
- **Example**: *"Employee emp_10 authenticated session sess_99 (confidence: 1.0)."*

### 3. STATE TRANSITION (`StateTransition`)
- **Definition**: A sensitive change in operational state or policy boundaries within the banking environment.
- **Properties**: Captures `from_state -> to_state`, the triggering event, and actor.
- **Example**: *"Account acc_01 transitioned from normal to beneficiary_changed at 08:24 UTC."*

### 4. SIGNAL (`CorrelationSignal`)
- **Definition**: A pattern or rule match indicating heightened investigative interest resulting from the correlation of multiple events.
- **Properties**: Deterministic, non-probabilistic, carries severity (`LOW`, `MEDIUM`, `HIGH`) and evidence references.
- **Example**: *"Customer lookup in Core Banking followed within 3 minutes by phone number change in CRM."*

### 5. ANOMALY (`BehavioralAnomaly`)
- **Definition**: A statistical observation that deviates significantly from an entity's historical baseline profile.
- **Properties**: Evaluated via non-parametric statistics (Median Absolute Deviation, Modified Z-score), bounded within specific dimensions.
- **Example**: *"Subject emp_10 transaction value Modified Z-score = 4.2 relative to 60-day historical distribution."*

### 6. CHANGE VECTOR (`ChangeVector`)
- **Definition**: The complete set of multi-dimensional differences between an entity's historical baseline and their observed behavior during an incident window.
- **Properties**: Evaluates 8 standardized dimensions; reports changed dimensions, statistically unusual dimensions, and telemetry completeness.
- **Example**: *"Subject changed device, IP address, and working hours; 2 dimensions statistically unusual."*

### 7. ATTACK PATH (`AttackPath`)
- **Definition**: A directed topological sub-graph tracing the causal path from actor/threat source to the target account or transaction.
- **Properties**: Set of `AttackPathNode` and `AttackPathEdge`, overall path confidence score.
- **Example**: `emp_10 -> sess_99 -> cif_44 -> acc_01 -> ben_88 -> tx_999`.

### 8. CONTRADICTION (`EvidenceContradiction`)
- **Definition**: A factual, physical, or logical incompatibility between two or more corroborated events from independent source systems.
- **Properties**: Preserved without automated resolution; requires human investigator adjudication with rationale.
- **Example**: *"Simultaneous active logins recorded from Nairobi and Mombasa branches within 15 seconds."*

### 9. SCENARIO / HYPOTHESIS (`InvestigationScenario`)
- **Definition**: A structured, plausible explanation of how and why the incident occurred, evaluated against supporting and refuting evidence.
- **Properties**: Four standard archetypes (`legitimate_service`, `insider_misuse`, `compromised_credentials`, `system_error`); carries qualitative plausibility and identified evidentiary gaps.

### 10. RECONSTRUCTION (`AttackReconstruction`)
- **Definition**: The complete, end-to-end deterministic synthesis of an incident: chronological timeline, state transitions, Change Vector, attack path, surfaced contradictions, Evidence Debt, and competing scenarios.

### 11. CASE (`EnterpriseCase`)
- **Definition**: The administrative and legal container governing an investigation. Tracks assignment, notes, approvals, evidence items, and regulatory closure status under bank governance.
