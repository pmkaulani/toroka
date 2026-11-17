# Strategic Research & Engineering Improvement Roadmap for Toroka

**Author:** Antigravity Engineering & Model Governance Research  
**Target Repository:** `pmkaulani/toroka`  
**Current Baseline:** Phase 12.6 (`main` @ `9c7270b`, 1,288 passing tests)  
**Target Horizon:** Phase 13.0+ (Enterprise Scale, Tier-1 Bank Pilot, Supervisory Certification)  

---

## Executive Overview

Toroka Phase 12.6 closed the critical governance gaps: canonical manifest hashing, database-derived promotion verification, 13 mandatory readiness attestations, event-bound Evidence Passports, durable transactional kill-switches, Copilot citation re-grounding, fail-closed health reporting, and two-person entity resolution.

To evolve Toroka from a **pilot-ready architecture** into a **Tier-1 enterprise platform** capable of processing tens of millions of daily core banking transactions while meeting rigorous global (OCC SR 11-7, NIST AI RMF, Basel III BCBS 239) and regional (Central Bank of Kenya Prudential Guidelines, Kenya Data Protection Act 2019) standards, this research identifies **8 strategic improvement pillars**.

---

## 1. High-Performance Graph Processing & Scalable Entity Resolution

### Current Limitation
In Phase 12.6, entity resolution and graph traversal (`EntityResolutionEngine`, `enterprise_network_nodes`, `enterprise_network_edges`) are managed via relational SQL queries and in-memory Python graph structures. When tracking complex fraud rings across a commercial bank with 10M+ accounts and 100M+ transactions:
- Multi-hop traversal (e.g. 4- to 7-hop rapid layering or pass-through chains) causes combinatorial memory spikes and high latency.
- In-memory graph rebuilding during query time blocks worker threads.

### Concrete Engineering Improvements
1. **Hybrid Relational-Graph Engine (PostgreSQL Apache AGE / Neo4j / pgvector):**
   - Retain relational transactional integrity for casework while offloading graph edge queries to a specialized graph extension (such as **Apache AGE** inside PostgreSQL or an isolated read-replica graph instance).
   - Implement OpenCypher queries for pattern matching:
     ```cypher
     MATCH path = (origin:Account)-[:TRANSFERRED*3..6]->(terminal:Account)
     WHERE terminal.is_high_risk = true
       AND ALL(r IN relationships(path) WHERE r.velocity_seconds < 300)
     RETURN path
     ```
2. **Streaming Cycle & Smurfing Detection:**
   - Implement streaming flow algorithms (Tarjan's Strongly Connected Components and Edmonds-Karp maximum flow) to identify circular round-tripping (funds returning to the originator through intermediaries) in real time.
3. **Graph Partitioning by Business Entity:**
   - Partition graphs into sub-clusters based on institutional risk domains (e.g., Corporate Banking vs. Retail / M-PESA Agents) to prevent single-query traversal explosions.

---

## 2. Real-Time Event Streaming & ISO 20022 Core Banking Ingestion

### Current Limitation
Toroka currently ingests data via batch CSV manifests conforming to `CanonicalDataContract v2.0.0`. While suitable for post-settlement investigations and end-of-day reconciliations, commercial banks require **in-flight transaction scoring** before clearing windows close.

### Concrete Engineering Improvements
1. **Event-Driven Streaming Ingestion (Kafka / Redpanda / Apache Pulsar):**
   - Introduce `toroka_enterprise.integrations.streaming` with consumer groups for:
     - `core-banking.transactions.v1`
     - `auth.iam-events.v1`
     - `channels.mobile-banking.v1`
   - Guarantee exactly-once processing (EOS) using transactional Kafka consumer offsets committed alongside database state.
2. **Native ISO 20022 Financial Messaging Support:**
   - Build a streaming decoder for standard financial message definitions:
     - `pacs.008.001.10`: Real-time Financial Institution Customer Credit Transfer.
     - `pacs.002.001.12`: Payment Status Report (reversals, rejections).
     - `camt.053.001.10`: Bank-to-Customer End-of-Day Statement.
   - Automatically parse Kenya-specific clearing headers (Pesalink, RTGS, KEPSS) into normalized `IntelligenceEventRecord` objects.
3. **Sub-100ms Inference & Advisory Hold Hook:**
   - Establish an ultra-low-latency pipeline returning an asynchronous `advisory_decision`:
     - `ALLOW`: Low risk, normal baseline.
     - `STEP_UP_AUTH`: Require hardware token / biometric confirmation before release.
     - `QUARANTINE_HOLD`: Immediate 30-minute hold for high-confidence multi-hop anomaly.

---

## 3. Hardware Security Module (HSM) Asymmetric PKI & Public Verifier

### Current Limitation
Phase 12.6 establishes tamper-evident lineage via SHA-256 digests and HMAC comparisons. However:
- Symmetric HMAC requires possessing the shared secret to verify integrity, meaning external regulators or auditors cannot verify a release or passport without elevated credentials.
- An unsigned SHA-256 hash proves tamper-evidence but does not provide legally binding non-repudiation under the Kenya Evidence Act or electronic signature regulations.

### Concrete Engineering Improvements
1. **Asymmetric Digital Signatures (Ed25519 / ECDSA P-256):**
   - Bind Release Manifests and Evidence Passports with an asymmetric digital signature generated inside the bank's HSM:
     - Standard: PKCS#11 driver interface for on-premise Thales Luna / Utimaco HSMs.
     - Cloud: Cloud KMS asymmetric signing key (`RSASSA_PSS_SHA_256` or `ECDSA_P256_SHA256`).
2. **Standalone Offline Verifier Binary (`toroka-verify`):**
   - Provide a lightweight, zero-dependency CLI utility (single compiled Go or Rust binary) allowing judicial bodies, external auditors, or bank supervisors to verify passports:
     ```bash
     toroka-verify passport --file passport-sig_rapid_01.json --public-key bank-trust-anchor.pub
     ```
3. **Merkle Tree Event Batching (RFC 6962):**
   - For high-volume transaction environments, batch events into an append-only Merkle tree. Passports contain a compact Merkle inclusion proof (logarithmic size $O(\log N)$) verifying that a specific event exists in the bank's master audit log without exposing unrelated customer transactions.

---

## 4. Semantic Natural Language Inference (NLI) & Air-Gapped Local LLM

### Current Limitation
Phase 12.6 enforces citation presence (`[Cites: ev_id]`) and exact excerpt matching against the evidence context. However:
- Lexical citation checking cannot catch **semantic hallucination**: a model can cite a real event while making ungrounded claims in text.
- Cloud-hosted LLM APIs raise bank confidentiality and data sovereignty objections under the Kenya Data Protection Act 2019.

### Concrete Engineering Improvements
1. **Automated Entailment Verification via Natural Language Inference (NLI):**
   - Implement an automated claim-level entailment verifier using a compact, local cross-encoder model (e.g., `DeBERTa-v3-small` fine-tuned on MNLI) classifying claims into `ENTAILMENT`, `NEUTRAL`, or `CONTRADICTION`.
2. **Air-Gapped, On-Premises Local LLM Serving:**
   - Integrate with containerized local inference engines (**vLLM** or **Ollama**) running open-weight banking models (e.g. `Llama-3.3-70B-Instruct-AWQ` or `Mistral-Large-Instruct`) operating strictly within the bank's air-gapped private subnet.
3. **Prompt Injection & Indirect Data Poisoning Defense:**
   - User-controlled fields (transaction memos, transfer narratives) are sanitized and stripped of prompt instruction markers before inclusion in LLM prompts.

---

## 5. Quantitative Model Risk Management (OCC SR 11-7 / Fed SR 15-18)

### Current Limitation
Current drift monitoring checks component activation counts and basic threshold violations. Regulatory expectations under **OCC Bulletin 2011-12 / SR 11-7** require continuous mathematical monitoring of feature distribution stability and model decay.

### Concrete Engineering Improvements
1. **Mathematical Distribution Drift Metrics:**
   - **Population Stability Index (PSI):**
     $$\text{PSI} = \sum \left( \% \text{ Actual}_i - \% \text{ Expected}_i \right) \times \ln\left( \frac{\% \text{ Actual}_i}{\% \text{ Expected}_i} \right)$$
     - Automated alert thresholds: $\text{PSI} < 0.10$ (stable), $0.10 \le \text{PSI} < 0.25$ (moderate shift), $\text{PSI} \ge 0.25$ (significant drift $\rightarrow$ auto-quarantine).
   - **Wasserstein Distance & Kolmogorov-Smirnov Tests:** Continuous 2-sample testing on continuous features.
2. **Automated Champion-Challenger (Shadow Mode):**
   - Run new detector versions in **Shadow Mode** for a 14-day observation window without taking blocking actions, comparing false discovery rates against the active Champion.
3. **Disparate Impact & Fairness Audits:**
   - Automated disparate impact ratio (DIR) evaluation across branch codes and customer segments.

---

## 6. Multi-Bank Federated Intelligence (Cross-Bank Mule Detection)

### Current Limitation
Syndicates move funds rapidly across banks: Bank A $\rightarrow$ Bank B $\rightarrow$ Bank C $\rightarrow$ M-PESA Cash-Out. Individual banks have blind spots.

### Concrete Engineering Improvements
1. **Privacy-Preserving Set Intersection (PSI):**
   - Enable financial institutions to query shared indicator databases using **Oblivious Transfer PSI** or **Homomorphic Encryption** without leaking non-matching customer data.
2. **Federated Anomaly Scoring:**
   - Compute multi-bank graph distance metrics without sharing plaintext transaction amounts or customer identities, fully complying with the **Kenya Data Protection Act 2019 (Section 25 & 41)**.

---

## 7. Operator Experience: Interactive Graph Canvas & Court-Ready Evidence Dossiers

### Concrete Engineering Improvements
1. **Interactive GPU-Accelerated Graph Canvas:**
   - Integrate an interactive canvas (using **Cytoscape.js** or **React Force Graph**) with a timeline scrubber slider for temporal transaction playback and automated cluster coloring.
2. **Court-Ready Forensic Evidence Dossier (PDF/A-3):**
   - Generate ISO 19005-3 compliant PDF/A forensic packages for law enforcement (DCI / Banking Fraud Investigations Unit - BFIU) with embedded cryptographic verification certificates.

---

## 8. Reliability, Resilience & Chaos Engineering

### Concrete Engineering Improvements
1. **Chaos Engineering & Failure Injection Harness:**
   - Programmatically simulate real-world banking outages: database disconnects mid-promotion, KMS latency spikes, and concurrent promotion races.
2. **Automated Mutation Testing (`mutmut`):**
   - Measure test suite mutation survival rate on governance modules to verify that mutating logic operators causes immediate test failure.

---

## Prioritized Implementation Roadmap

| Priority | Pillar | Target Horizon | Estimated Effort | Strategic Impact |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1 (High)** | **Asymmetric HSM Signatures & Verifier CLI** | Phase 13.0 | 2 weeks | Enables regulatory inspection and external audit verification without shared secrets. |
| **Tier 1 (High)** | **Quantitative Drift Metrics (PSI / KS-test)** | Phase 13.0 | 2 weeks | Satisfies OCC SR 11-7 / Model Risk Management quantitative monitoring requirements. |
| **Tier 2 (Medium)**| **NLI Semantic Grounding & Local LLM Serving**| Phase 13.1 | 3 weeks | Eliminates cloud LLM data egress and semantic hallucination risks. |
| **Tier 2 (Medium)**| **Interactive Graph Canvas in Workbench** | Phase 13.1 | 3 weeks | Drastically reduces investigator cognitive load when triaging multi-hop fraud rings. |
| **Tier 3 (Enterprise)**| **Real-Time Streaming & ISO 20022 Engine** | Phase 13.2 | 4 weeks | Moves Toroka from post-settlement detection to in-flight transaction interception. |
| **Tier 3 (Enterprise)**| **Federated Cross-Bank Mule Intelligence** | Phase 13.3 | 6 weeks | National-level syndicate detection across Kenya commercial banking institutions. |
