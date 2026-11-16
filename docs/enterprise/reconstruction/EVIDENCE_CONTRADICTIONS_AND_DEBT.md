# Evidence Contradictions & Evidence Debt

## 1. Overview & Philosophy

In real-world bank investigations, evidence is rarely clean or harmonious:
- An employee's access card shows entry into the Nairobi branch at 08:30 UTC, but their core banking login originates from a workstation registered to Mombasa at 08:31 UTC.
- A teller terminal reports a cash withdrawal of \$5,000, while the core ledger records \$10,000.
- An investigator is asked to conclude whether fraud occurred, but the bank's SIEM logs for the incident window were overwritten due to a 7-day retention policy.

Most automated fraud systems make an invisible, dangerous choice: they **silently resolve** contradictions (e.g., picking the later timestamp, taking the average, or discarding the conflicting log) and **ignore missing data** (treating missing logs as evidence of absence).

Toroka adheres to an uncompromising institutional standard:
1. **Never silently resolve factual contradictions.** Surfacing conflicting evidence is an essential duty of the system.
2. **Explicitly quantify Evidence Debt.** If critical systems are missing or unconfigured, the system reports exactly what cannot be proven.

---

## 2. Multi-Source Contradiction Detection

The Contradiction Detection engine evaluates pairs and tuples of canonical events across disparate source systems for physical, temporal, and logical impossibilities.

### Severity Classification (`ContradictionSeverity`)
- `LOW`: Minor timestamp drift ($\le 30\text{ seconds}$) or discrepancies in non-critical descriptive metadata.
- `MEDIUM`: Logical discrepancies, such as concurrent active sessions across distinct workstations in the same campus.
- `HIGH`: Physical or impossible discrepancies, such as concurrent logins from geographically separated branches (velocity violations), conflicting financial amounts, or action recorded after employment termination.

### Detection Scenarios

| Contradiction Type | Source Systems | Condition | Severity |
| :--- | :--- | :--- | :--- |
| **Simultaneous Branch Presence** | `iam` + `siem` / `access_control` | Same `actor` observed at different `branch_code` within $< 5\text{ minutes}$ | `HIGH` |
| **Financial Ledger Discrepancy** | `core_banking` + `switch` | Transaction amount in core ledger $\neq$ payment switch dispatch amount | `HIGH` |
| **Clock / Timestamp Inversion** | Any | Child event timestamp precedes parent event timestamp by $> 10\text{ seconds}$ | `MEDIUM` |
| **Identity / Device Mismatch** | `iam` + `device_mgmt` | Session registered to Device A, but terminal telemetry reports Device B | `MEDIUM` |

### Adjudication Workflow
Contradictions cannot be resolved by an automated algorithm. They require human investigator adjudication:
- Status transitions from `surfaced` to `resolved`.
- The investigator must provide a mandatory `resolution_note` explaining the operational reason (e.g., *"Confirmed NTP time drift on legacy core banking host; SIEM GPS timestamp accepted"*).
- The investigator's identity (`resolved_by`) and timestamp are recorded in the tamper-evident cryptographic audit chain.

---

## 3. Evidence Completeness & Evidence Debt

### Concept of Evidence Debt
**Evidence Debt** is the quantified gap between the telemetry required to rigorously investigate an incident and the telemetry actually available to Toroka.

When a bank has high Evidence Debt:
- An incident cannot be proven to be fraud or legitimate.
- Attack paths cannot be completed.
- Scenarios cannot be decisively ruled out.

### Evidence Requirements & Scoring
For every investigation, Toroka evaluates requirements across six source domains:

| Domain | Required For | Required Fields |
| :--- | :--- | :--- |
| `iam` | Authentication & credential attribution | `actor`, `session_id`, `ip_address`, `device` |
| `core_banking` | Account access & financial postings | `account_id`, `customer_id`, `amount`, `channel` |
| `switch` | Interbank & mobile disbursement verification | `rrn`, `dest_institution`, `response_code` |
| `siem` | Endpoint integrity & concurrent sessions | `endpoint_id`, `process_hash`, `geo_ip` |
| `hr` | Employment status & authorized location | `branch_code`, `status`, `job_family`, `leave_status` |
| `crm` | Customer complaint or notification history | `case_number`, `dispute_type`, `filing_time` |

### Calculation of Telemetry Completeness ($C_{\text{telemetry}}$)
Given $R_{\text{total}}$ standard requirements and $R_{\text{satisfied}}$ corroborated requirements:
$$C_{\text{telemetry}} = \frac{R_{\text{satisfied}}}{R_{\text{total}}} \times 100\%$$

If $C_{\text{telemetry}} < 70\%$, the incident report prominently displays an **Evidence Debt Alert**:
> *"Evidence Debt: 33% telemetry missing. Missing systems: SIEM, HR. Findings are provisional pending full audit retrieval."*
