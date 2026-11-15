# Source Reliability Framework

## 1. Controlled Reliability Hierarchy

In cross-system investigations, evidence originating from an authoritative general ledger cannot be treated identically to an unauthenticated customer ticket or a volatile syslog feed.

Toroka Enterprise establishes a controlled source reliability hierarchy:

| Source System | Canonical Weight | Authoritative | Description |
| :--- | :---: | :---: | :--- |
| `CORE_BANKING` | **1.00** | Yes | Core banking posting journals and balance sheets; primary system of record. |
| `PAYMENT_SWITCH`| **0.95** | Yes | Interbank payment settlement rails (M-PESA, SWIFT, RTGS, ACH). |
| `IAM` | **0.90** | Yes | Identity directory, SSO, MFA challenges, and credential management logs. |
| `HR` | **0.85** | Yes | Human resources management system, payroll rosters, leave records. |
| `SIEM` | **0.80** | No | Aggregated security telemetry and firewall/endpoint logs. |
| `CRM` | **0.70** | No | Customer service tickets, inquiry logs, and contact notes. |
| `MANUAL_INVESTIGATION`| **0.75** | No | Analyst notes, witness summaries, and manual case annotations. |

---

## 2. Independent Corroboration vs. Replicated Logging

A critical pitfall in fraud analytics is counting replicated copies of an event as independent confirmation. For example:
- A single user login generates an IAM authentication log.
- The IAM log is forwarded to a SIEM forwarder.
- The SIEM forwarder sends an alert to a security dashboard.

Although three log streams exist, they represent **one underlying event from one source authority (`IAM`)**. Toroka Enterprise deduplicates evidence by source system:
- Multi-source corroboration requires evidence spanning distinct systems (e.g. `CORE_BANKING` posting corroborated by `IAM` login session and `HR` leave status).
