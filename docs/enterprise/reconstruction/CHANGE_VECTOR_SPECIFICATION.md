# Change Vector Specification

## 1. Concept & Purpose

Traditional bank fraud alerts ask: **"Is this transaction fraudulent?"**
This binary approach produces high false positive rates and lacks operational context.

The Toroka **Change Vector** fundamentally reframes the investigation question:
**"What changed in the environment, credentials, or behavior prior to or during this incident?"**

A Change Vector compares observed attributes during an incident window against the subject's established historical behavioral profile (constructed during Phase 6). It identifies changed dimensions, flags statistically significant deviations, and calculates telemetry completeness.

---

## 2. Monitored Change Dimensions

The Change Vector evaluates eight standardized dimensions:

| Dimension | Baseline Source | Observed Source | Change Indicator |
| :--- | :--- | :--- | :--- |
| `device` | Historical endpoint fingerprints | IAM session device token | New/unseen terminal MAC or browser fingerprint |
| `ip_address` | Subnet / CIDR history | IAM/SIEM connection IP | IP outside normal ISP, geofence, or VPN subnet |
| `working_hours` | Normal shift distribution | Transaction / login timestamp | Event timestamp falls outside 5th–95th percentile shift hours |
| `customer_set` | Historical CIF access portfolio | Core Banking audit trail | First-time access to high-net-worth or dormant customer |
| `permissions` | IAM RBAC role registry | Active privileges at event time | Privilege escalation, emergency delegation, role change |
| `transaction_value` | Empirical transaction distribution | Financial posting amount | Value exceeds 3x MAD (Modified Z-score > 3.5) |
| `transaction_frequency` | Typical postings / hour | Core Banking throughput | Rapid burst execution (> 3x historical mean rate) |
| `branch` | Assigned branch code | Physical terminal / switch branch | Action originated from non-assigned branch location |

---

## 3. Mathematical & Algorithmic Representation

Given:
- Subject $S$
- Established baseline profile $B = \{d_1: P_1, d_2: P_2, \dots, d_k: P_k\}$
- Observed incident window attributes $O = \{d_1: v_1, d_2: v_2, \dots, d_m: v_m\}$

The Change Vector $C(S)$ is computed as:

1. **Changed Dimensions ($D_{\text{changed}}$)**:
   $$D_{\text{changed}} = \{d \in O \mid v_d \neq \text{baseline}(d) \lor \text{flagged}(v_d)\}$$
2. **Unusual Dimensions ($D_{\text{unusual}}$)**:
   $$D_{\text{unusual}} = \{d \in D_{\text{changed}} \mid \text{is\_statistically\_unusual}(v_d, P_d)\}$$
   Where continuous values are evaluated via Median Absolute Deviation (MAD):
   $$M_i = \frac{0.6745 \cdot (x_i - \tilde{x})}{\text{MAD}} > 3.5$$
3. **Telemetry Completeness ($K$)**:
   $$K = \frac{|O \cap D_{\text{monitored}}|}{|D_{\text{monitored}}|}$$
   Where $|D_{\text{monitored}}| = 8$.

### Explanation Synthesis
The engine synthesizes an explainable factual statement:
> *"Subject emp_12 exhibits 3 changed dimension(s) (device, ip_address, working_hours) and 2 statistically unusual dimension(s) with 87% telemetry completeness. Evidence indicates operational change, which does not constitute proof of misconduct."*

---

## 4. Investigative Usage & Governance

- **Non-Accusatory Context**: A high change count does not imply fraud. Legitimate reasons include:
  - Hardware replacement or OS upgrade.
  - Branch transfer or promotion.
  - Authorized overtime or crisis response.
- **Evidence Debt Link**: If $K < 0.60$ (less than 60% of monitored dimensions available), the Change Vector is flagged with high *Evidence Debt*, signaling that the bank's logging infrastructure lacks sufficient telemetry to validate behavioral anomalies.
