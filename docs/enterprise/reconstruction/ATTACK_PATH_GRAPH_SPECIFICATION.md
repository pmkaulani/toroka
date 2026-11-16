# Attack Path Graph Specification

## 1. Overview & Objectives

In complex banking fraud or insider attacks, the threat actor rarely interacts directly with the stolen funds. Instead, attacks traverse intermediate entities:
`EMPLOYEE -> SESSION -> CUSTOMER -> ACCOUNT -> BENEFICIARY -> TRANSACTION -> CASHOUT`

The **Attack Path Graph** provides a directed, evidence-backed topological model connecting all entities involved in the incident. Every edge in the graph represents a verified causal or associative relationship corroborated by at least one source system.

---

## 2. Graph Topology & Schema

### Nodes (`AttackPathNode`)
Nodes represent distinct entities in the bank's ecosystem:

| Attribute | Type | Description |
| :--- | :--- | :--- |
| `node_id` | `str` | Unique node identifier (e.g., `emp:emp_12`, `acc:acc_99`) |
| `node_type` | `str` | Canonical entity type (`employee`, `session`, `customer`, `account`, `beneficiary`, `transaction`, `device`, `ip_address`, `branch`) |
| `display_label` | `str` | Human-readable pseudonymized title (e.g., `Employee emp_12`) |
| `attributes` | `dict[str, Any]` | Extracted contextual attributes |

### Edges (`AttackPathEdge`)
Edges represent verified directed interactions between entities:

| Attribute | Type | Description |
| :--- | :--- | :--- |
| `edge_id` | `str` | Edge identifier |
| `source_node` | `str` | Originating `node_id` |
| `target_node` | `str` | Destination `node_id` |
| `relationship` | `str` | Interaction type (`authenticated`, `accessed`, `modified_beneficiary`, `authorized_transfer`, `owns`, `originates_from`) |
| `confidence` | `float` | Source reliability and linkage confidence ($0.0 \le c \le 1.0$) |
| `first_seen` | `datetime \| None` | Earliest timestamp of relationship |
| `last_seen` | `datetime \| None` | Latest timestamp of relationship |
| `source_system`| `str \| None` | System corroborating the edge (`iam`, `core_banking`, etc.) |

---

## 3. Canonical Attack Path Patterns

### Pattern A: Account Takeover via Call Center / Teller Impersonation
```text
[Employee emp_44]
       │
       ▼ (authenticated)
[Session sess_901] ──(originated_from)──► [Device dev_pc12]
       │
       ▼ (accessed)
[Customer cif_881]
       │
       ▼ (owns)
[Account acc_4401]
       │
       ▼ (modified_beneficiary)
[Beneficiary ben_ext09]
       │
       ▼ (authorized_transfer)
[Transaction tx_88301] ──(payout_to)──► [Mule Account acc_mule01]
```

### Pattern B: Dormant Account Drain with Supervisor Override
```text
[Operator emp_10] ──(accessed)──► [Dormant Account acc_dormant]
       │
       ▼ (requested_override)
[Supervisor emp_20] ──(approved_override)──► [Override Log log_ovr]
       │
       ▼ (authorized_payout)
[Transaction tx_payout] ──(routed_via)──► [RTGS Payment sw_rtgs]
```

---

## 4. Graph Construction & Path Confidence

The attack path is constructed deterministically from cross-system relationships:
1. **Root Identification**: The primary subject of the case (usually an employee or compromised credential) is set as root ($v_0$).
2. **Breadth-First Traversal**: Traverses outgoing relationships with confidence threshold $c \ge 0.50$.
3. **Aggregate Path Confidence**:
   The aggregate confidence $C_{\text{path}}$ across path edges $E = \{e_1, e_2, \dots, e_k\}$ is calculated as the mean edge confidence:
   $$C_{\text{path}} = \frac{1}{|E|} \sum_{i=1}^{|E|} c(e_i)$$
   If no edges are present, default fallback confidence is $0.50$.

---

## 5. UI Visualization

In the Toroka Enterprise Workbench, the Attack Path is rendered as an interactive horizontal node-link diagram. Investigators can:
- Click any node to filter corresponding canonical events.
- Click any edge to view the underlying audit trail and source system record IDs.
- Highlight high-risk edges (confidence $< 0.80$ or cross-branch anomalies).
