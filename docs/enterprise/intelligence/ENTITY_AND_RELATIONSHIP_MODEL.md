# Toroka Enterprise — Entity & Relationship Graph Model

## 1. Overview & Provenance Model

Relationships between people, accounts, devices, and sessions are treated as **admissible evidence** in Toroka. A relationship is never a simple boolean pointer; it carries an immutable provenance record:

```python
@dataclass(frozen=True)
class Relationship:
    installation_id: str
    source: EntityRef
    target: EntityRef
    relationship_type: str

    first_seen: datetime | None = None
    last_seen: datetime | None = None
    confidence: float = 1.0

    source_system: str | None = None
    source_record_id: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
```

---

## 2. Supported Entity Types

| Entity Type | Description | Typical Source System |
|---|---|---|
| `EMPLOYEE` | Bank staff member, teller, relationship officer, system admin | HR Roster, IAM Active Directory |
| `CUSTOMER` | Customer Master Profile (CIF) | Core Banking, CRM |
| `ACCOUNT` | Deposit, loan, clearing, GL, or suspense account | Core Banking |
| `TRANSACTION` | Posting, funds transfer, card settlement, reversal | Core Banking, Payment Switch |
| `DEVICE` | Teller terminal, branch workstation, corporate laptop | IAM, MDM, IT Asset Inventory |
| `SESSION` | Authenticated application session or VPN tunnel | IAM, SIEM, Core Banking Session Mgr |
| `IP_ADDRESS` | Source IPv4/IPv6 address of connection | Network Gateway, VPN, Webhook |
| `BRANCH` | Bank physical operating branch, agency, or cash centre | HR, Core Banking Organization Hierarchy |
| `ROLE` | RBAC role, permission set, or transaction approval limit | IAM, CBS Security Matrix |
| `CASE` | Active or closed investigation case file in Toroka | Toroka Casework Subsystem |

---

## 3. Installation Scoping & Isolation

All `EntityRef` and `Relationship` objects are strictly scoped to an `installation_id`.
Attempting to create an edge between entities across different installations raises `ValueError` immediately at construction:

```python
if self.source.installation_id != self.installation_id:
    raise ValueError("source installation mismatch")

if self.target.installation_id != self.installation_id:
    raise ValueError("target installation mismatch")
```

Cross-tenant queries are blocked both in application memory and in the database schema through composite unique constraints on `(installation_id, source_type, source_id, target_type, target_id, relationship_type)`.
