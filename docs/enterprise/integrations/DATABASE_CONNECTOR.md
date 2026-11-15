# Toroka Enterprise — Read-Only Database Adapter

## 1. Overview & Operational Model

`BankDatabaseConnector` connects directly to relational database reporting replicas (PostgreSQL, Oracle, Microsoft SQL Server, MySQL) via SQLAlchemy.

It enables high-throughput data extraction without putting load on transaction-processing master nodes.

---

## 2. Guardrails & Safety Constraints

To protect bank production databases, `BankDatabaseConnector` enforces five mandatory constraints:
1. **View-Only Queries**: Toroka queries pre-materialized database views (e.g. `vw_core_transactions`, `vw_staff_roster`) rather than raw internal table structures.
2. **Table/View Whitelist**: The adapter validates the requested view against an explicit allowlist (`allowed_tables_or_views`).
3. **Strict Query Parameterization**: Dynamic SQL concatenation is strictly forbidden. Offset and limit parameters are bound as parameterized variables.
4. **Read-Only Transaction Isolation**: Database sessions are opened in `read_only=True` mode where supported by the underlying RDBMS.
5. **No Long-Lived Table Locks**: Queries are batched with modest limits (default 500 rows) to prevent transaction log contention.

---

## 3. Configuration & Query Execution

```python
from toroka_enterprise.integrations.connectors.database import BankDatabaseConnector

connector = BankDatabaseConnector(
    connector_id="cbs-replica-01",
    connection_url="postgresql://toroka_ro:secret@reporting-db.bank.internal:5432/cbs_reporting",
    table_or_view="vw_core_transactions",
    cursor_column="id",
    allowed_tables_or_views=("vw_core_transactions", "vw_staff_roster"),
)
```

The adapter queries:
```sql
SELECT * FROM vw_core_transactions
WHERE id > :cursor_val
ORDER BY id ASC
LIMIT :limit_val;
```
As records are streamed, the highest `id` value becomes the next cursor for subsequent batch extraction.
