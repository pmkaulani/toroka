# Toroka Enterprise — Ingestion Operations & Job Management

## 1. Overview & Operational Model

Ingestion jobs in Toroka can be triggered manually via the Enterprise Workbench or scheduled through enterprise job schedulers (Cron, Airflow, Kubernetes CronJobs) using the REST API:

`POST /api/enterprise/v1/integrations/connectors/{connector_id}/sync`

---

## 2. Row-Level Cursor Leasing & Concurrency

To prevent race conditions when multiple background workers execute simultaneously, Toroka leases cursors using database row locks:
```python
cursor_row = db.query(IntegrationCursor).filter_by(
    installation_id=installation_id,
    connector_id=connector_id,
).with_for_update().first()
```
The lock is held for the duration of the batch transaction. Subsequent sync requests for the same connector wait until the running batch commits its cursor, preventing cursor corruption or split-brain ingestion.

---

## 3. Ingestion Job Lifecycle

Each execution records an `IntegrationJobRecord`:
1. **Started**: `status="running"`, `started_at=now`, records cursor position before extraction.
2. **Batch Processing**: Streams batches, counting:
   - `records_accepted`: New unique canonical records.
   - `records_duplicates`: Idempotent duplicates skipped.
   - `records_corrected`: Altered records stored as new version (`status="corrected"`).
   - `records_rejected`: Unparsable records routed to dead-letter queue.
3. **Completed**: Updates cursor in `enterprise_integration_cursors`, commits transaction, logs audit event, sets `status="completed"`.
4. **Failed**: If an unrecoverable network or database error occurs, records `error_message`, leaves cursor at last committed checkpoint, sets `status="failed"`.
