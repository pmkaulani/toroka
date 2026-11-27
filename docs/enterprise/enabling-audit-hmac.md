# Enabling HMAC signing on an existing unkeyed AuditLog

This guide covers adding an HMAC key to an `AuditLog` that was initialised
without one (i.e. `hmac_key` was not supplied to the constructor).

> [!WARNING]
> Existing audit rows that were written without a key have no HMAC field.
> Adding a key does **not** retroactively sign old rows.  The chain is
> preserved — new rows will be HMAC-chained from the previous unkeyed head —
> but old rows cannot be verified with the new key.  This is intentional:
> altering old rows would invalidate the hash chain.

## Steps

### 1. Confirm the current state

```python
import sqlite3
con = sqlite3.connect("audit.db")
# A NULL hmac means the row was written without a key.
rows = con.execute("SELECT count(*) FROM audit_records WHERE hmac IS NULL").fetchone()[0]
print(f"Rows without HMAC: {rows}")
```

### 2. Generate and store the key

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
# Output: a 64-hex-character string (32 bytes = 256 bits)
```

Store the key in your secrets manager (Kubernetes Secret, HashiCorp Vault,
AWS Secrets Manager, etc.).  **Never commit it to source control.**

For the enterprise API, set it via:
- Environment variable: `TOROKA_ENT_AUDIT_CHECKPOINT_KEY`  
- Or Docker secret: `TOROKA_ENT_AUDIT_CHECKPOINT_KEY_FILE=/run/secrets/audit_key`

### 3. Deploy

Roll the enterprise-api pods with the new environment variable set.
The `AuditLog` constructor will start signing new rows immediately.

### 4. Mark the boundary

Add a sentinel audit event immediately after deployment so you can
identify which rows were written before HMAC signing was enabled:

```bash
curl -s -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"event": "audit.hmac_signing_enabled", "detail": "HMAC key added to AuditLog"}' \
  http://enterprise-api:8080/api/enterprise/v1/audit/events
```

### 5. Create the first checkpoint

```bash
curl -s -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  http://enterprise-api:8080/api/enterprise/v1/audit/checkpoints | jq .
```

### 6. Notify your compliance team

Inform your compliance/audit team that:

- Rows before the sentinel event (see step 4) have no HMAC and cannot be
  cryptographically verified.
- Rows from the sentinel event onward are HMAC-chained and can be verified
  via the checkpoint API.
- The hash chain itself (SHA-256 row-to-row linkage) is unbroken across
  the boundary — the HMAC is an additional layer on top.

## Verification

After the first keyed checkpoint:

```bash
# GET the checkpoint ID from the list
CID=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
  http://enterprise-api:8080/api/enterprise/v1/audit/checkpoints \
  | python3 -c "import sys,json; print(json.load(sys.stdin)[0]['checkpoint_id'])")

# Verify it
curl -s -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  http://enterprise-api:8080/api/enterprise/v1/audit/checkpoints/${CID}/verify
```

Expected result: HTTP 200 with `"status": "ok"`.
