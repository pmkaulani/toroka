# Audit Checkpoint Operations Guide

Audit checkpoints are HMAC-signed snapshots of the enterprise audit log
head.  They let you verify that the audit chain has not been tampered with
since the last checkpoint, without replaying every event.

## Why they matter

The enterprise `AuditLog` is append-only and hash-chained (each row
includes the HMAC of the previous row).  A checkpoint signs the current
chain head with a key stored **outside** the application database.  An
attacker who compromises the database cannot forge a valid checkpoint
without also compromising the checkpoint key — which must be stored on
different infrastructure.

## Runtime requirements (staging + production)

| Variable | Description |
|---|---|
| `TOROKA_ENT_AUDIT_CHECKPOINT_DIR` | Writable directory for checkpoint files.  Must point to WORM/object-lock storage or be replicated off-host before the next checkpoint is written. |
| `TOROKA_ENT_AUDIT_CHECKPOINT_KEY` | HMAC-SHA256 key, minimum 32 bytes UTF-8.  Must be stored in a KMS-backed secret on a different host from the application database. |

The application raises `RuntimeError` at startup if either is missing in
staging or production.

## Storage: why a plain volume is not enough

`DirectoryImmutableCheckpointStore` uses `os.link()` (exclusive hard
link) so a checkpoint file, once written, cannot be silently overwritten
by a second write of the same filename within the same run.  However,
`os.link()` only works **within a single filesystem**.  A container's
writable layer is a local filesystem; it provides no tamper evidence if
the host is compromised.

**Production options (in increasing strength):**

1. **GCS/S3 Object Lock bucket** – mount via a FUSE sidecar (e.g.
   `gcsfuse`, `s3fs`, `mountpoint-s3`) and point `CHECKPOINT_DIR` at
   the mount.  Enable Object Lock in Compliance mode so even bucket
   owners cannot delete a file before its retention period expires.
2. **Off-host rsync** – after each checkpoint write, a DaemonSet or
   sidecar immediately `rsync --archive --checksum` the directory to an
   immutable remote destination.
3. **Separate write-only NFS share** – the application can write but not
   delete; the NFS server enforces this with ACLs.

For small deployments, option 2 with a nightly integrity check is
acceptable provided the rsync destination is on different infrastructure
from the application database.

## Scheduled checkpoints

Use the Kubernetes CronJob in `deploy/audit-checkpoint-cronjob.yaml`.
It runs every 15 minutes (at :03, :18, :33, :48 past each hour) and a
second job verifies the result 5 minutes later.

**To install:**

```bash
kubectl apply -f deploy/audit-checkpoint-cronjob.yaml
```

Create the required Secret first:

```bash
kubectl create secret generic toroka-ent-checkpoint-creds \
  --namespace toroka \
  --from-literal=checkpoint-api-token="<service-account-bearer-token>" \
  --from-literal=checkpoint-verify-url="http://enterprise-api:8080/api/enterprise/v1/audit/checkpoints"
```

> [!IMPORTANT]
> The bearer token must belong to a service account whose JWT `groups`
> claim (or the configured `role_claim`) maps to the `auditor` role in
> `TOROKA_ENT_ROLE_MAP_JSON`.  Investigators and authorisers must NOT
> be used for the scheduled checkpoint writer.

## Manual checkpoint smoke test

Run this after first deployment or after any HMAC key rotation:

```bash
# 1. Write a checkpoint
curl -s -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  http://localhost:8080/api/enterprise/v1/audit/checkpoints | jq .

# 2. Verify it (replace <id> with the checkpoint_id from step 1)
curl -s -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  http://localhost:8080/api/enterprise/v1/audit/checkpoints/<id>/verify | jq .

# 3. Tamper test: corrupt the checkpoint file and verify it fails
CHECKPOINT_DIR="${TOROKA_ENT_AUDIT_CHECKPOINT_DIR}"
LATEST=$(ls -t "${CHECKPOINT_DIR}" | head -1)
printf 'TAMPERED' >> "${CHECKPOINT_DIR}/${LATEST}"
curl -s -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  http://localhost:8080/api/enterprise/v1/audit/checkpoints/<id>/verify
# Expected: 400 / verification failure, NOT 200
```

## HMAC key rotation

> [!WARNING]
> Key rotation does NOT invalidate existing checkpoints.  Existing
> checkpoints remain valid under their original key.  Store old keys
> until all checkpoints signed with them have been archived (typically
> after the regulatory retention period).

1. Generate a new key: `python3 -c "import secrets; print(secrets.token_hex(32))"`
2. Update the secret (`TOROKA_ENT_AUDIT_CHECKPOINT_KEY`) in your KMS /
   Kubernetes Secret.
3. Roll the enterprise-api pods (zero-downtime rolling update is fine).
4. Run the manual smoke test above with the new key.
5. Keep the old key in a secondary secret for archival verification.

## Alerting

Configure an alert on:
- CronJob `audit-checkpoint-verifier` failing for any reason (backoffLimit=0,
  so a single failure means something is wrong).
- `audit-checkpoint-writer` failing 2 consecutive times (the writer has
  backoffLimit=2 to handle transient errors).

Both alerts should page on-call; a failed verify is a potential integrity
incident and must be investigated before the next business day.
