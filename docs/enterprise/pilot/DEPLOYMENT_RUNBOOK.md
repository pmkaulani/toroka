# Toroka Enterprise — Pilot Deployment Runbook

## 1. Prerequisites & Resource Sizing

### 1.1 Infrastructure Requirements
- **Compute**: Linux VM or Kubernetes cluster (x86_64, 4 vCPU, 8GB RAM minimum per replica).
- **Runtime**: Docker Engine 24+ / Containerd / Podman.
- **Persistence**: Two separate PostgreSQL 16 instances (Operational DB and Vault DB).
- **Identity Provider**: OIDC-compliant Identity Provider (Active Directory, PingFederate, Okta, Keycloak) supporting RS256/ES256.
- **KMS / HSM**: Bank key management service capable of AES-256-GCM data key generation and unwrap.
- **Immutable Storage**: Object store supporting WORM (Write Once Read Many) / S3 Object Lock.

---

## 2. Secrets & Credential Provisioning

Create the protected secrets directory on the deployment host (permission `0700`, owner `toroka`):

```bash
mkdir -p /opt/toroka/secrets
chmod 700 /opt/toroka/secrets

# Generate strong database passwords and service tokens
openssl rand -hex 32 > /opt/toroka/secrets/enterprise_db_password.txt
openssl rand -hex 32 > /opt/toroka/secrets/vault_db_password.txt
openssl rand -hex 32 > /opt/toroka/secrets/vault_service_token.txt

# Configure connection URLs with TLS enabled
echo "postgresql+psycopg://toroka_ent:$(cat /opt/toroka/secrets/enterprise_db_password.txt)@enterprise-db.internal:5432/toroka_enterprise?sslmode=verify-full" > /opt/toroka/secrets/enterprise_database_url.txt
echo "postgresql+psycopg://toroka_vault:$(cat /opt/toroka/secrets/vault_db_password.txt)@vault-db.internal:5432/toroka_vault?sslmode=verify-full" > /opt/toroka/secrets/vault_database_url.txt

chmod 600 /opt/toroka/secrets/*.txt
```

---

## 3. Database Migration Execution (Dedicated Release Step)

> [!IMPORTANT]
> Never allow application container replicas to independently run schema migrations upon startup. Migrations must be run as an isolated pre-deployment job by a dedicated migration user.

```bash
# Run operational database migrations
docker run --rm \
  --network operational_db \
  -v /opt/toroka/secrets:/run/secrets:ro \
  -e TOROKA_ENT_DATABASE_URL_FILE=/run/secrets/enterprise_database_url \
  toroka/enterprise-api:latest \
  alembic -c services/enterprise_api/alembic.ini upgrade head
```

Verify migration revision:
```bash
# Check Alembic version in operational database
docker run --rm \
  --network operational_db \
  -v /opt/toroka/secrets:/run/secrets:ro \
  -e TOROKA_ENT_DATABASE_URL_FILE=/run/secrets/enterprise_database_url \
  toroka/enterprise-api:latest \
  alembic -c services/enterprise_api/alembic.ini current
```

---

## 4. Container Deployment via Docker Compose

Deploy the isolated stack using `compose.enterprise.yaml`:

```bash
docker compose -f compose.enterprise.yaml up -d
```

Verify container status and non-root execution:
```bash
docker compose -f compose.enterprise.yaml ps
docker compose -f compose.enterprise.yaml exec enterprise-api id
# Output must report uid=10001(toroka) gid=10001(toroka)
```

---

## 5. Ingress & TLS Reverse Proxy Configuration (Nginx Example)

```nginx
# /etc/nginx/conf.d/enterprise_bank.conf
limit_req_zone $binary_remote_addr zone=enterprise_api_limit:10m rate=10r/s;

server {
    listen 443 ssl http2;
    server_name toroka.bank.internal;

    ssl_certificate /etc/ssl/certs/toroka_bank_internal.crt;
    ssl_certificate_key /etc/ssl/private/toroka_bank_internal.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    # Institutional HSTS & Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    client_max_body_size 10m;

    # Enterprise API routes
    location /api/ {
        limit_req zone=enterprise_api_limit burst=20 nodelay;
        proxy_pass http://127.0.0.1:8101;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Correlation-ID $request_id;
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
    }

    # Enterprise Workbench (same-origin static assets)
    location /workbench/ {
        proxy_pass http://127.0.0.1:8101;
        proxy_set_header Host $host;
    }

    # Health probe endpoints
    location /health/ {
        proxy_pass http://127.0.0.1:8101;
    }
}
```

---

## 6. Service Health & Readiness Verification

```bash
# Verify process liveness
curl -k -f https://toroka.bank.internal/health/live
# Expected response: {"status": "alive", "service": "toroka-enterprise-api"}

# Verify deep deployment readiness (DB, Schema, Vault, Audit)
curl -k -f https://toroka.bank.internal/health/ready
# Expected response: {"status": "ready", "service": "toroka-enterprise-api", "persistence": "connected", "vault": "connected"}
```

---

## 7. Rollback Procedure

If deployment verification fails:
1. Revert DNS or Ingress router to previous release tag.
2. If schema rollback is required and backward-compatible:
   ```bash
   docker run --rm \
     --network operational_db \
     -v /opt/toroka/secrets:/run/secrets:ro \
     -e TOROKA_ENT_DATABASE_URL_FILE=/run/secrets/enterprise_database_url \
     toroka/enterprise-api:latest \
     alembic -c services/enterprise_api/alembic.ini downgrade -1
   ```
3. Restart previous version containers.
