# Toroka Enterprise Secrets Directory

This directory contains file-based secrets for `compose.enterprise.yaml` and production container deployments.

> [!WARNING]
> Do NOT commit real secrets, production credentials, or database passwords to git.
> The `.gitignore` file ignores `secrets/` except for template files.

To populate local test secrets:
```bash
echo "test_ent_db_secret_pass" > secrets/enterprise_db_password.txt
echo "test_vault_db_secret_pass" > secrets/vault_db_password.txt
echo "postgresql+psycopg://toroka_ent:test_ent_db_secret_pass@enterprise-db:5432/toroka_enterprise" > secrets/enterprise_database_url.txt
echo "postgresql+psycopg://toroka_vault:test_vault_db_secret_pass@vault-db:5432/toroka_vault" > secrets/vault_database_url.txt
echo "toroka_super_secure_vault_service_token_32chars_min" > secrets/vault_service_token.txt
```
