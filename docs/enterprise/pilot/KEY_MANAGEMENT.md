# Toroka Enterprise — Key Management & Cryptographic Operations

## 1. Architectural Principles & Envelope Encryption

Toroka Enterprise delegates all master key management to the bank's approved Key Management Service (KMS) or Hardware Security Module (HSM). The application never stores master encryption keys on disk or in environment variables.

```
+--------------------------------------------------------------+
|                    Bank KMS / HSM Boundary                   |
|                                                              |
|   Master Key Encryption Key (KEK) : alias/toroka-vault-kek   |
|     - Kept inside KMS HSM boundary                           |
|     - Accessible only via authenticated IAM / Service Role   |
+--------------------------------------------------------------+
                               |
            generate_data_key  |  decrypt_data_key
                               v
+--------------------------------------------------------------+
|             Toroka Identity Vault Container Runtime          |
|                                                              |
|   Ephemeral Data Encryption Key (DEK): 256-bit AES-GCM       |
|     - Used in RAM only for single pseudonym encryption       |
|     - Zeroized / discarded after operation                   |
|     - Stored wrapped (encrypted by KEK) alongside record     |
+--------------------------------------------------------------+
```

---

## 2. Key Hierarchy & Envelope Structure

1. **Master Key Encryption Key (KEK)**:
   - Managed in bank KMS (e.g., AWS KMS, Azure Key Vault, Google Cloud KMS, HashiCorp Vault Transit, or Thales HSM).
   - Identified by an ARN or alias (e.g., `alias/toroka-enterprise-identity-vault`).
2. **Encrypted Data Encryption Key (EDK)**:
   - Unique 32-byte key generated per identity mapping record.
   - Wrapped by the KEK and stored in `enterprise_identity_vault.ciphertext`.
3. **Payload Envelope Format**:
   ```json
   {
     "format": "envelope_aes_256_gcm",
     "version": "v1",
     "kms_key_id": "alias/toroka-enterprise-identity-vault",
     "edks": "<base64-encoded-kms-wrapped-dek>",
     "nonce": "<base64-encoded-12-byte-nonce>",
     "ct": "<base64-encoded-ciphertext-and-auth-tag>"
   }
   ```
4. **Authenticated Additional Data (AAD)**:
   - Every ciphertext is authenticated against `AAD = f"{installation_id}:{pseudonym}".encode("utf-8")`.
   - Modifying the pseudonym, swapping records, or changing the installation ID immediately invalidates decryption with an AESGCM tag verification failure.

---

## 3. Key Rotation Procedure

Toroka Enterprise supports multi-version key management. Existing ciphertext records retain their `key_version` in the database:

1. **Create New KEK in Bank KMS**:
   - Provision `alias/toroka-vault-kek-v2`.
2. **Update Vault Configuration**:
   - Set `TOROKA_VAULT_KEY_VERSION=v2`.
   - Map `{"v1": "alias/toroka-vault-kek-v1", "v2": "alias/toroka-vault-kek-v2"}` in key configuration.
3. **Transparent Re-encryption**:
   - New identity mappings are encrypted with `v2`.
   - Existing records are decrypted using `v1` and re-wrapped with `v2` during scheduled maintenance or access:
     ```python
     vault_repo.rotate_key(installation_id, pseudonym, new_key_version="v2")
     ```
   - Historical records remain decryptable as long as `v1` KEK is preserved in decrypt-only mode.

---

## 4. Compromise & Revocation Runbook

If a KMS key or vault credential is suspected of compromise:
1. **Trigger Reveal Kill Switch**:
   - Remove or rotate `TOROKA_VAULT_SERVICE_TOKEN` to immediately block the Enterprise API from calling reveal endpoints.
2. **Revoke KMS Permissions**:
   - Disable the compromised KEK in the bank KMS console.
   - Decryption attempts will fail closed (`KMS unavailable / access denied`).
3. **Audit Access Logs**:
   - Review KMS CloudTrail / audit logs for all decrypt requests during the suspect window.
   - Cross-reference KMS requests against `enterprise_audit_records` for corresponding `reveal_consumed` events. Any KMS decrypt without a matching audit record indicates out-of-band compromise.
