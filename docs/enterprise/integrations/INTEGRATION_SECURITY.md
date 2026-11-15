# Toroka Enterprise — Integration Security Architecture

## 1. Zero-Trust Security Perimeter

The Toroka integration layer adheres to strict zero-trust operational security guidelines:

1. **Cryptographic Secret Storage**: Connector API keys, webhook HMAC secrets, and database credentials are never stored in plaintext within source code or repository commits. They are injected via environment variables or retrieved from an enterprise secrets manager (HashiCorp Vault, AWS Secrets Manager).
2. **Network Segmentation & Egress Control**: In production environments, Toroka services reside within a dedicated Virtual Private Cloud (VPC) / subnet. Egress traffic is restricted via firewall rules to pre-approved internal bank endpoints.
3. **No Dynamic Outbound Fetching**: The API gateway forbids dynamic, user-supplied outbound URL calls. Connectors require static whitelisting (`allowed_hosts`).
4. **Least-Privilege Database Accounts**: Database connectors connect via dedicated SQL users granted solely `SELECT` permissions on specific reporting views. `INSERT`, `UPDATE`, `DELETE`, `DROP`, and `ALTER` grants are strictly denied at the database server level.
5. **Separation of Integration vs. Casework**: The integration service account has no authority to review case files, view plaintext customer identities, or approve closure proposals.
