# Toroka Enterprise — Security & Privacy Boundaries in Intelligence

## 1. Zero-PII Policy in Intelligence Tables

To comply with banking secrecy, GDPR, and Kenya Data Protection Act (KDPA), Toroka enforces a **strict Zero-PII boundary** in all intelligence tables:

1. **No Plaintext Names or Government IDs**: Employee and customer identifiers in `enterprise_intelligence_events`, `relationships`, and `signals` use pseudonymous tokens (e.g. `emp_teller_42`, `cif_vip_1001`).
2. **Isolation from Identity Vault**: The intelligence subsystem has NO direct access to `enterprise_identity_vault` or the vault master encryption keys.
3. **Ephemeral Identity Reveal Integration**: If an investigator requires the real-world identity of an employee or customer, they must submit a formal `RevealRequest` through the Phase 3.2/3.4 maker-checker governance workflow. Plaintext identities are never cached or stored in the intelligence bundle.

---

## 2. Strict Installation Multi-Tenancy Isolation

Toroka installations operate with zero cross-tenant contamination:
- `installation_id` is derived strictly from the authenticated OIDC token / session principal, never from user-supplied URL or query parameters.
- All database queries filter explicitly by `installation_id`.
- Entity references and relationship edges validate that `source.installation_id == target.installation_id == self.installation_id`.
- Temporal correlation windows only fetch events registered to the active installation.

---

## 3. Query Performance & Anti-DoS Boundaries

To prevent long-running table locks or Denial-of-Service through unconstrained database joins:
1. **Bounded Time Windows**: Correlation queries require explicit windows (`start_time <= event_time <= end_time`) with default limits of [-60m, +60m] up to a maximum of 24 hours.
2. **Targeted Entity Queries**: Timeline and relationship queries use index lookups on `actor`, `subject`, `source_id`, and `target_id`.
3. **No Unbounded Graph Traversal**: Relationship retrieval queries only 1-hop direct neighbors, avoiding runaway recursive graph traversals.
