# Toroka Phase 7 — Integration Guide

**Version:** 7.0.0  
**Purpose:** Add operational intelligence, provider governance, correction-capable case memory and multilingual evaluation to the existing Toroka backend.

## 1. Integration boundary

This is an additive Python package. Copy `toroka_phase7/` beside the existing Toroka phase packages. Do not replace the existing FastAPI application, chat flow, verdict engine, logo, frontend shell, or database migrations.

The current Phase 2 assessment remains the only final verdict authority. Phase 7 emits feed matches, language signals, operational status and reviewed memory observations. A signal is not a fraud finding. A campaign relationship does not transfer a verdict to another merchant.

## 2. Configuration and secrets

- Use the **same stable HMAC secret already used by Phase 3** for entity-link compatibility. Do not create a second unrelated secret. Store it in the backend secret manager; require at least 32 bytes. Rotating it breaks cross-phase matching unless a controlled migration is prepared.
- Keep provider credentials in server-side secret storage and send them in provider-required headers. Never embed credentials in URLs, frontend bundles, logs or metrics.
- Place SQLite databases on persistent, encrypted storage with backups and tested restore procedures. For multi-instance production deployments, consider a managed database and implement a concurrency-safe adapter before horizontal scaling; do not put a SQLite file on an unsafe shared network filesystem.
- Keep operations state and case memory logically separate. Apply the organisation's data-retention and deletion policy to both.

## 3. Provider enablement workflow

`reference_feed_catalog()` is a research checklist; every entry is disabled and is not a pre-approved data source. Before registering a provider:

1. Obtain the exact feed endpoint and current terms for the specific plan/API.
2. Have the current terms, commercial/internal-use permission, display permission, redistribution rights, attribution, privacy treatment, rate limits and retention reviewed by an authorised operator/legal reviewer.
3. Record the terms review timestamp and a bounded re-review period.
4. Record the exact HTTPS endpoint host in `allowed_hosts` (no wildcard domains).
5. Set `commercial_use_allowed`, `internal_check_allowed`, `display_allowed`, `redistribution_allowed` and `permission_confirmed` according to the approved scope. These are separate permissions.
6. Register the policy only after the review. A successful API call is not proof of redistribution rights.

PhishTank's older FAQ and current terms page require reconciliation against the current Cisco terms before activation. OpenPhish commercial operational use requires prior written permission under its published terms. Provider access is intentionally disabled by default; do not enable a feed based on this package's examples.

## 4. Safe worker and scheduling integration

The package has no daemon, scheduler or built-in network client. The host application should call `Phase7Coordinator.refresh_due_feeds()` from its existing background-job system, not from a user chat request.

```python
from toroka_phase7 import (
    OperationsStore, FeedRunner, Phase7Coordinator,
    CaseMemoryStore, RuntimeConfig,
)

operations = OperationsStore("data/toroka_ops.sqlite3")
# `approved_fetcher` is implemented by your server and provider-specific policy.
runner = FeedRunner(operations, fetcher=approved_fetcher,
                    worker_id="toroka-feed-worker-01")
memory = CaseMemoryStore(
    "data/toroka_case_memory.sqlite3",
    secret=existing_phase3_entity_hash_secret,
    retention_days=180,
)
coordinator = Phase7Coordinator(
    feed_runner=runner,
    operations_store=operations,
    case_memory=memory,
)

# From a scheduled worker only:
result = coordinator.refresh_due_feeds()

# In an investigation request; signal-only response, never a verdict:
language_signals = coordinator.analyze_text(message_text)

# Admin-only operational view:
health = coordinator.operational_status()
```

`FeedRunner` injects a fetch callback and enforces response type/size, content type, final HTTPS host allowlist, retries and lease ownership. **The injected HTTP client still has to enforce SSRF-safe egress**:

- Resolve the hostname immediately before connecting; reject all private, loopback, link-local, multicast, reserved and non-global IP answers.
- Pin the actual connection to an approved resolved IP while preserving the original hostname for TLS SNI and certificate verification. Protect against DNS rebinding.
- Disable automatic redirects, or validate every redirect hop from scratch against HTTPS, exact host allowlists and public IP rules.
- Use connect/read timeouts, response byte limits, content-type checks, bounded decompression, and no cookies or user-supplied authorization headers.
- Never use this provider fetcher for arbitrary user-submitted URLs. Website investigation must use a separate SSRF-hardened fetch service.
- Honor `Retry-After`, plan-specific quotas and provider backoff. Do not run overlapping workers for one feed; use the database lease.

Use one external scheduler (existing Celery/RQ/APScheduler/managed job/cron) at or above each feed's approved `poll_interval_seconds`. Configure alerts for stale feeds, repeated failures and circuit-open state. `metrics_snapshot()` contains aggregate counts only; do not add domains, phone numbers, case references or customer identifiers as metric labels.

## 5. Cross-phase wiring

### Phase 3 — entity graph

`CaseMemoryStore` is designed to reuse Phase 3's HMAC convention: `toroka-v3:{kind}:{normalized}`. Supply the same secret. Domain, Kenyan mobile and social-handle digests are compatible. Never return or log raw identifiers during graph lookup.

### Phase 4 — threat cache

`OperationsStore.export_to_phase4()` imports current feed indicators into an already-registered Phase 4 `ThreatIntelStore`. It requires the Phase 7 source policy to allow end-user display, and Phase 4 must have its own appropriate source/attribution policy configured. Internal-check permission alone is not permission to display or redistribute. Do not export sources whose licence permits checking only.

### Phases 2, 5 and 6 — investigation

- Pass fresh feed hits and Phase 7 language signals as source-labelled evidence into the existing Phase 5 fusion layer.
- Preserve provenance/source-family deduplication. One user sending an SMS and screenshot does not automatically count as two independent sources.
- Keep Phase 3 graph edges as contextual leads, not guilt by association.
- Keep the Phase 6 website/social/image/voice evidence behind its existing isolated provider and user-capture safeguards.
- Pass the fused evidence to the Phase 2 assessor for the final `safe / suspicious / high risk / inconclusive`-style result already used by Toroka. Do not let Phase 7 bypass it.

## 6. Case memory, review and corrections

- Store only HMAC entity fingerprints, opaque case/evidence references, source-family labels, moderation state and expiry. Do not put full SMS, receipt images, raw phone numbers, raw domains or reporter identifiers in memory.
- Unreviewed submissions are private and cannot appear in public lookup. A public `corroborated_indicator` requires an authoritative permitted source or at least two independent server-assigned source families and a moderator decision.
- **Never accept `actor_role`, `source_family`, `authoritative_source` or source provenance from a browser request.** Derive these values in authenticated backend middleware/workflows and enforce record-level authorisation before calling the store.
- Use opaque case IDs and evidence references. Verify that the correction requester can access the target record before `request_correction()`; the store method itself does not authenticate the requester.
- Open correction requests suppress the memory result until resolved. Accepted corrections deactivate the record. Provide a visible correction/removal route and retain an audit trail consistent with the retention policy.
- Schedule `CaseMemoryStore.purge_expired()` and `OperationsStore.prune_expired_indicators()` as maintenance jobs. Test deletion and restore.

## 7. Kenyan advisories and privacy

Use `kenya_reference_sources()` as a directory of official National KE-CIRT/CC and Communications Authority resources. `curate_ke_cirt_advisory()` creates a manually reviewed, cited summary only; it does not crawl the site or transform national statistics into an IOC. Link to the source, publication date and retrieval date, and distinguish historical context from current intelligence.

Kenyan phone numbers, location information, online identifiers, images and audio can be personal data. Do not infer that the small-entity registration exemption applies to Toroka; the ODPC FAQ includes categories that are not exempt, including certain crime-prevention/prosecution purposes. Obtain qualified Kenyan privacy advice on controller/processor roles, lawful basis, notice, DPIA, registration, retention, user rights and cross-border processors before production.

## 8. Release checklist

Use `production_readiness(RuntimeConfig(...))` to record controls. It is not a compliance certificate. Before production, require secrets management, TLS, encryption at rest, backup/restore, rate limits, audit logs, monitoring/alerts, governance, ODPC assessment, privacy impact review, tested deletion, current provider terms, incident runbook and human review for public claims.

`shadow_release_gate()` only authorises shadow evaluation, never production promotion. It requires sufficient overall and language-specific evidence for English, Kiswahili and Sheng. Synthetic tests are not production quality evidence. Use campaign-separated, independently labelled, representative test data, and obtain consent/lawful basis before any model training.

## 9. Test and run

```bash
python -m unittest discover -s tests -v
python examples/phase7_demo.py
```

The unit suite uses synthetic data and no external network calls. The optional Phase 4 bridge test skips when the Phase 4 package is not on `PYTHONPATH`.
