# Toroka Enterprise (insider-risk investigation, seed)

Decision support for authorised investigators. It surfaces **leads with cited evidence**; it never labels a person.
Built on `toroka_core` (shared with the consumer app): typed evidence, source-independent scoring, injectable profile.

## What exists
| Module | Job |
|---|---|
| `mapping.py`, `ingest.py`, `schema.py`, `pseudonym.py` | Read-only flat-file extracts from any system via a mapping file -> keyed-HMAC pseudonymised dataset + a **data-quality report** (rejected rows, missing feeds, unmapped accounts, naive timestamps read as EAT, branches with incomplete CRM) |
| `scenarios.py` | Eight providers: access justification, bulk browsing, contact/authentication change, dormant/deceased reactivation, change-then-money, suspense-posting integrity, payroll beneficiary integrity, entitlement integrity |
| `profile.py` | Insider scoring policy and wording: no time decay on case evidence; **no single rule hit can take the "critical" shortcut**; review-state labels instead of risk verdicts |
| `scan.py` | Candidate focuses -> `EvidenceEngine` -> surfaced leads (PRIORITY REVIEW / REVIEW / CONFLICTING RECORDS) |
| `casework.py`, `audit.py` | RBAC case store, **dual-approval identity reveal** (different user, written reason, single use, 24h expiry), closing requires the alternative explanations considered; hash-chained append-only audit log |
| `coverage.py`, `discover.py` | Per-detector coverage on a given bank's data; mapping suggester (drafts only) |
| `foreign.py`, `replay.py` | Foreign-shaped test exports; synthetic extracts with injected patterns drawn from public cases, plus hard negatives and an evaluation harness |

## Run
```
export PYTHONPATH=../smart-scam-identifier/packages/core:.     # or TOROKA_CORE_PATH for tests
python -m toroka_enterprise demo            # synthetic end-to-end
python -m pytest -q                         # 33 tests
TOROKA_ENT_SECRET=... TOROKA_ENT_VAULT_KEY=$(python -m toroka_enterprise keygen) \
  python -m toroka_enterprise scan --data ./extracts --out ./out
```
Canonical feeds are specified in `ingest.SPEC`. `audit_log` and `system_accounts` are required; every other feed that is absent is reported as "could not check", never as clean.

## Working on any system (no per-bank code)
The engine never sees a core-banking vendor. A bank's exports are translated into the canonical feeds by a **mapping file** (TOML): per feed, which file/glob, delimiter, encoding, which source column is each canonical column, the timestamp format (`iso`, `epoch_s`, `epoch_ms` or any strptime pattern), and how the bank's codes translate (action codes, suspense GL codes, status flags).
```
python -m toroka_enterprise suggest-mapping --file AUDIT_TRAIL.txt --feed audit_log --out audit.toml   # a DRAFT: confirm every line
python -m toroka_enterprise validate --data ./extracts --mapping mapping.toml                          # reads, reports, writes nothing
python -m toroka_enterprise scan --data ./extracts --mapping mapping.toml --out ./out
```
Three behaviours make this safe on unfamiliar data: **unmapped codes are counted and reported** (never dropped silently); **fields the system does not supply are recorded as absent** and dependent checks stand down instead of inferring risk (no approver column does not mean "unapproved"); and the **coverage report** lists, per detector, READY / DEGRADED / CHECK / BLIND on that bank's data. "Works on any system" therefore means: works to the extent the system exposes the events a detector needs, and says plainly where it does not.

Minimum data per detector: access justification needs the audit log with customer ids plus portfolio assignments (CRM tickets strengthen it); contact-change needs audit events plus customer instructions; account lifecycle needs customer status/dormancy plus reactivation events and instructions; suspense and payroll checks need ledger postings with maker/checker (payroll also needs the HR roster with salary accounts); entitlement checks need the system-account list (leavers also need the HR roster).

Proof, with limits: two deliberately foreign exports (pipe-delimited with `dd/mm/yyyy` dates and vendor-style codes; tab-delimited with epoch seconds and dotted codes) produce findings identical to the canonical run. Both styles are **invented by me**, so this shows the mechanism works, not that any real vendor's export is covered. The suggester is a heuristic that matched all five audit-log columns on both invented styles; expect to correct it by hand on real exports. Not supported: fixed-width, XML/JSON or direct database reads; files are loaded in memory (very large audit logs need a streaming reader).

## What the synthetic result does and does not mean
The demo finds 9/9 injected patterns with 0 false review leads (also across 20 seeds). The injected patterns are the ones the providers were written for and the benign data comes from my own generator, so this is a **regression harness, not evidence of real-world performance**. Two things it does show: switching the CRM-gap gating off produces false leads from the one branch whose CRM isn't integrated, so data-quality gating is load-bearing; and the tests fail when guards are removed (mutation-checked).

## Not built / known limits
- No authentication or SSO: callers pass a `Principal`; a bank deployment must supply identities from its IdP.
- Audit chain is tamper-**evident**: deleting the tail is only detectable against a head hash stored outside the DBA's control.
- Batch extracts only; no live connectors, no streaming, no UI. SQLite stores are single-node.
- Shared/generic accounts, third-party (vendor) sessions, cash/vault reconciliation and whistleblower intake are not implemented.
- Thresholds (`Rules`) are defaults to be calibrated against a bank's own adjudicated cases.
- Legal review is required before processing any staff data (Data Protection Act DPIA, employment procedure, FRC confidentiality).
