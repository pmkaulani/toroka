# ADR-003: Privacy by default: short-retention encrypted storage (amended)

**Status:** Proposed (amended 20 Oct 2026; replaces the first-release decision to store nothing)
**Deciders:** Kaulani (founder). Needs Kenyan data-protection advice (this document is not legal advice).

## Context
The first release stored only a hash of the submitted text. The feature set now needs more: adding a screenshot re-assesses the whole check, people can see and delete their history, and results can be exported. All of that needs the submitted text for a short time. People paste names, numbers, ID details and sometimes PINs.

## Decision
- Submitted text is stored only as a Fernet-encrypted field. PIN/OTP-like values are masked **before** encryption, so they are never stored in any form.
- Default retention is 7 days, then a purge job deletes the check, its screenshots, extractions, signals and assessments. People can delete earlier, and export what we hold.
- Screenshots are re-encoded (EXIF and appended data dropped), encrypted on disk, kept for the same period, and **never served back**: no route returns a stored file. Only redacted extracted text is shown to the owner.
- Phone numbers are masked in results. Identifiers used for lookup are stored as keyed HMAC digests, never in indexes in plain form.
- Reports: the narrative is encrypted and private; only a moderated indicator (identifier, count, month) is searchable.
- Channel senders (WhatsApp, SMS): the sender number is used to reply and as an HMAC rate-limit key; the reply outbox stores it encrypted.
- No message text in logs, URLs, analytics or error responses. Result links carry the access token in the URL fragment, which browsers do not send to servers.

## Options Considered
### A. Store nothing raw (the original decision)
Simplest and safest, but it cannot support adding evidence, history, export or re-checking. Rejected now that those features exist.
### B. Encrypted storage with short retention (chosen)
Supports the features with a small exposure window. Needs key management, a purge job (built) and a documented posture before real users.
### C. Longer retention for re-checks and an evaluation set
More useful for improvement, much larger legal and breach exposure. Deferred: an evaluation set should come from a separate, explicit consent flow.

## Trade-off Analysis
B gives up some of A's simplicity to make the product usable, and keeps C's risks out. The weak points are operational: one encryption key (no rotation yet), backups that outlive the purge, and a synchronous pipeline with no worker isolation.

## Consequences
- Easier: adding screenshots, history, delete and export; explaining retention in one sentence.
- Harder: key management, backup policy, breach response, proving deletion.
- Revisit: when real users arrive, and before any longer retention or evaluation-set collection.

## Action Items
1. [x] Encrypted text, masking before storage, hashed lookups, token-gated reads, purge job, delete and export (tested).
2. [ ] Get Kenyan data-protection advice: registration, impact assessment, lawful basis, cross-border hosting.
3. [ ] Key management and rotation (switch to MultiFernet, document recovery), and a backup retention policy that matches the purge.
4. [ ] Write the user-facing privacy notice in English and Swahili.
5. [ ] Separate consent flow before any message is kept for evaluation.
