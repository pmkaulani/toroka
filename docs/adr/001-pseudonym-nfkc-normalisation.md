# ADR-001: Unicode normalisation is NOT applied to identifier inputs

**Status:** Accepted  
**Date:** 2026-11-28  
**Deciders:** Security review (reviewer@), engineering  

---

## Context

`Pseudonymiser.ref()` computes `HMAC-SHA256(key, identifier.strip().casefold())`.
Two questions were raised during the security review:

1. Should we also apply NFKC (or NFC) normalisation before the HMAC so that
   visually identical strings produce the same pseudonym?
2. If we do not, what are the consequences?

## Decision: NFKC normalisation is intentionally omitted

Identifiers ingested by the enterprise layer come from bank core-banking
systems (CBS) over ISO 20022 or the bank's own integration APIs.  Bank
systems typically:

- normalise their own master-data at input time (account opening),
- store a canonical form (usually plain ASCII or NFC-normalised UTF-8), and
- always return that same canonical form in every message.

Applying a second normalisation inside Toroka would:

1. **Mask cross-bank duplicates that are not real duplicates.**  Two banks
   may legitimately hold customers whose names differ only by Unicode
   decomposition (rare but not impossible for transliterated names).
   Silently merging their pseudonyms would create false links.

2. **Create a maintenance hazard.**  If a future CBS upgrade changes its
   own normalisation form, identifiers that were stored pre- and post-
   upgrade would suddenly produce different pseudonyms even though the
   bank considers them the same person.  The correct fix in that case is
   a migration script (see `Pseudonymiser.legacy_ref()`), not silent
   normalisation.

3. **Conflict with regulatory traceability.**  Audit rows must be traceable
   back to the exact string the bank provided.  Altering the string before
   hashing makes that trace ambiguous.

## Consequences

- If a CBS sends the same identifier with different Unicode representations
  in different messages, two distinct pseudonyms will be created.  This is
  treated as a data-quality issue on the bank's side, not a Toroka bug.
- If a bank upgrades its CBS and changes normalisation form, a pseudonym
  migration must be run (using `Pseudonymiser.legacy_ref()`) before the new
  form is live.  This is documented in the pseudonym migration runbook.
- `casefold()` (Python's Unicode case-folding, which is a superset of
  `str.lower()`) is still applied so that case differences in latin
  identifiers (e.g. `EMP-123` vs `emp-123`) do not produce distinct
  pseudonyms.

## Alternatives considered

| Option | Rejected because |
|---|---|
| Apply NFKC before HMAC | Creates false identity merges; masks real data-quality issues |
| Apply NFC only | Same risk, smaller scope — does not resolve the ambiguity |
| Store raw + normalised pseudonyms | Doubles storage and complicates every query |
