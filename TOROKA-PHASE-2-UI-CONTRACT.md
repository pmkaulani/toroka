# Phase 2 — UI contract for explainable results

Use this as the response contract for the Toroka chat UI.

## Result header

- Verdict label and confidence
- Short conclusion that is grounded in the evidence
- `Risk index: NN/100` only if there is usable evidence, with a persistent note: `Signal index, not a probability`

## Evidence groups

**Risk indicators** — each entry must include source, observed date, summary, strength, confidence, and source link.

**Identity and business signals** — company/business registration evidence, website/domain matches, phone consistency, and business profile links. Distinguish self-asserted details from independently checked records.

**Physical location candidates** — address, source attribution, Google Maps link, phone match, website match, and the explicit state `Not independently verified` unless a genuine official check was performed.

**Unknown / not checked** — providers unavailable, private social profile, inaccessible page, no public reports, or no registry query. These are gaps, not positive evidence.

## Required language

Prefer: `We found a third-party listing matching the name and area.`

Avoid: `This is their verified shop.`

Prefer: `No threat-feed hit was returned for this domain.`

Avoid: `This website is safe.`

Prefer: `The BRS record confirms that an entity with this name is registered; it does not confirm this social account or payment recipient.`

Avoid: `BRS verified this Instagram seller.`

Prefer: `No independent complaints were found in the sources checked.`

Avoid: `No complaints exist.`
