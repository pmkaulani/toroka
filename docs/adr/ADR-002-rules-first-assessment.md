# ADR-002: Rules-first, evidence-based assessment; no model decides the label

**Status:** Proposed
**Date:** 2026-10-20
**Deciders:** Kaulani (founder); Kenyan counsel to review the wording policy before public launch.

## Context
The product tells people whether to pay. A false accusation harms a business or person; a false reassurance costs someone money. The blueprint already forbids a bare score, accusations, and fabricated certainty. Early on there is no report database, so many checks will have little evidence.

## Decision
The label comes from a small, readable policy over **findings** and **coverage** (`assessment-policy-v0.1`):
- `high_risk` only when a verified official statement is contradicted by the message;
- `suspicious_verify_first` when any supporting-strength signal exists;
- `inconclusive` when only weak signals exist, or a blocking check could not be run;
- `no_known_threats_found` otherwise, always with the list of what was not checked.

Language models, when added, may extract fields or draft plain-language text from findings. They never choose or change the label, and message text is treated strictly as data.

## Options Considered

### Option A: Rules and official registry decide; models only assist
| Dimension | Assessment |
|-----------|------------|
| Complexity | Low now, grows with rule count |
| Cost | Near zero per check |
| Scalability | Excellent: deterministic and cacheable |
| Team familiarity | High |

**Pros:** explainable, testable, no prompt-injection path to the label, defensible in a dispute.
**Cons:** misses novel scams and unseen phrasing; Swahili and Sheng coverage needs hand work.

### Option B: LLM classifier decides, rules as guardrails
**Pros:** broader recall. **Cons:** non-deterministic, hard to explain, injectable, per-check cost, and hard to defend when a business disputes a result.

### Option C: Single numeric risk score
Rejected: invites false precision, which the blueprint explicitly warns against.

## Trade-off Analysis
Precision and defensibility beat recall at this stage. Recall can be bought later with a model that only **proposes** candidate findings for human review into the rules library.

## Consequences
- Easier: golden-case tests, audits, dispute handling, offline development.
- Harder: coverage of new scam patterns depends on how fast rules and the registry are updated.
- Revisit: after the pilot, measure how often results are `inconclusive` and which missed patterns drive it.

## Action Items
1. [x] Implement policy v0.1 with 74 passing tests (including false-positive guards).
2. [ ] Collect real, consented messages as the evaluation set (research plan).
3. [ ] Define how a rule change is reviewed and versioned (policy v0.2 process).
4. [ ] Counsel review of wording and the dispute path.
