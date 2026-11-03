# Process optimization

Three processes: how a person decides whether a message is real (the product's reason to exist), how the official-source registry stays fresh (the moat's upkeep), and how you build and ship rule changes. Durations are **not measured yet**; where a number appears it is a design target, and anything about today's behaviour is a hypothesis to validate in the interviews.

## A. "Is this message real?" (user process)

### Current state (hypothesis, validate in interviews)
| # | Step | Who | Typical waste |
|---|---|---|---|
| 1 | Receive message, feel doubt | User | Pressure to act fast |
| 2 | Gut check; maybe screenshot | User | Rework: no shared criteria |
| 3 | Ask a friend or family WhatsApp group | User, then others | Waiting; handoff; opinions, not evidence |
| 4 | Search the number or the text | User | Over-processing; conflicting results; unknown sources |
| 5 | Hunt for the official site or number | User | Manual work; fake sites rank too |
| 6 | Call or message the organisation | User, organisation | Waiting; contact details may themselves be fake |
| 7 | Decide, act, optionally forward to 333 | User | Report loop gives little feedback |

Main waste: **waiting** (steps 3 and 6), **handoffs** (3, 6), **manual work** (4, 5), and decisions made on opinion rather than a dated source.

### Future state
| # | Step | Change |
|---|---|---|
| 1 | Receive message | Unchanged |
| 2 | Paste, share or forward it | One gesture replaces steps 2 to 4 |
| 3 | Automated checks run in parallel: rules, official statements, domains, (later) link reputation and reports | No human wait |
| 4 | Result: label, the one reason that matters, evidence with dates, what was not checked | Evidence instead of opinion |
| 5 | One next step, with the official source shown as a link the user opens themselves | Replaces the site hunt |
| 6 | Optional private report; the sender is never named publicly | Checkpoint, not a gate |

### Improvements
| Recommendation | Removes | Impact to measure |
|---|---|---|
| Single intake (paste, share target, later forward) | Steps 2 to 4 | Time from message to decision |
| Show sources and their review dates in the result | Step 5 | Share of users who open the official source |
| Coverage list ("not checked") instead of silence | Over-trust | Rate of acting on `inconclusive` correctly |
| Next step names the official channel | Step 6 guesswork | Contacted-organisation rate |
| Parallel checks with a time budget; show partial results with a clear status | Waiting | Design target: rules-only result in a few seconds on a 3G-class connection |

### Measures (instrument from the first pilot)
Time to decision; share of results where the user says the result changed what they would do; share of `inconclusive` results and what users do next; source-open rate; abandonment between paste and result; false-positive reports on genuine messages (from the golden suite and pilot feedback).

### Implementation plan
1. Interviews and the six-message test establish the baseline (research plan).
2. Ship the web slice with paste intake; log only counts and timings, never message text.
3. Add share-target (PWA), then forward-to-check once intake data shows what people send.
4. Review the measures after 30 days of pilot use and cut or add checks accordingly.

## B. Official-source registry upkeep (ops process)

### Plan in the blueprint
Weekly human review of changes, reviewer and expiry per record.

### Waste identified
Manual rereading of unchanged pages (over-processing); no signal when a page changes; one reviewer as a single point of failure; a growing registry nobody can keep fresh.

### Future state
1. **Expiry-driven queue.** Each statement has `last_verified_at` and `review_interval_days` (already in `registry.yaml`). A weekly job lists what falls due in the next 14 days.
2. **Change detection.** *Built:* `python -m app.cli registry-check` fetches each official page through the SSRF-guarded fetcher, hashes its visible text and reports `CHANGED: review needed`. It never edits a record or its verification date; a person re-verifies. `registry-due` lists what is stale or falling due.
3. **Two tiers.** Statements that can raise `high_risk` (fee and PIN rules) need human review; domain and contact lists can be machine-checked and human-sampled.
4. **Stale means weaker.** Already implemented: past review date, strength drops and the result says so.
5. **Cap and publish coverage.** Stay under about 30 sources until the process is proven; publish the list so users see what is covered.
6. **Checkpoints, not gates.** A reviewer can ship an update immediately and a second person samples after the fact for low-risk entries.

Measures: share of statements inside their review window; days from source change to registry update; rule-driven false positives and misses per month.

## C. Build and release process (rules and code)
1. Vertical slices: each slice goes from input to a tested result.
2. Every rule starts as a failing golden case (a real or invented message plus the expected label and findings).
3. Every false-positive report becomes a permanent guard case; the suite is the contract between rules, copy and policy.
4. CI on every push: tests must pass; a rule change that flips an existing golden case needs a written reason.
5. Policy changes bump `POLICY_VERSION`; results carry the version so disputes can be reproduced.
6. Trunk-based with small commits; feature flags for anything user-visible.
