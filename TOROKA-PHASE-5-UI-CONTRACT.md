# Toroka Phase 5 — UI Contract

## Design intent

Present the result as an investigation with visible evidence, not a dramatic single-number scam score. Preserve Toroka's existing logo, ChatGPT-familiar chat composition, no-account barrier and English/Swahili experience. Phase 5 augments the existing result; it must not introduce a second, competing verdict.

## 1. Investigation overview

Payload fields:

- `case_ref`
- `indicator_band`: `insufficient_evidence`, `limited_signals`, `review_recommended`, `elevated_signals`
- `evidence_strength`
- `independent_source_groups`
- `evidence_count`
- `verdict_policy`

Display copy:

| API band | Customer-facing wording |
|---|---|
| `insufficient_evidence` | Not enough evidence to assess this confidently |
| `limited_signals` | A few indicators need checking |
| `review_recommended` | Important discrepancies or warning signs found |
| `elevated_signals` | Multiple independent source families support warning signs |

Always add: “This is an evidence assessment, not a legal finding. Verify the recipient and business independently.” Never translate a band directly to “scammer” or “safe”.

## 2. Evidence cards

Each signal contains:

- `category`, `severity`, `summary`, `explanation`
- `source_group`, `evidence_ref`, `observed_at`
- `confidence` (internal rule confidence; not a probability of fraud)
- `excerpt` (already redacted)
- `limitations`

Card design should show what was observed, why it matters, where it came from, when it was observed and what it does *not* prove. Keep source and evidence details expandable to avoid overwhelming chat.

## 3. M-PESA receipt comparison

Render `artifact_summaries[].receipt_analysis` as a compact comparison:

| Field | UI display |
|---|---|
| `parsed_amount` | Amount visible in supplied receipt text |
| `amount_match` | Match / Does not match / Not enough information |
| `recipient_identifier_masked` | Masked Till/Paybill/account identifier |
| `recipient_identifier_match` | Match / Does not match / Not enough information |
| `recipient_name_masked` | Masked name from receipt text |
| `recipient_name_match` | Match / Does not match / Not enough information |
| `payment_verified` | Always show “Not verified by this screenshot check” |
| `status` | Parsed consistency check / Insufficient receipt fields |

If a value is `null`, show “Not found in the supplied text”; do not infer it. A matching receipt must not receive a green “payment successful/verified” badge. A mismatch should offer steps to check the original transaction record and contact the merchant via an independently sourced channel.

## 4. Conversation timeline

Use `artifact_summaries[].conversation_timeline`:

- message index;
- role;
- timestamp;
- event category.

Do not display or reconstruct raw message text from this payload. Provide a source link back to the user's original upload where the current privacy policy allows. Label events as “pattern observed”, not “seller committed fraud”.

## 5. Evidence strength and provenance

`independent_source_groups` describes provenance families, not how many signals or uploads exist. Explain that multiple user-submitted artifacts are not necessarily independent. Threat-feed/official/provider sources should display their own source attribution and freshness from Phase 4.

Campaign and entity graph relationships remain in a separate “Related signals” section and should say “possible connection” with a short explanation. Phase 3 relationship signals are contextual only, even when the relationship assertion itself has been verified. Do not transfer another profile's verdict to this seller.

## 6. Model shadow panel

Customer UI should not show model probabilities, suggested scam labels or internal model identifiers. Shadow results belong in an admin-only evaluation dashboard. If model inference fails, it should not create an error in the customer's investigation; the evidence response continues.

## 7. Corrections and feedback

Provide “This finding is incorrect” or “Add context” actions using the existing moderation/feedback workflow. Keep consent explicit and separate from using the application. A correction is pending until reviewed; user allegations must not instantly change shared seller reputation.

## 8. Accessibility and language

- All states must work in English and Kiswahili; preserve mixed-language content as submitted.
- Use text labels and icons together; do not use color alone to communicate severity.
- Keyboard focus, screen-reader labels and responsive card stacking are required.
- Avoid alarmist motion, sounds, flashing, or red full-screen warnings.
- Keep the input/composer visible and preserve existing chat history interactions.
