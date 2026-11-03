# Toroka Phase 3 UI Contract

This adds detail to the current Toroka chat experience; it is not a new dashboard and does not replace the existing logo, composer or conversation layout.

## 1. Connected entities

Render an expandable section titled **Connections found** only when relationship assertions exist.

Each connection card contains:
- Identifier type, such as `Website`, `Phone`, `M-PESA Paybill`, `Social profile`, `Business registration` or `Location`.
- Relationship phrase, such as `Profile lists this website` or `Seller requests payment to this Paybill`.
- Source label, clickable source link if one exists, observation date, evidence ID and status.
- Match confidence as a qualitative descriptor (`Low`, `Moderate`, `High`) with the note: **confidence in matching this relationship, not fraud probability**.
- Limitations and an explicit **This connection does not prove common ownership or wrongdoing** note for shared identifiers.

The graph uses pseudonymous node references. Historical identifiers should not be revealed from the graph database. A masked value may be shown only when it is available in the current user's submitted case and local display policy allows it.

## 2. Shared infrastructure

Render a separate card titled **Shared infrastructure**. State exactly what is shared and how many seller records currently contain that identifier. Use three distinct explanatory labels:
- `Shared identifier only`
- `Shared identifier + corroborated reports`
- `Shared identifier + independent risk evidence`

Do not use a shared-infrastructure label as a standalone red/green verdict. Keep linked seller cards individually investigable. Do not copy one seller's risk score to another.

## 3. Payment details comparison

Show a compact comparison table:

| Field | Expected | Receipt | Result |
|---|---|---|---|
| Amount | KSh … | KSh … | Match / Mismatch / Not checked |
| Recipient | … | … | Match / Mismatch / Not checked |
| Till/Paybill | masked | masked | Match / Mismatch / Not checked |
| Account reference | masked | masked | Match / Mismatch / Not checked |

Display this permanent explanatory line:

**This comparison checks the details you supplied. It does not authenticate the receipt or confirm that money reached the seller.**

On a mismatch, explain the exact field that differs and recommend stopping before sending additional money until the recipient is independently confirmed. Do not claim fraud solely from a mismatch: mistaken references and third-party payment arrangements can occur.

## 4. Case timeline

Show events newest-first, with source name, observation date, exact finding summary and evidence link. Distinguish:
- `Evidence observed`
- `Relationship observed`
- `Report submitted — pending review`
- `Report reviewed — unverified`
- `Report corroborated`
- `Report rejected`

Do not aggregate all community reports into one undifferentiated complaint count.

## 5. Verdict behaviour

Phase 3 does not invent a new fraud verdict. Feed only eligible, directly matched and properly sourced findings back into the Phase 2 evidence assessor. Relationship edges and shared-infrastructure observations default to contextual evidence. Pending reports never become verified risk items.

The result must keep the Phase 2 note that the evidence-weighted risk index is not a probability. A connection to a suspicious seller does not make the current seller suspicious by association.

## 6. Interaction and accessibility

- Keep cards collapsed by default to preserve the clean chat interface; show the strongest directly relevant connection first.
- Use text labels in addition to icons and colours.
- Keyboard focus must be visible; buttons must announce actions; tables need accessible headers.
- Provide `Report incorrect connection` / `Request correction` on relationship cards. This must create a moderation/correction case, not silently delete or rewrite the original source record.
- Provide `Investigate this connected entity` only where a user-visible identifier can be safely reintroduced from a currently authorized source. A pseudonymous node reference alone is not a valid investigation target.
