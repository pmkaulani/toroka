# Toroka Phase 4 — Chat UI Contract

Phase 4 enriches Toroka's existing ChatGPT-like investigation response. It must not replace the current logo, chat composer, no-account flow, language toggle or conversation layout. Do not introduce a large dashboard as the primary user experience.

## 1. Message analysis card

Use a collapsible section titled **Message signals** / **Dalili kwenye ujumbe**.

Each signal row contains:
- human-readable category;
- severity text (`Critical`, `High`, `Medium`, `Context`), not colour alone;
- a short, redacted excerpt showing the phrase that matched;
- why the phrase matters;
- what the phrase match cannot establish;
- a next action.

Show risk-bearing signals before context signals. Never turn a context-only brand mention or payment instruction into a warning badge. A government/SHA/KRA/HELB/Safaricom name appearing in text is not proof of impersonation.

## 2. Threat intelligence card

Show **Threat intelligence** only when a relevant feed check returned a match or a check was unavailable/stale and that limitation matters.

Display:
- feed/provider name and attribution required by the provider;
- exact indicator type and safely rendered host/domain;
- source record link where provider terms allow display;
- feed observation/update time and status (`Active match`, `Expired record`, `Feed not fresh`);
- a plain-language note that a match applies to that domain/indicator, not automatically to a person, shop or separate social profile.

A no-match result must say **No matching record was found in the sources checked**. It must never say **Verified safe**.

Do not display data from a provider policy marked `display_allowed=false`. Do not publicly submit URLs containing user data, invitation links, password resets, account tokens or M-PESA transaction references.

## 3. Related investigations

Use a collapsed **Related activity** section when campaign links exist.

For each link show:
- a pseudonymous investigation reference;
- the reason for the similarity (shared domain, shared phone, similar message template);
- similarity as a matching descriptor, not fraud probability;
- moderation state of the related report;
- a permanent caveat: **This is a similarity lead, not proof that the same person operates both accounts.**

Never show historical raw phone numbers, payment numbers, emails or private handles from the campaign store. The current user-submitted value can be masked in the current case only.

Pending or rejected reports must never be presented as corroborated activity. Do not aggregate them into a single complaint count.

## 4. Learning and corrections

Add two separate controls:
- **Report an incorrect finding** — creates a moderation/correction request.
- **Allow this case to help improve Toroka** — separate optional consent, unchecked by default, with a short explanation of what features will be retained and how long.

Do not imply that pressing a report button immediately changes a seller's reputation or trains the AI. The UI should explain that reviewed cases may inform future system evaluation; no instant self-training occurs.

## 5. Bilingual language and accessibility

Maintain English and Swahili support. All signal names, severity text, caveats and safety actions must have reviewed translations. Do not machine-translate critical safety language at request time without review.

Use text labels with icons and colour. Provide keyboard focus, accessible button names, screen-reader summaries and responsive cards. Keep evidence details collapsed by default so the chat remains familiar and usable on mobile.

## 6. Verdict and safety consistency

Phase 4 does not issue its own verdict. The final conclusion still comes from Phase 2's evidence assessment plus the full investigation context. Phase 4 contributes:
- directly matched, fresh, policy-permitted external threat evidence;
- transparent phrase-pattern findings with low/moderate evidential weight;
- campaign similarity as context only;
- unavailable/stale checks as limitations.

Retain the note that the risk index is an evidence-weighted signal index, not a probability. Keep **Inconclusive** available whenever source coverage or identity matching is insufficient.
