# Phase 6 UI Contract — Toroka

## Preserve the existing product

- Keep the authentic Toroka logo unchanged.
- Keep the existing familiar chat-first interaction and no-account entry path.
- Preserve English/Kiswahili language controls and the current mobile-first layout.
- Do not replace the conversation with an analytics dashboard or force the user to understand technical forensics.
- Add Phase 6 as expandable evidence inside an investigation response.

## Investigation response layout

1. **Investigation summary:** existing Phase 2 verdict and explanation remain in charge.
2. **What Toroka checked:** concise checklist of completed, unavailable and skipped checks.
3. **Advanced evidence:** collapsible sections for Website, Social profile, Images, Call transcript and Business/location.
4. **Recommended next action:** clear safe action based on the user's case, not a generic risk score.
5. **Source and limitations:** every item shows collection method, date/time, source label and what it cannot prove.

## Cards

### Website forensics
Show normalized hostname, scan timestamp, certificate result, redirect summary, domain-registration age if available and missing security headers. Do not show token-bearing pasted paths or query parameters. Label domain age and header gaps as context, not scam indicators. Do not imply a website is safe because TLS is valid.

### Social profile
Show platform icon/name, sanitized handle, canonical profile link, display name, authorized observation method and last-checked time. A badge gets the label `Platform badge observed`, not `Business verified`. User screenshot evidence must be labelled `User-provided screenshot`.

### Image reuse
Show `Exact file match`, `Visually similar`, `Possible similarity` or `No match found`. Where a result is available, show a thumbnail only if the image is permitted to display and the user has access. Add the similarity distance and a note that suppliers and catalogue images can be shared legitimately. Never show `stolen image` based only on a perceptual hash.

### Content Credentials
Use `Credentials validated`, `Validation failed`, `Not present`, `Not checked` or `Unavailable`. A validated credential describes a signed media history; it does not certify the factual truth of the image. Absence must never render an `AI-generated` badge.

### Call / audio transcript
Show only language categories such as `OTP/PIN request`, `Remote-access request`, `Urgent payment` and `Impersonation language`. Show `Speaker attribution reviewed` or `Speaker unknown`. Unknown attribution must display as context. Do not show caller identity, voiceprint, or deepfake certainty.

### Business and location
Clearly distinguish:
- `Official BRS search checked` — only when the backend has verified an official source.
- `User-provided document — not independently checked`.
- `Map listing candidate — not registry verification`.
- `Seller-provided claim — not independently checked`.

If map and claimed coordinates differ, show approximate distance and a neutral `Address discrepancy to clarify` label. Never show a map candidate as a registered office or infer account ownership from a matching business name.

## Copy tone

Prefer clear, action-oriented language:
- “The public profile was observed, but this does not establish who controls it.”
- “This image resembles another product photo. Sellers can legitimately share supplier catalogue images.”
- “The listed location differs from the location provided by the seller. Confirm the exact premises.”
- “The transcript contains a request for a PIN. Toroka cannot identify the speaker from this transcript alone.”

Avoid sensational labels such as `confirmed scammer`, `criminal network`, `deepfake caller`, or `stolen product image` unless a competent authority or verified source actually establishes those facts and the claim is relevant.

## Interaction details

- Each card can expand to reveal source, date, extraction/provider method, confidence and limitations.
- Provide a correction/report action where a business owner can dispute incorrect public details.
- Provide a `How to verify` action to BRS/eCitizen or a platform's official page when no authorized API exists.
- Provide `Delete this upload` or the app's existing case deletion control.
- On mobile, collapse technical details by default; no pop-up should block the ongoing chat.
