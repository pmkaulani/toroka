# Toroka Phase 7 — UI Contract

Phase 7 should strengthen the existing Toroka experience without replacing its chat-first interface, logo, typography system or established visual language.

## User-facing investigation

### A. Language signals

Show a compact section such as **Message patterns detected** with language label (English / Kiswahili / Sheng), category, short redacted evidence excerpt and an explanation. Label it `Pattern signal`, not `scam verdict`. Provide a small note that rule-based language matching can miss slang, code-switching and context.

### B. Threat-intelligence match

When a current feed indicator is relevant, display:
- provider/source attribution only when the licence allows display;
- indicator type (domain, URL, IP or file hash), not secret feed fields;
- `Last checked` / observation date and expiry/freshness status;
- source link only when permitted;
- a short distinction between active, expired, stale and unverified data.

If a source permits internal checking only, say `Threat-intelligence match found` without exposing source-specific restricted fields or references. Do not label a seller as a scam solely because an indicator matches a shared domain/phone.

### C. Memory and corrections

Only show reviewed, unexpired corroborated indicators. Show the number of independent source families and last reviewed date, with a clear warning that a shared identifier does not establish common ownership. Provide `Report an error` / `Request correction` for any displayed memory result. Never expose pending reports, reporter identities or moderator notes.

### D. Kenyan advisory context

Display official KE-CIRT/CC material as **National cybersecurity context**, with authority, publication date, retrieval date and link. Do not imply that a general advisory identifies the seller under investigation.

## Operator-only interface

A separate admin/operations view may show:
- feed status: disabled, never succeeded, healthy, degraded, stale or circuit open;
- last attempt, last success, next attempt, retry state and approximate cached count;
- provider terms-review date and permission scopes;
- open operational alerts and acknowledgement state;
- aggregate metrics and system readiness controls.

Do not surface API keys, internal credentials, raw user content, HMAC secrets or personal identifiers. Keep operations screens out of ordinary chat results.

## Verdict hierarchy

1. The existing Phase 2 evidence assessor remains authoritative.
2. Phase 5 combines provenance-aware evidence and prevents duplicate counting.
3. Phase 3 graph edges and Phase 7 memory remain contextual evidence.
4. Phase 7 language heuristics are signals only.
5. No Phase 7 status, advisory, memory link or alert automatically changes a seller verdict.

## Accessibility and interaction

Maintain readable contrast, keyboard navigation, labelled status text (not color alone), expandable evidence details and responsive cards. Keep the main chat composer visible and avoid interruptive full-screen admin controls for ordinary users. Provide clear empty, loading, stale, restricted-source and provider-unavailable states.
