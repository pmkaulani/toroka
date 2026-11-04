# Toroka Build 5 — Email Forensics Changelog

## Added
- Original RFC 5322/MIME email analysis from `.eml`, `.txt`, `.headers`, or pasted raw headers.
- Sender identity comparisons across `From`, `Sender`, `Reply-To`, `Return-Path`, and Message-ID domains.
- Trusted/untrusted `Authentication-Results` handling based on configured authserv IDs and the newest `Received` hop.
- DKIM signature metadata and optional local cryptographic verification with `dkimpy`.
- Optional consent-based DNS posture checks for SPF/DMARC records and DKIM keys.
- Brand impersonation, internationalized-domain, suspicious URL, display/target mismatch, and active-link-scheme observations.
- Metadata-only attachment inspection and SHA-256 fingerprints; no attachment execution or extraction.
- Guest-compatible `POST /v1/email/analyze` API and chat interface entry point.
- English and Kiswahili interface copy.

## Safety and privacy
- 5 MiB message limit, MIME-part and link limits, and endpoint rate limiting.
- Raw message content is not persisted, logged, or returned.
- Links are not fetched and attachments are not opened.
- Authentication results are untrusted unless the receiving authserv ID is explicitly configured and matches the newest trusted route hop.
- DNS queries require explicit user opt-in; no message body or attachment is transmitted to DNS resolvers.

## Verification
- Email Forensics focused tests: 22 passed.
- JavaScript syntax checks: passed.
- Python compilation: passed.
- Full project test run reached 92% but did not exit before the command timeout; no full-suite pass is claimed.
