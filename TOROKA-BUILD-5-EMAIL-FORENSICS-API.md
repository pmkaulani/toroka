# Email Forensics API Contract

## `POST /v1/email/analyze`

Content type: `multipart/form-data`. Guest-accessible, rate limited to 10 requests per client per hour.

Exactly one input is required:

- `file`: `.eml`, `.txt` or `.headers`; 5 MiB maximum.
- `raw_email`: pasted full RFC 5322 message or raw header block.

Optional:

- `allow_dns_checks`: boolean, default `false`. When true, Toroka performs DNS posture lookups and attempts DKIM signature verification. Only domain and DKIM selector queries are sent; raw message data is not transmitted to DNS resolvers.

Response includes:

- `attention_level` and explanatory `summary` (not a safety guarantee).
- `sender_identity` (`From`, `Sender`, `Reply-To`, Return-Path domain and Message-ID domain).
- `authentication` (trusted receiver results, untrusted claims, DKIM metadata/verification and DNS posture).
- `routing` (bounded Received-hop summaries).
- `links` (destination host/domain and warning codes; no full URL paths or query strings).
- `attachments` (filename, MIME type, size and SHA-256; no content).
- `findings` and `limitations`.
- `privacy` fields confirming the raw email was not stored or returned.

## Trust rules

Authentication-Results is untrusted unless its authserv-id is explicitly configured in `EMAIL_TRUSTED_AUTHSERV_IDS` and matches the newest `Received` hop. The default allow-list is empty.

No SPF result is independently computed from arbitrary uploaded message headers. Receiver-generated Authentication-Results may be shown as trusted only under the configured trust rule. DKIM signature presence is not the same as cryptographic verification. DKIM verification requires the user to opt into DNS checks and `dkimpy` to be installed.

## Errors

- `413`: message exceeds 5 MiB.
- `415`: unsupported file type/binary `.msg`.
- `422`: empty, dual input, malformed or unsupported input.
- `429`: rate limit exceeded.
