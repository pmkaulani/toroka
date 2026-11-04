# Toroka Build 5 — Email Forensics & Sender Identity Intelligence

## Delivered

- Local-first RFC 5322 / MIME parser using Python's standard email package.
- Guest-accessible `POST /v1/email/analyze` endpoint and chat-composer modal.
- Original `.eml`, `.txt`, `.headers` and pasted full-message/header input; 5 MiB limit.
- Sender identity comparison for `From`, `Sender`, `Reply-To`, `Return-Path` and Message-ID domain.
- Trusted vs untrusted `Authentication-Results` handling. Results are untrusted by default; a configured authserv ID is only trusted when it also matches the newest `Received` hop.
- DKIM signature metadata, selector and signer-domain alignment observations.
- Optional, user-consented DNS posture checks and optional local cryptographic DKIM verification through open-source `dkimpy`.
- Display-name and sender-local-part brand impersonation indicators; internationalized/Punycode hostname indicators.
- HTML link destination mismatch and active-link-scheme checks. Links are not fetched.
- Attachment metadata, SHA-256 and potentially active file-type warnings. Attachments are not opened, executed or extracted.
- English and Kiswahili UI labels.
- Rate limiting, no raw-message persistence, no raw-message logging, no raw body returned.

## Integration points

- `services/api/toroka_email_forensics/analyzer.py`
- `services/api/app/routes_email.py`
- `services/api/app/main.py`
- `services/api/app/config.py`
- `services/api/app/static/index.html`
- `services/api/app/static/app.js`
- `services/api/app/static/i18n-chat.js`
- `services/api/app/static/styles.css`
- `services/api/tests/test_email_forensics.py`

## API

`POST /v1/email/analyze` (`multipart/form-data`)

- `file`: one `.eml`, `.txt` or `.headers` file; alternatively
- `raw_email`: full raw message or header block
- `allow_dns_checks`: optional boolean, default false

Exactly one of `file` or `raw_email` is required. No authentication account is required; the endpoint is guest-accessible and rate limited. It does not save an email case or its raw content.

## Authentication correctness

- An uploaded `Authentication-Results` header is not trusted just because it names `mx.google.com`, Outlook or another provider.
- Set `EMAIL_TRUSTED_AUTHSERV_IDS` to a comma-separated list of exact authserv IDs only after confirming the receiving provider and its newest `Received` hop.
- A screenshot/forwarded email cannot reliably prove the original authentication outcome.
- SPF cannot be recalculated with confidence from an arbitrary uploaded message; sender-controlled routing lines are not trusted as an origin-IP source.
- A valid DKIM signature is evidence of a signing-domain signature, not proof that the sender's account is uncompromised or that content is safe.

## Dependencies and external calls

- No API key, credit card or paid email-scanning service is required.
- `dkimpy>=1.1.8` is included in `requirements.txt`; it is BSD-like licensed and resolves public DKIM keys using DNS.
- External DNS is disabled unless the user checks the consent box for a particular analysis. This sends DNS name/selector queries only, never the message body or attachments.
- The supported Makefile and Docker installation paths use `pip install -r requirements.txt`, which installs `dkimpy`. If you install from `pyproject.toml`/`uv.lock` alone, DKIM cryptographic verification remains optional and will report `dependency_not_installed` until you separately install `dkimpy>=1.1.8`. No lockfile change is required for the core parser or API.

## Verification

- Email Forensics focused suite: 22 passed.
- Python compilation: passed.
- `node --check` for `app.js` and `i18n-chat.js`: passed.
- API routes tested for guest access, `.eml` upload, pasted raw email, dual-input rejection, binary `.msg` rejection and size limit.
- Live DNS/DKIM checks were not run; tests are deterministic and do not send real messages or external DNS queries.

## Limitations

- Outlook `.msg` binary format is not supported; export as `.eml`.
- SPF is not independently recalculated from untrusted uploaded headers.
- DKIM crypto verification requires the optional runtime library to be installed and a user opt-in to DNS checks.
- ARC headers are detected but ARC chain verification is not implemented.
- No attachment malware sandboxing or archive extraction is implemented.
- This feature does not connect to a user's mailbox or read email accounts. The user must submit an exported original message or headers.
