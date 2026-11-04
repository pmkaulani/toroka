# Build 5 Integration Guide

1. Back up the current project and `.env`.
2. Apply the Build 5 project or source patch, preserving `.env`, database files, evidence storage and encryption/HMAC keys.
3. Install dependencies using `pip install -r requirements.txt`. This includes `dkimpy` for optional local cryptographic DKIM checks. No API key or credit card is required.
4. Optionally configure trusted receiving-server IDs in `.env`, for example `EMAIL_TRUSTED_AUTHSERV_IDS=mx.google.com`, only after verifying the authserv ID and matching newest Received hop from original messages. Leave empty otherwise.
5. Restart Toroka. No database migration is required.
6. Open **Investigate an email** from the chat composer.
7. Upload an original `.eml` (preferred) or paste full original headers. A forwarded copy or screenshot loses forensic evidence.
8. Leave DNS checks disabled for offline/local parsing. If enabled, user consent is explicit and only sender-domain/DKIM-selector DNS queries occur.
9. Review the returned findings and limitations. Never describe a DMARC/DKIM/SPF pass as proof that an email or mailbox is safe.

## No-key path

Header parsing, identity consistency, routing summaries, suspicious-link analysis, MIME/attachment metadata, local hash calculation and basic domain-claim indicators work without any third-party API key or network request.

## Local validation

```bash
PYTHONPATH=packages/rules:packages/connectors:services/api pytest -q services/api/tests/test_email_forensics.py
node --check services/api/app/static/app.js
node --check services/api/app/static/i18n-chat.js
python -m compileall -q services/api/app services/api/toroka_email_forensics
```

## Privacy

The endpoint does not store raw message content, does not log message bodies, does not return message bodies, and does not open links or attachments. DNS lookups are user-opt-in and disclose domain/selector names to the configured DNS resolver.
