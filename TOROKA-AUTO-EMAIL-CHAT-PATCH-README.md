# Toroka — Automatic Email Recognition in Chat

This patch removes the standalone **Investigate an email** composer button and its modal. Email forensics now behaves as part of Toroka's normal chat.

## What changes

- The normal attachment picker accepts images plus original `.eml` / `.headers` files. `.txt` files are accepted as email sources only when their contents look like raw email headers.
- Pasted structured raw headers (for example `From`, `Subject`, `To`, and/or `Received`) are detected when the user presses Send.
- The normal chat submit action automatically calls the existing `POST /v1/email/analyze` endpoint for original email sources.
- Email findings render inside the conversation as a normal Toroka reply. No email-mode button or popup is shown.
- Screenshots and ordinary pasted email text continue through the existing chat investigation path; screenshots alone cannot establish SPF, DKIM or DMARC results.
- Raw email headers are not echoed into the visible user chat bubble. The UI shows a short attachment/source label instead.
- The service-worker cache key is bumped so installed clients refresh the changed chat assets.
- English and Kiswahili attachment labels and validation messages are updated.

## Apply

1. Back up the current project.
2. Extract this ZIP into the `smart-scam-identifier` project root, preserving the directory paths. Allow the listed files to be replaced.
3. No database migration or API-key configuration is required.
4. Restart/redeploy Toroka. The service-worker cache name has been bumped to refresh the app shell.
5. Test by attaching an original `.eml` with the normal paperclip, or paste several raw email headers into the ordinary composer and press Send.

## Validation performed

- Email forensics endpoint + chat integration contract: 27 tests passed.
- Python compilation: passed.
- JavaScript syntax checks: passed for app.js, i18n-chat.js, sw.js and the Playwright browser test.
- CSS parsed with tinycss2: 0 top-level parse errors.
- Confirmed there are no remaining `email-forensics-open`, `email-forensics-dialog`, `email-tool-entry`, `email-tool-button`, or `initEmailForensics` references in the live static UI.
- The Playwright browser test was added but not executed in this environment because its npm dependencies are not installed.

## Important

This patch changes UI routing only. It keeps the existing local-first email forensic parser and `POST /v1/email/analyze` endpoint. It does not connect to or read a user's mailbox. The user still submits an exported original email or its source text.
