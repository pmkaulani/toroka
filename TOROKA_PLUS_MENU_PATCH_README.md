# Toroka Composer Plus Menu Patch

This patch adds a ChatGPT-style `+` action menu to the existing Toroka chat composer.

## What changes

- Replaces the permanently visible paperclip/camera/clipboard row with one plus button.
- Opens an accessible, keyboard-navigable menu with:
  - Photos and screenshots
  - Original email file (`.eml`, `.headers`, or validated raw-header `.txt`)
  - Paste from clipboard
  - Quick-start prompts for website/link, online-shop, and M-PESA/payment investigations
- Keeps all actions inside the existing conversation and composer.
- Automatically routes original email files and pasted raw email headers to `/v1/email/analyze`.
- Renders email-forensics findings inline as a normal assistant reply.
- Removes the separate "Investigate an email" composer button and the email modal.
- Keeps the existing logo, sidebar, welcome screen, composer layout, guest access, language support, evidence engine and email-forensics backend.

## Files

Replace these paths in the existing `smart-scam-identifier` project root:

- `services/api/app/static/index.html`
- `services/api/app/static/app.js`
- `services/api/app/static/styles.css`
- `services/api/app/static/i18n-chat.js`

Add:

- `services/api/tests/test_composer_actions_menu.py`

## Apply

1. Back up the project.
2. Extract this ZIP into the `smart-scam-identifier` project root, preserving folders and allowing the four listed static files to be replaced.
3. Do not replace `.env`, databases, evidence storage, encryption keys, HMAC keys or model data.
4. Restart the API/static server and hard-refresh the browser (Ctrl+Shift+R).

No database migration or API key is required. The patch uses Toroka's existing guest-accessible email-forensics endpoint and current image investigation endpoint.

## Validation performed

- 36 focused tests passed: new plus-menu contract tests, existing email-forensics tests and front-end static tests.
- `node --check` passed for `app.js` and `i18n-chat.js`.
- Python compilation passed for the API and email-forensics package.
- Playwright/browser visual interaction was not run in this environment.
