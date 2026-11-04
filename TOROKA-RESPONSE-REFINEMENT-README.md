# Toroka response and investigation-status refinement

This is a narrowly scoped source patch for the Toroka Build 5 project.

## Scope

This patch changes only:
- `services/api/app/static/app.js`
- `services/api/app/static/i18n-chat.js`
- `services/api/app/static/i18n.js`
- `services/api/app/static/styles.css`
- `services/api/app/ai_agent.py`

It does **not** change the Toroka logo, welcome/home layout, sidebar, composer layout, page structure, database schema, API credentials, or investigation providers.

## Apply

1. Back up your current Toroka project.
2. Extract this ZIP into the existing project root, preserving folder paths and allowing these five files to be replaced.
3. Restart the API service and hard-refresh the browser (Ctrl+F5).
4. Run the focused tests listed in the handoff report.

Do not replace `.env`, databases, evidence storage, encryption keys, HMAC keys, ML model files, or other runtime data with anything from this patch; none are included.

## Behaviour changes

- Investigation progress messages are contextual (email, web/social, image, payment, or general checks), typed in sequence, and do not cycle endlessly.
- If an investigation takes longer, the user sees a calm waiting message rather than repeated or misleading activity claims.
- Progress announcements remain accessible to assistive technology and respect reduced-motion preferences.
- Assistant responses stream by paragraph/list block, preserving headings, bullets, bold text, and safe HTTP(S) source links.
- Investigation answers lead with the conclusion, surface a small set of strongest findings, then present next steps, limitations, and public search leads/sources.
- English and Kiswahili status labels are included; Swahili copy should receive native-speaker review before public launch.

No API keys are required for these changes.
