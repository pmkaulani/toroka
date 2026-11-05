# Toroka conversation response quality update

## Problem fixed
The local conversation responder previously recognised only a narrow set of identity questions (for example, `who are you` and `what can you do`). Natural questions such as `what do you do?`, `tell me everything about you`, `tell me more`, `i need more details`, and `that not enough` often fell through to a generic default response.

## Changes
- Added a truthful, product-specific explanation of Toroka's purpose and supported investigation types.
- Added progressive depth: first explanation, how investigations work, then full capabilities / limits / privacy explanation.
- Follow-up depth is activated only when recent user messages show that the conversation is about Toroka. An unrelated `tell me more` about a seller or case is not misrouted into the product explanation.
- Added an explicit account of evidence handling: user-supplied observations, source findings, risk inference and unknowns are distinguished.
- Clarified limits: screenshots do not prove payments; a business listing does not prove social-account ownership; unavailable providers are not represented as having run.
- Replaced the repetitive generic fallback with a brief, natural invitation to explain the user's actual question.
- Added equivalent English and Kiswahili responses.

## Files
- `services/api/app/ai_agent.py`
- `services/api/tests/test_conversation_about_toroka.py`

## Validation
The new conversation suite, existing investigation grounding suite and investigation quality suite passed together: **37 passed**. Python compilation passed. FastAPI emitted existing `on_event` deprecation warnings; no failures occurred in these targeted suites.

## Install
Copy the files in this patch into the matching paths in the Toroka project root. No database migration, API key or new package is required.
