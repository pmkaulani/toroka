# Phase 4 API Contract

This is an integration contract for Toroka's existing backend, not a standalone public API server.

## `POST /v1/intelligence/content-analysis`

Purpose: add content-pattern, permitted threat-feed and campaign context to an existing investigation.

### Request

```json
{
  "case_id": "opaque-case-uuid",
  "extracted_text": "You have won a prize. Pay a processing fee.",
  "channel": "screenshot",
  "source_group": "whatsapp"
}
```

| Field | Type | Rules |
|---|---|---|
| `case_id` | string/UUID | Opaque random case ID; never a phone, email or person's name |
| `extracted_text` | string | Required, bounded to 20,000 characters; from existing text/OCR pipeline |
| `channel` | enum | `message`, `sms`, `whatsapp`, `instagram`, `facebook`, `tiktok`, `email`, `screenshot`, `webpage`, `call`, `unknown` |
| `source_group` | enum | `sms`, `whatsapp`, `instagram`, `facebook`, `tiktok`, `telegram`, `email`, `website`, `social_media`, `message`, `screenshot`, `call`, `user-submitted`, `unknown` |
| `moderation_state` | enum | Backend-only field; never trust the client to set `corroborated` |

### Response

The response is `Phase4Result.to_dict()` and contains:

- `case_ref`: pseudonymous case reference;
- `content_analysis`: language hint, detected patterns, redacted excerpts, domains and masked phone numbers;
- `threat_matches`: feed, indicator, confidence, source status, dates, attribution, reference link and limitations;
- `campaign_links`: pseudonymous related-case references, match basis, text similarity and moderation status;
- `recommended_actions`;
- `limitations`;
- `verdict_policy`: statement that Phase 4 does not issue the final seller verdict.

Never return HMAC secrets, raw campaign fingerprints, database paths, private identifiers or moderation account IDs.

## `POST /v1/intelligence/feedback`

Purpose: submit a user correction/report request for moderation. This is **not** a direct training API.

User-submitted fields should include only:
- opaque `case_id`;
- `claim_type`: `suspected_scam`, `looks_legitimate`, `incorrect_finding`, `report` or `other`;
- `training_opt_in`: explicit boolean, default `false`;
- structured feature fields from the allowlist, not free text.

The backend calls `FeedbackLedger.submit()`. The user cannot assign the supervised truth label. A moderator later calls `FeedbackLedger.review()` with an authorized role and a moderator-assigned label (`scam_confirmed`, `legitimate`, `inconclusive` or `false_positive`) only when approving the case. Rejected or needs-more-evidence cases do not receive a training label.

## Feed operations

- Provider registration is a backend startup/configuration action.
- Feed refresh is a worker/cron action; it must not be callable directly by an anonymous client.
- Refresh adapters must keep API keys private, validate schemas, cap payload sizes, observe rate limits and log only sanitized error types.
- The browser cannot select the provider, feed source, `verified` state or verdict polarity.

## Suggested FastAPI boundary

```python
from typing import Literal
from uuid import UUID
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter()

class ContentAnalysisRequest(BaseModel):
    case_id: UUID
    extracted_text: str = Field(min_length=1, max_length=20_000)
    channel: Literal["message", "sms", "whatsapp", "instagram", "facebook",
                     "tiktok", "email", "screenshot", "webpage", "call", "unknown"]
    source_group: Literal["sms", "whatsapp", "instagram", "facebook", "tiktok",
                          "telegram", "email", "website", "social_media", "message",
                          "screenshot", "call", "user-submitted", "unknown"]

@router.post("/v1/intelligence/content-analysis")
def content_analysis(payload: ContentAnalysisRequest):
    # Load the existing authorized case context; do not create duplicate cases blindly.
    result = phase4.investigate_content(
        case_id=str(payload.case_id),
        content=payload.extracted_text,
        channel=payload.channel,
        source_group=payload.source_group,
        moderation_state="pending",  # backend-controlled
    )
    return result.to_dict()
```

This route example omits the application's authentication/rate-limiting dependencies, error middleware, case ownership checks and structured logging. Add those before production. Preserve the no-account experience by using the existing anonymous case-session and abuse-control layer; do not require registration merely to call Phase 4.
