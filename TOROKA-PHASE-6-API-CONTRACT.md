# Phase 6 API Contract

Suggested host route: `POST /v1/investigations/{case_ref}/phase6`

This is a host-application contract, not a live route shipped by the core package. Mount it into Toroka's existing backend; do not create a new standalone app.

## Request ownership

The browser may supply an opaque artifact reference and user-submitted claim. The backend must supply all trusted source labels, collection modes derived from actual provider authorization, verified BRS source types, C2PA validation status, transcription provider name, speaker review state and passive website snapshot.

Example normalized server payload:

```json
{
  "case_ref": "toroka_case_0001",
  "website_snapshot": {
    "tls_certificate_valid": true,
    "tls_hostname_match": true,
    "tls_days_remaining": 82,
    "domain_age_days": 46,
    "redirect_hosts": ["seller.example", "checkout.example"],
    "security_headers": {"strict-transport-security": "max-age=31536000"}
  },
  "social_observations": [
    {
      "artifact_ref": "social_case_001",
      "collection_mode": "platform_authorized_api",
      "profile_url": "https://www.tiktok.com/@sample_shop",
      "observed_at": "2026-11-04T08:30:00Z",
      "public_fields": {"display_name": "Sample Shop", "is_platform_verified": false}
    }
  ],
  "image_artifacts": [
    {
      "artifact_ref": "image_case_001",
      "bytes": "<server-side byte buffer, not JSON text>",
      "grayscale_8x9": "<8x9 matrix from isolated image processor>",
      "known_fingerprints": [],
      "c2pa_status": "not_checked"
    }
  ],
  "audio_transcripts": [
    {
      "artifact_ref": "audio_case_001",
      "transcript": "<server-side transcript; do not log or return>",
      "consent_confirmed": true,
      "provider": "approved-transcription-provider",
      "speaker_role": "unknown",
      "speaker_role_reviewed": false
    }
  ],
  "business_checks": [
    {
      "artifact_ref": "business_case_001",
      "claim": {"business_name": "Sample Shop", "registration_number": "CPR/0001"},
      "record": {"source_type": "user_uploaded_registry_document", "registered_name": "Sample Shop"}
    }
  ]
}
```

The `bytes` field represents an internal buffer; in a real route use multipart upload and server-side storage/worker references. Never ask the browser to submit binary bytes as a string or to set official source labels.

## Response

`Phase6Result.to_dict()` returns:

- `case_ref`, `phase`, bounded `findings`, `sections`, `next_steps`, `limitations`;
- `raw_uploads_stored: false` and an explicit `verdict_policy`.

A finding contains: `ref`, `source_group`, `category`, `severity`, `polarity`, `summary`, `explanation`, `confidence`, bounded `excerpt`, `observed_at`, `limitations`.

## Error handling

- `400`: invalid URL/profile/source field, invalid coordinate or malformed evidence schema.
- `401/403`: no current session, missing user consent, unauthorized moderation/provider operation.
- `413`: upload or transcript over configured limit.
- `422`: invalid/missing speaker attribution or malformed record.
- `429`: rate limit exceeded.
- `503`: external provider or isolated processing worker unavailable.

A provider error is `unavailable`, never a clean result. Do not include provider credentials, raw content or URLs containing user tokens in the error body.

## Security requirements

- Authenticate the case/session and authorize access before returning case evidence.
- Set source-group/source-type/collection-mode labels server-side.
- Apply server upload validation and malware scanning.
- Run website fetches in a restricted worker with connection-time DNS pinning and redirect validation.
- Enforce strict request/response size limits, timeouts, rate limits and per-session quotas.
- Do not place raw artifacts, user contact details, OTPs, payment references, transcript text or query-string tokens in logs.
