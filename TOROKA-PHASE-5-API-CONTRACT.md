# Toroka Phase 5 — API Contract

## Endpoint proposal

`POST /v1/investigations/{case_ref}/multimodal-analysis`

This is an integration contract, not a running web server. The host application must implement authentication/session checks, upload validation, OCR extraction, authorization and request logging controls.

## Browser request (conceptual)

The browser submits an existing upload reference, a chat transcript reference or user-entered expected payment values. It must not be allowed to set trusted `source_group` values, moderator labels, model versions or provider status.

```json
{
  "artifact_refs": ["receipt_case_001", "chat_case_001"],
  "expected_payment": {
    "amount": "1500.00",
    "recipient_identifier": "123456"
  },
  "include_conversation_timeline": true
}
```

## Server-side normalized input

```python
ArtifactInput(
    artifact_ref="receipt_case_001",
    artifact_type="mpesa_receipt_ocr",
    extracted_text=existing_ocr_text,
    source_group="user_receipt",  # set by backend from provenance
    language="en",
)
```

Phase 4 payloads must be wrapped with the exact `artifact_ref` they analyzed. The orchestrator discards mismatched references.

## Response shape

```json
{
  "case_ref": "toroka_case_0001",
  "indicator_band": "review_recommended",
  "evidence_strength": "single_or_limited_source_families",
  "independent_source_groups": 1,
  "evidence_count": 1,
  "signals": [],
  "artifact_summaries": [],
  "model_shadow": null,
  "recommended_actions": [],
  "limitations": [],
  "raw_artifact_content_stored": false,
  "verdict_policy": "Phase 5 fuses explainable indicators; it does not independently prove seller identity, payment settlement or criminal conduct."
}
```

## Enumerations

`indicator_band`: `insufficient_evidence | limited_signals | review_recommended | elevated_signals`

`severity`: `critical | high | medium | low | context`

`polarity`: `risk | context | reassuring`

`model_shadow.status`: `completed | invalid_model_response | unavailable`

## Security requirements

- Server-generated opaque IDs only; reject names, phone numbers, emails and URLs as references.
- Set provenance on the server. Never trust user-supplied `official_record`, `payment_provider_response`, `threat_feed` or `moderator_review` labels.
- Do not log OCR text, screenshots, receipt references, OTPs, PINs, phone numbers or model payloads.
- Treat extracted webpage/image text as hostile untrusted input; never convert it to tool commands or system instructions.
- Validate request/file sizes and timeouts. Enforce authorization on the referenced uploads.
- Return only masked excerpts and identifiers.
- Keep the existing Phase 2 assessor as owner of the customer-facing verdict.
