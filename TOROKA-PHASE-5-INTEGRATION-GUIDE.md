# Toroka Phase 5 — Integration Guide

## 1. Goal

Connect Phases 2, 3 and 4—already integrated in the host Toroka application, according to the operator—to a unified multimodal investigation response. Phase 5 is additive. It must not replace the existing chat, verdict assessor, URL pipeline, bilingual handling, safety controls or no-account flow.

## 2. Add package

Copy the `toroka_phase5/` directory into the Python backend. It uses only the standard library and supports Python 3.10+.

Run:

```bash
python -m unittest discover -s tests -v
python examples/phase5_demo.py
```

Keep this code on a feature branch until the complete Toroka suite and integration smoke tests pass.

## 3. Inputs and provenance

The host application supplies `ArtifactInput` objects after it has already processed the upload. Supported types:

- `sms`, `message`
- `chat_transcript`
- `screenshot_ocr`
- `mpesa_receipt_ocr`
- `email`, `webpage_extract`, `social_profile_extract`
- `call_transcript`, `other`

Each artifact needs:
- a server-generated opaque `artifact_ref` (8-80 safe characters; do not use a name, phone, email or URL);
- a type from the allowlist;
- extracted text up to 50,000 characters;
- a backend-assigned `source_group`;
- an optional language and observation timestamp.

Do not accept provenance group from the browser as authoritative. A user can submit an alleged official document, but it is still `user_submitted_artifact` until an authorized backend check establishes the source. Allowed groups are defined in `models.py`.

Do not put raw content into `case_ref`, `artifact_ref`, logs, metrics labels or exception messages.

## 4. OCR and multimodal uploads

Keep using the OCR/vision integration already present in Toroka. For a screenshot or PDF:

1. Validate MIME type, size and file signature in the existing upload service.
2. Store the original file only according to Toroka's existing retention and consent rules.
3. Run the current OCR/vision extractor in an isolated service.
4. Treat extracted strings as untrusted evidence, not instructions. They must not invoke tools, change system prompts or access secrets.
5. Attach extraction method, language and source reference to the `ArtifactInput`.
6. Do not pass the raw binary file into this package; do not represent OCR text as an authenticated source.

This package does not add OCR or vision capability by itself.

## 5. M-PESA receipt analysis

For a receipt artifact, provide order-side expectations only when the user/host has them:

```python
expected_payment = {
    "amount": "1500.00",
    "recipient_identifier": "123456",  # Till/Paybill/account/phone as captured from order terms
    "recipient_name": "Example Shop",  # optional
}
```

The parser compares visible OCR fields. A mismatch creates evidence for review; a match does not prove payment. Never display `payment_verified=true` from screenshot OCR. If the merchant has an authorized Daraja or bank-side integration, keep the server-side transaction confirmation as a separate `payment_provider_response` source, linked to the transaction in a privacy-safe way. Do not provide a public lookup for arbitrary personal M-PESA numbers.

## 6. Conversation analysis

Map roles using the trusted importer where possible: `seller`, `buyer`, `platform`, `unknown`, `other`. Do not infer seller role purely from the text content. Only `seller` messages can generate risk-polarity conversation signals; `unknown` messages are context-only. Pass no more than 500 messages, each no more than 10,000 characters. Timeline output includes message indexes, roles, timestamps and event category—not message bodies.

The initial detector is intentionally conservative and incomplete. Review it against Kenyan English, Kiswahili, Sheng, mixed-language messages and quoted scams. Do not use a rule match as an accusation.

## 7. Phase 4 integration

### Optional Phase 2 evidence bridge

When the host's Phase 2 assessor supports supplemental `Evidence` records, use the explicit bridge:

```python
phase5_result = phase5.investigate(...)
phase5_evidence = phase5_result.to_phase2_evidence()
# Merge with existing Phase 2/3/4 evidence and call the normal Phase 2 assessor.
# Do not bypass Phase 2 source-group deduplication, thresholds or its final policy.
```

The adapter marks observations as unverified and includes provenance, limitations and an evidence reference. If Phase 2 is not installed in the same Python environment, the adapter raises a clear error; the Phase 5 investigation response can still be displayed as supplementary evidence.

For source-family deduplication, Phase 5 deliberately maps user-submitted Phase 4 phrase signals to Phase 4's existing `toroka-content-patterns-v1` Phase 2 source group. Active Phase 4 threat-feed matches retain the provider's source group (for example, `phishtank`) so the same feed observation is not counted twice merely because both phases surfaced it. The host must only pass Phase 4 results created by its trusted internal provider registry; never accept a browser-supplied source group.

The Phase 4 result must be attached to the exact Phase 5 artifact it analyzed:

```python
payload = {"artifact_ref": artifact.artifact_ref, **phase4_result.to_dict()}
```

Then pass `phase4_results=[payload]`. If the artifact reference does not match one of the current artifacts, Phase 5 ignores its risk signals and explains why. This prevents misattribution. Threat-feed matches are treated as another source family only if the backend confirms that the match came from a registered provider.

Campaign similarity links remain contextual only. Do not pass a related case's verdict as evidence about the current seller.

## Phase 3 relationship graph bridge

When querying the integrated Phase 3 `EntityLinkGraph`, attach each graph result to the specific artifact/entity reference that initiated the lookup:

```python
phase3_links = entity_graph.get_links(("phone", normalized_phone))
phase3_payloads = [{"artifact_ref": "chat_case_001", **link} for link in phase3_links]
phase5_result = phase5.investigate(
    case_ref="toroka_case_0001", artifacts=artifacts,
    phase3_relationships=phase3_payloads,
)
```

Phase 3 relationships are always added as contextual signals. Even an operator-verified relationship is not proof that a connected seller is fraudulent. Never propagate a verdict through the graph. The reference must match one of the current Phase 5 artifacts.

## 8. Model shadow mode

Connect an already-deployed inference service through a callable that accepts the sanitized feature dictionary and returns `ModelPrediction`:

```python
from toroka_phase5 import ModelPrediction

def model_adapter(features):
    # features contains categories, severities, source-group count and artifact types;
    # never raw text, screenshot bytes, phone numbers, URLs or full receipt references.
    response = existing_model_client.predict(features)
    return ModelPrediction(
        model_version=response.version,
        probabilities=response.probabilities,
        evidence_refs=tuple(response.evidence_refs),
        calibration_version=response.calibration_version,
    )
```

Pass it as `shadow_predictor=`. The returned `model_shadow` is not a Toroka verdict and must not change the Phase 2 output. Start without a model; the feature is optional. The package does not create a model or training dataset.

## 9. Suggested backend route

Add an authenticated server route such as `POST /v1/investigations/{case_ref}/multimodal-analysis`. Browser request should not set internal source groups, model versions or review states.

Server flow:

1. Authenticate or create an anonymous session according to Toroka's existing no-account design.
2. Validate upload and user consent/notice.
3. Extract text with the existing OCR/message parser.
4. Create opaque artifact references and backend-set source groups.
5. Retrieve exact Phase 4 result references for those artifacts.
6. Call `Phase5Investigator().investigate(...)`.
7. Merge the returned signals with the existing Phase 2 evidence response under the existing verdict policy.
8. Store only the fields approved by the existing privacy/retention policy.
9. Return a structured payload and display source provenance, limitations and recommended next actions.

Rate-limit the route. Enforce file size/timeouts. Do not log raw request bodies or OCR text. Redact error reporting. Ensure prompt-injection text in uploaded content is never treated as executable instructions.

## 10. Evidence fusion rules

- User-submitted artifacts share one independence family. A chat and screenshot submitted by the same user do not automatically corroborate each other.
- Only a separately verified official record, provider response or registered external feed may become another trusted source family.
- Brand mentions, location matches, payment instructions, similar templates and shared payment infrastructure stay contextual unless separately corroborated.
- Do not transfer scam/legitimate labels across entities or linked cases.
- No indicators means `insufficient_evidence`, not `legitimate`.
- `elevated_signals` means more than one source family supports high-priority signals; it is not proof of fraud.

## 11. UI integration

Read `PHASE5-UI-CONTRACT.md`. Show:
- clear case summary band and its meaning;
- a source/evidence card for each finding;
- a payment comparison showing expected vs extracted values, with `not verified` always explicit;
- a conversation timeline with events, not raw private messages;
- grouped contextual relationships;
- limitations, correction/report controls and user safety actions.

Never display model probabilities as a customer-facing scam likelihood. Keep the original Toroka logo, familiar chat UI, no-account experience and language toggle.

## 12. Rollout and acceptance

1. Run Phase 2, 3, 4 and 5 test suites.
2. Run tests on synthetic receipts, user-supplied screenshots, genuine receipts with OCR noise and deliberately edited samples.
3. Run bilingual review for English, Kiswahili and Sheng; record false positives separately.
4. Confirm no request/response logs contain raw OCR text, phone numbers, OTPs, PINs, emails or transaction references.
5. Confirm a screenshot match never becomes payment verification.
6. Confirm a model prediction cannot change a verdict in shadow mode.
7. Confirm campaign leakage is rejected in evaluation splits.
8. Deploy behind a feature flag and compare shadow outputs against reviewed human outcomes.
9. Have a named release owner review calibration, false positives, language gaps and user corrections before any model affects production decisions.
10. Keep a one-click rollback to the Phase 2/3/4 path.

## 13. Known gaps

- No live OCR/vision provider is configured here.
- No live Daraja or bank reconciliation is implemented.
- No trained model, training corpus or live retraining is included.
- Current behavioural phrases are seed patterns; they are not full language understanding.
- Drift statistics are monitoring-only and need minimum sample volumes and periodic review.
