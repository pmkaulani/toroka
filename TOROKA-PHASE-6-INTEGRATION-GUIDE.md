# Phase 6 Integration Guide

## 1. Integration objective

Add deeper evidence panels to Toroka's existing investigation pipeline while preserving its current chat experience and existing Phase 2–5 verdict policy. Phase 6 is an additional analysis layer. It is not a replacement verdict engine.

Do not create a second FastAPI app, separate chat product, new account requirement, or new logo. Mount the modules inside the current backend and map the returned findings to the current chat-response schema.

## 2. Install

Copy `toroka_phase6/` into the backend package path and keep the package name stable. No core pip dependencies are needed. Confirm that Phase 2 `toroka_evidence` and Phase 5 `toroka_phase5` remain importable in the same Python environment.

Run:

```bash
python -m unittest discover -s tests -v
```

In the combined development environment, run the full Phase 2–6 test suites and the Phase 6 bridge tests.

## 3. Orchestration

The host backend is responsible for:

1. Authenticate the anonymous session or existing user session.
2. Present a clear notice and obtain the required consent for any audio/call processing.
3. Validate upload size, MIME type, file signature and malware scanning using the existing upload pipeline.
4. Run the existing OCR/vision, transcript and provider connectors in isolated workers.
5. Create opaque artifact references server-side. Never use a phone number, URL token, M-PESA transaction reference or seller handle as an artifact ID.
6. Assign source group and source type on the server. Do not accept those trust labels from the browser.
7. Pass bounded, already-extracted observations to `Phase6Investigator`.
8. Merge Phase 6 findings into existing evidence response using one adapter route.
9. Keep Phase 2's assessment and existing policy as the final customer-facing verdict.

Example:

```python
from toroka_phase6 import Phase6Investigator

phase6 = Phase6Investigator().investigate(
    case_ref=opaque_case_ref,
    website_snapshot=trusted_scan_snapshot,        # optional
    social_observations=authorized_profile_rows,   # optional
    image_artifacts=prepared_image_fingerprints,   # optional
    audio_transcripts=consented_transcript_rows,   # optional
    business_checks=backend_classified_records,    # optional
)

# Add findings as supplementary evidence. Choose one adapter, not both.
phase5_signals = phase6.to_phase5_signals()
# OR
phase2_evidence = phase6.to_phase2_evidence()
```

`to_phase5_signals()` requires the integrated Phase 5 package. `to_phase2_evidence()` requires the Phase 2 package. Both preserve limitations and mark provenance appropriately. Neither marks user uploads as verified.

## 4. Website forensics: safe network architecture

Phase 6's `validate_target_url(url, resolved_addresses)` does not make an HTTP request or resolve DNS. It rejects non-HTTP schemes, credentials in URLs, non-standard ports, localhost/reserved hosts and non-public DNS answers.

Implement fetching in an isolated worker with the following requirements:

- Accept only `https` by default; allow `http` only as a low-confidence observation when there is a documented reason.
- Resolve the hostname, validate **all** returned IPv4/IPv6 addresses, and connect only to a validated/pinned IP. Do not re-resolve between validation and connection.
- Preserve the original hostname for the HTTP Host header, TLS SNI and certificate hostname verification.
- Block loopback, private, link-local, multicast, reserved, unspecified, IPv4-mapped private IPv6 and cloud metadata ranges.
- Disable automatic redirect following. Validate each `Location` target, resolve and pin it independently, and cap redirects.
- Set tight connect/read timeouts, response-size limits and content-type allowlists. Do not execute JavaScript or download arbitrary files.
- Run without internal-network access, cloud credentials or access to local files.
- Do not log the pasted URL path/query; they may contain one-time tokens, invitation links or credentials.

After the safe fetcher or a licensed provider returns a sanitized snapshot, call `analyze_site_snapshot(snapshot)`. Supported fields include `tls_certificate_valid`, `tls_hostname_match`, `tls_days_remaining`, `domain_age_days`, `redirect_hosts` and `security_headers`. Domain age, missing headers and redirect count are context—not proof of fraud.

## 5. Social-account evidence capture

The `inspect_social_observation()` adapter accepts these collection modes only:

- `platform_authorized_api`: server received data under an approved API product and scopes.
- `official_platform_embed`: data observed through a platform-supported embed.
- `user_supplied_capture`: a screenshot or profile information submitted by the user; source group remains user-submitted.
- `merchant_authorized_export`: seller-authorized data export; source group remains user-submitted until independently checked.

Unsupported modes such as `headless_browser_scrape` are rejected. Do not scrape private profiles, bypass login, rotate accounts, evade rate limits, or use session cookies supplied by a user.

Platform notes:

- Instagram API products are access/scope restricted. The documented Facebook Login path is designed for professional accounts and does not provide general access to consumer personal accounts. Do not build a general public-profile crawler on it.
- TikTok Display API is an OAuth-based display product. Its basic profile and video scopes are tied to the creator authorization model; it is not an arbitrary profile-search API.
- Store only the minimum fields needed for the investigation, and label every observation with platform, retrieval method, scope, time and freshness.
- A verification badge is a platform-defined signal, not evidence of fulfilment or recipient ownership.

## 6. Image and receipt reuse

The existing upload/OCR pipeline remains responsible for safe image decoding and OCR. For each image:

1. Validate file signature and size; do not trust extension or browser MIME.
2. Compute SHA-256 over the original bytes for exact duplicate checks.
3. Downscale to an 8×9 grayscale sample inside an image worker and pass the 8×9 matrix to `dhash_from_grayscale()`.
4. Compare dHash values using `compare_fingerprints()`; preserve distance and algorithm version.
5. For OCR reuse checks, call `keyed_ocr_fingerprint(text, secret)` with a stable server-side HMAC key of at least 32 bytes. Never store the raw OCR text in the reuse index.
6. If Content Credentials/C2PA are available, validate the manifest with a maintained verifier and configured trust list before passing `c2pa_status` to `interpret_content_credentials()`.
7. Keep original image storage governed by the existing case retention and deletion workflow.

A match can indicate a shared catalogue image, supplier stock photo, repost or reuse. It does not establish who created, owns or uploaded the image. No face recognition is included. An absent credential does not mean an image is AI-generated; screenshots, compression and re-encoding can remove provenance data.

## 7. Call / voice analysis

Phase 6 analyzes a transcript supplied by the existing transcription service; it does not transcribe audio or detect voice cloning.

- Obtain explicit, recorded consent/notice before processing a call recording; give users a way to decline.
- Use a current supported transcription workflow and disclose the provider. For example, OpenAI's current Speech-to-Text docs recommend `gpt-transcribe` for completed recordings and `gpt-live-transcribe` for live streams; check current supported file sizes, formats and pricing before implementation.
- Preserve source audio only under Toroka's retention rules. Do not persist the raw transcript in the Phase 6 evidence store or logs.
- Use human-reviewed speaker attribution before a transcript pattern can be risk-polarity. If role is `unknown` or unreviewed, the finding remains context-only.
- Review English, Kiswahili, Sheng, mixed language, accents, crosstalk and transcription errors.
- No caller identity, voiceprint, deepfake or AI voice conclusion is generated by this package.

Example:

```python
from toroka_phase6 import analyze_call_transcript

result = analyze_call_transcript(
    transcript=provider_transcript,
    consent_confirmed=True,
    provider="approved-transcription-provider",
    artifact_ref="audio_case_0001",
    speaker_role="external_party",
    speaker_role_reviewed=True,  # set only after a reviewer checks the source
)
```

## 8. Kenyan business and location verification

Use the business checker with backend-classified sources:

- `verified_brs_official_search`: only after the backend has obtained and checked an official BRS/eCitizen response/document through an authorized process.
- `authorized_registry_response`: only for an approved integration with source provenance retained.
- `user_uploaded_registry_document`: a user-provided certificate; it is not independently verified by upload alone.
- `maps_place_listing`: third-party candidate listing; never call it a BRS verification.
- `merchant_claim`: seller statement, not external proof.

BRS currently describes official company searches through eCitizen (CR12) and says a business name is not a separate legal entity. Do not scrape private eCitizen flows or pretend the package performed an official search. Build a guided link-out/upload/review flow unless BRS provides a supported, authorized integration.

When location coordinates are available, the helper calculates distance and marks a discrepancy beyond 1.5 km as a review lead. It is not proof of deception: geocoding precision, branches, building entrances and location changes require human review.

Google Places has attribution and display restrictions; do not cache/place data outside the allowed exceptions, and show the required Google attribution/logo when displaying results. A place ID is an identified caching exception in the current Places policy.

## 9. UI integration

Read `PHASE6-UI-CONTRACT.md`. Add collapsible evidence sections underneath the conversational answer:

- Website forensics: host, scan time, TLS result, redirect observations and limits.
- Social profile: profile link, observation method, fields and last-checked time.
- Image reuse: exact/perceptual match, comparison thumbnail only where licensed/consented, match distance and caveat.
- Call analysis: detected language/tactics and speaker-attribution status, never a deepfake badge.
- Business identity/location: BRS official record vs user document vs map listing clearly distinguished; list location mismatch distance only where coordinates exist.

Keep evidence source, timestamp, collection method, confidence/strength and limitations visible. Do not collapse different modalities into a made-up single probability.

## 10. Privacy, retention and legal review

Kenya's Data Protection Act and ODPC guidance require lawful, fair, transparent, purpose-limited, proportionate and secure handling, including data-subject rights. Before launch, review controller/processor roles, lawful basis, notice, retention, deletion, correction, cross-border provider processing, security controls and whether a DPIA is required.

- Keep provider credentials server-side.
- Do not log raw images, audio, transcripts, contact numbers, OTPs, URL query strings or receipt references.
- Retain derived hashes only where there is a defined purpose and expiry/rotation plan.
- Provide a report correction/removal pathway and audit the change.
- Avoid collection of face templates or voiceprints.

## 11. Rollout acceptance checklist

- [ ] Phase 2–6 automated tests pass in the same environment.
- [ ] Website fetch worker is independently reviewed for DNS rebinding, redirects, IPv6 and metadata-service SSRF.
- [ ] Social provider scopes and terms are approved; no scraping fallback exists.
- [ ] C2PA validation is done by an actual verifier, not by trusting a browser-supplied `valid` value.
- [ ] Audio consent and reviewer-controlled speaker attribution work end-to-end.
- [ ] Registry source types are backend-set and cannot be sent by the browser.
- [ ] Map and seller address mismatches are context only.
- [ ] Raw uploads, transcripts, OTPs and tokens do not appear in logs or normal API responses.
- [ ] Correction/deletion workflow is exercised.
- [ ] New findings are displayed as supplementary evidence; Phase 2 remains the final verdict authority.
- [ ] Deploy behind a feature flag and keep a one-step rollback.

## 12. Known gaps

- No live Meta/TikTok/Google/BRS provider client is configured in this package.
- No safe outbound HTTP fetcher or DNS resolver is implemented here; only preflight validation is included.
- No actual image decoder, OCR, C2PA validator or reverse-image search service is bundled.
- No audio transcription API client or deepfake detection is bundled.
- No direct BRS/eCitizen API is assumed.
- No production database migration or user-interface code is applied; adapt the contracts to Toroka's real repo and deployment.
