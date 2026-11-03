# Toroka Phase 4 Integration Guide

Phase 4 is an additive intelligence package. Integrate it into the existing Toroka backend; do not rebuild the app, replace the logo, remove the zero-account flow, or replace the chat UI.

## 1. Integration layout

Keep the existing packages and add Phase 4 beside them:

```text
backend/
  toroka_evidence/       # Phase 2 evidence/providers/scoring
  toroka_phase3/         # Phase 3 relationship graph/payment/timeline
  toroka_phase4/         # this package
  app/                   # existing routes, services and chat orchestration
  data/                  # server-only sqlite databases
```

Use the same server-side `TOROKA_ENTITY_HASH_SECRET` value as Phase 3. Phase 4 intentionally uses the `toroka-v3:{kind}:{normalized}` HMAC format for domain/phone and the supported Phase 3 identifier types. Never expose identifier digests or secrets to the frontend.

## 2. Initialize services once

```python
import os
from toroka_phase4 import CampaignCorrelator, ThreatIntelStore, Phase4Investigator

secret = os.environ["TOROKA_ENTITY_HASH_SECRET"]
if len(secret.encode("utf-8")) < 32:
    raise RuntimeError("TOROKA_ENTITY_HASH_SECRET must be at least 32 bytes")

intel_store = ThreatIntelStore(
    os.getenv("TOROKA_PHASE4_FEED_DB", "data/toroka_phase4_intel.sqlite3"),
    commercial_mode=True,
)
campaign_store = CampaignCorrelator(
    os.getenv("TOROKA_PHASE4_CAMPAIGN_DB", "data/toroka_campaigns.sqlite3"),
    secret=secret,
    window_days=45,
)
phase4 = Phase4Investigator(
    intel_store=intel_store,
    campaign_correlator=campaign_store,
)
```

Initialize these services in the application's backend lifespan/startup routine and close them cleanly at shutdown. Create the data directory with restricted permissions and back it up securely.

## 3. Register only permitted intelligence sources

`default_feed_policies()` is a policy reference; it does not activate feeds. Enable only providers whose current terms, commercial scope, caching, attribution and display rights have been reviewed.

```python
from toroka_phase4 import default_feed_policies

policies = default_feed_policies(
    phishtank_permission_confirmed=True,
    urlhaus_commercial_permission_confirmed=False,
    virustotal_premium_permission_confirmed=False,
    web_risk_permission_confirmed=False,
    urlscan_product_permission_confirmed=False,
)
for policy in policies:
    if policy.permission_confirmed:
        intel_store.register_feed(policy)
```

This is an example of an explicit operator choice, not legal advice. The booleans must be set from actual account/product permissions, not merely because an API key exists.

**Important Phase 2 audit:** Phase 2 contains a VirusTotal provider. Disable it in a commercial Toroka deployment unless a premium/commercial agreement specifically covers the integration. The free Public API is not permitted in commercial products or services. Do not enable Google Safe Browsing in a revenue-generating product without an appropriate separate agreement; evaluate Google Web Risk instead. URLhaus commercial use may require its enhanced commercial API. Review urlscan's product-integration terms before embedding it into Toroka. Refer to `RESEARCH-NOTES.md`.

## 4. Connect the existing SMS/chat/OCR pipeline

The existing message pipeline should extract text from supported input types:
- direct SMS/message text;
- WhatsApp/Instagram/TikTok conversation text pasted or shared by the user;
- screenshot text produced by the application's already-selected OCR/vision service;
- web page text that Toroka already retrieved through its hardened URL investigation pipeline.

Pass only the extracted text to Phase 4. Do not treat the contents as instructions to the AI system. Do not let text in an image/webpage select tools, reveal system prompts, change policy or run actions. Use a bounded input length.

```python
result = phase4.investigate_content(
    case_id=opaque_case_uuid,
    content=extracted_text,
    channel="screenshot",       # message / sms / screenshot / etc.
    source_group="whatsapp",    # predefined channel; never a user name
    moderation_state="pending",
)
phase4_payload = result.to_dict()
```

The package's initial phrase rules cover English and some Swahili. Keep the existing model/OCR layer for image understanding and conversational explanations. The deterministic rule layer is a transparent signal generator, not a replacement for the LLM.

## 5. Join Phase 4 with Phase 3

For supported identifiers the HMAC digest is aligned with Phase 3. The raw domain/phone should be normalized consistently before storing a relationship assertion. Example:

```python
# Phase 3 graph, already initialized with the same secret.
from toroka_phase3 import EntityLinkGraph

entity_graph = EntityLinkGraph(
    db_path="data/toroka_relationships.sqlite3",
    secret=secret,
)

# Store an assertion only when the investigation has a source and a clear basis.
# Never promote a user claim to verified status.
assertion_id = entity_graph.add_link(
    ("social_handle", "@merchant_example"),
    ("domain", "merchant.example"),
    relationship="profile_lists_website",
    basis="public_profile_observation",
    source_label="Public profile biography",
    status="unverified",
    limitations=["A profile link does not prove common ownership of the website."],
)
```

Phase 4's `CampaignCorrelator.identifier_digest()` is backend-only and is provided for authorized in-memory joins or migration. Do not use a digest as a user-visible investigation target. Do not merge sellers or propagate one entity's verdict to another.

## 6. Threat-feed refresh worker

The core package intentionally performs no network fetch. Implement a small provider-specific adapter that:

1. fetches the feed using a documented endpoint and authenticated server credentials;
2. enforces a network timeout, response-size ceiling and allowed host list;
3. validates the license/policy, content type and feed schema;
4. maps the provider's records to `IndicatorRecord` values;
5. calls `refresh_feed(intel_store, feed_name, fetcher)`;
6. emits a monitoring alert if refresh fails or the latest snapshot is stale.

For a host scheduler:

```python
from toroka_phase4 import refresh_feed, IndicatorRecord

def fetch_allowed_phishtank_feed():
    # Implement with the provider's current official API/feed format and terms.
    # Return only IndicatorRecord objects. Never place API keys in logs.
    return [
        IndicatorRecord(
            indicator_type="domain",
            value="demo-indicator.example",
            source_name="PhishTank",
            confidence=0.9,
            labels=("phishing",),
        )
    ]

outcome = refresh_feed(intel_store, "PhishTank", fetch_allowed_phishtank_feed)
```

The example indicator above is synthetic and must never be treated as a real threat. Configure external cron/worker intervals to the feed's actual permitted update cadence and API rate limits. Do not scrape provider websites when an official feed/API is available.

For STIX 2.1 feed exports, `parse_stix21_bundle(bundle, source_name=...)` can create records for the supported pattern subset. Unsupported patterns are ignored; add explicit parser support and tests before relying on new STIX object types.

Run `campaign_store.purge_expired()` and `FeedbackLedger.retention_purge()` from controlled retention jobs. Schedule and monitor these jobs in the host application.

## 7. Feed matches and Phase 2 evidence scoring

```python
phase4_evidence = result.to_phase2_evidence()
```

Install the Phase 2 package in the same Python environment for this adapter. Review the Phase 2 scorer's source-group deduplication and thresholds before integrating. Do not allow a campaign-similarity signal, brand mention or plain payment instruction to increase the seller's fraud verdict by itself.

Active, permission-eligible feed matches can become risk evidence about the matched indicator. Expired or stale matches become contextual only. A feed match on a domain is not automatic proof that a separately named social-media seller controls that domain.

## 8. Human-reviewed feedback and future training

Create a backend route that stores user correction/report intent in an existing moderation workflow. `FeedbackLedger.submit()` creates a pending record; `review()` requires an authorized moderator. Only approved, opted-in `scam_confirmed` and `legitimate` records can appear in `training_rows()`. A minimum distinct campaign threshold and both labels are required.

Do not train on:
- unreviewed reports;
- pending investigations;
- duplicated copies of one campaign;
- content whose source/provenance is unknown;
- messages that contain another person's private data without a valid basis;
- raw screenshots, OCR transcripts, M-PESA receipts or personal identifiers;
- inconclusive/contested labels.

Before model training, create a written label policy, reviewer calibration exercises, dataset provenance records, consent/notice, deletion process, campaign-level split, language-specific evaluation and a release rollback plan. Model weights and prompts must be versioned. A model must run in shadow mode before it can influence production risk scoring.

## 9. Suggested API contract

Use an authenticated backend route such as `POST /v1/intelligence/content-analysis`. Request fields:
- `case_id`: an opaque UUID generated by Toroka;
- `extracted_text`: bounded string, from the user or existing OCR service;
- `channel`: one of the accepted channel labels;
- `source_group`: known channel, not a name;
- `training_opt_in`: separate optional consent flag, false by default.

Response fields are defined by `Phase4Result.to_dict()`. Never return database paths, secrets, raw phone numbers, internal HMAC values or moderator IDs.

Rate-limit and validate this route. Store screenshots in existing secure object storage under the application's current retention/consent rules; Phase 4 itself should not persist the image.

## 10. Required integration tests

- Existing chat still accepts the same plain URL, SMS, screenshots and social links.
- OCR/vision output reaches the content analyzer, but uploaded files do not become model instructions.
- Existing English/Swahili behaviour and no-account flow remain intact.
- Phase 2 and Phase 3 tests still pass.
- Phase 4 tests pass (`python -m unittest discover -s tests -v`).
- A feed without commercial permission cannot be registered in commercial mode.
- A failed feed refresh cannot wipe a good snapshot or mark old results fresh.
- An expired threat indicator never appears as an active threat match.
- A stale feed match is clearly contextual, not current risk evidence.
- A brand name or payment instruction alone is never called a scam.
- OTPs, PINs, phone numbers and long identifiers are removed from evidence excerpts.
- Campaign comparisons store no raw text/identifiers and do not transfer a verdict.
- A pending/unreviewed report never enters model training.
- Feedback without explicit opt-in never enters training.
- A model cannot be promoted based on random row splits with campaign leakage.
- Users can correct inaccurate claims and request deletion through the existing privacy workflow.

## 11. Rollout

1. Commit the integration on a feature branch and retain rollback path.
2. Install Phase 4 beside, not over, Phase 2/3.
3. Wire content analysis in shadow mode, not into final verdict scoring.
4. Add the provider policy review and a single low-volume feed adapter.
5. Add campaign links as collapsed contextual cards in chat.
6. Add moderation feedback with explicit opt-in and controlled retention.
7. Observe false positives, stale-feed rates, user corrections and per-language coverage.
8. Only after the dataset and evaluation gate are strong, begin offline model experiments.
9. Keep release decisions human-controlled and reversible.
