# Phase 3 Integration Guide

## 1. Keep the current application intact

Phase 3 is designed as an additive layer. Keep Toroka's current chat, image input, English/Swahili support, zero-account experience, Phase 2 `EvidenceEngine`, and URL investigation pipeline. Do not create a second FastAPI application or replace the existing chat response schema.

Recommended backend tree:

```text
backend/
  toroka_evidence/       # Phase 2
  toroka_phase3/         # this package
  app/
    chat_orchestrator.py
    investigations.py
```

## 2. Use the same identity hashing secret

`EvidenceMemory` from Phase 2 and `EntityLinkGraph` from Phase 3 should use the same `TOROKA_ENTITY_HASH_SECRET` if the graph is expected to recognize the exact same normalized identifiers as Phase 2. The hash namespaces are versioned separately and may not be byte-for-byte identical across packages; pass the original normalized identifiers into each package rather than attempting to reuse their internal hashes.

Use one secret manager value, server-side only. Do not rotate it casually: changing it breaks historical matching. If a key rotation is required, plan an explicit re-key migration that reads and re-hashes protected identifiers (which may require a secure temporary data migration process).

## 3. Record relationships with clear evidence basis

Do not add a relationship just because an LLM inferred it from a similar shop name. Record a relationship only when an actual source or user claim exists.

Example: seller claims a website in their bio:

```python
graph.add_link(
    ("social_handle", "@sample_shop"),
    ("domain", "sample-shop.co.ke"),
    relationship="claims_website",
    basis="public_page",
    source_label="Instagram profile bio",
    source_url="https://www.instagram.com/sample_shop/",
    evidence_id="<phase-2-evidence-id>",
    match_confidence=0.86,
    status="unverified",
    limitations=["A profile link does not prove control of the website."],
)
```

Example: seller asks buyers to pay a Paybill on a public page:

```python
graph.add_link(
    ("social_handle", "@sample_shop"),
    ("mpesa_paybill", "123456"),
    relationship="requests_payment_to",
    basis="public_page",
    source_label="Payment instructions visible on public seller page",
    evidence_id="<phase-2-evidence-id>",
    match_confidence=0.90,
    status="unverified",
    limitations=["The public post does not establish who controls the Paybill."],
)
```

The `match_confidence` is confidence in matching the observed value to the indicated seller record. It is not the probability of fraud.

## 4. Add connected-entity context to the existing investigation

After Phase 2 produces its `InvestigationResult`, the chat orchestrator can query relationships for identifiers explicitly present in the current case:

```python
relationships = []
if request.social_handle:
    relationships.extend(graph.get_links(("social_handle", request.social_handle)))
if request.claimed_website:
    relationships.extend(graph.get_links(("domain", request.claimed_website)))
if request.claimed_phone:
    relationships.extend(graph.get_links(("phone", request.claimed_phone)))
if request.claimed_payment_identifier:
    # Supply the correct kind based on user/provider extraction; never guess Till vs Paybill.
    relationships.extend(graph.get_links(("mpesa_paybill", request.claimed_payment_identifier)))
```

Deduplicate by `assertion_id` before returning. Do not ask an LLM to invent or merge entities. Use the graph's stored source, relationship, status, evidence ID and limitation fields as the source of truth.

For shared-infrastructure analysis, build `SellerFootprint` inputs only from seller records that Toroka already has permission to process. Use `graph.identifier_digest(kind, value)` to create backend-only HMAC digests—not raw phone numbers or payment identifiers—for the `identifiers` dictionary. Never expose these digests to the browser. Populate `corroborated_reports` only from the Phase 2 moderation state `corroborated`; do not count `pending` or `reviewed_unverified` as corroborated.

## 5. Add M-PESA receipt consistency checks

Use Toroka's existing image/text extraction pipeline to produce these temporary fields:

- expected order amount and amount shown on receipt;
- seller's stated recipient name and receipt's displayed recipient name;
- expected Till/Paybill short code and receipt's displayed business number;
- expected account/invoice reference and receipt's displayed reference;
- whether a transaction reference appears.

Pass them into `review_payment_claim(PaymentClaim(...))`. Keep the source classification `user_supplied_receipt_not_independently_verified`. The response can flag a wrong amount, unexpected recipient, short code or account reference. Matching values mean only that the extracted fields are consistent with the user's supplied expectations.

**Never** say the transaction is confirmed just because an SMS or screenshot looks plausible. Do not ask users to paste their M-PESA PIN, OTP, full account credentials or other authentication secrets. Do not persist the full receipt text when a small set of extracted fields is enough.

## 6. Official Kenyan business verification

BRS identifies the official search process through eCitizen. Its published FAQ says a business name is not a legal entity and describes an Official Search (CR12) for private limited companies. For Toroka:

1. Show a guided `Verify business registration` step.
2. Send the user to the official BRS/eCitizen route.
3. Allow the user to provide the result only as a user-supplied document.
4. Display issuer, document type, registration name/number, issue date and what was checked.
5. Keep the record `unverified` until an authorized operator or approved official integration verifies it.
6. Even after verification, state only that the particular registration record was checked. Do not imply that the social account, payment destination, inventory or delivery performance is verified.

Do not scrape logged-in eCitizen content or pretend that Toroka queried it.

## 7. M-PESA official transaction verification boundary

Safaricom's Daraja Transaction Status API is documented for an organization to check a recent transaction on the business account, using an M-PESA receipt number or conversation identifier. It is not a universal public lookup for any individual recipient's account.

For a merchant-partner integration, the merchant must authorize Toroka and provide its own approved Daraja setup/credentials. Use a server-to-server integration, protect initiator/security credentials, process asynchronous results, verify callback origin/integrity according to Safaricom's then-current requirements, and scope results to the partner's own shortcode/account. Never accept a frontend `verified=true` flag. This partner integration is not implemented in this package.

## 8. Chat response mapping

Keep the familiar assistant response. Add collapsible sections after the natural-language conclusion:

```json
{
  "phase3": {
    "connected_entities": [],
    "shared_infrastructure_patterns": [],
    "payment_review": null,
    "case_timeline": {
      "events": [],
      "community_report_counts": {
        "pending": 0,
        "reviewed_unverified": 0,
        "corroborated": 0,
        "rejected": 0
      }
    },
    "limitations": []
  }
}
```

Use Phase 2 evidence IDs as cross-references. Do not copy raw PII or tokens into this payload. If a relationship has no public source URL, show its source label and evidence ID rather than inventing a link.

## 9. Required integration tests

- A link to a social profile and a website remains `unverified` until an independent source supports the relationship.
- Two shops sharing a phone or Paybill are not automatically merged.
- A shared number alone never raises a seller's fraud verdict.
- Pending reports do not contribute to corroborated-report counts.
- An uploaded CR12/CR13 is not automatically marked verified.
- A matching user-supplied M-PESA SMS does not yield payment confirmed.
- Amount/recipient/shortcode/reference mismatches are surfaced.
- Provider timeouts remain unavailable, not clean.
- Deletion requests remove relationship assertions touching the specified identifier.

## 10. Rollout sequence

1. Deploy Phase 3 tables to a staging DB with backups.
2. Wire relationship recording into the existing investigation orchestrator.
3. Run on historical/synthetic examples and inspect the graph manually.
4. Add UI components behind a feature flag.
5. Pilot with internal users; monitor false links, incorrect parsing and user disputes.
6. Only then expose graph and payment comparison to all users.

Do not train a machine-learning model on community allegations at this stage. Build a labelled, adjudicated dataset first, with explicit consent, moderation outcomes, appeal/correction workflow and an independent holdout set.
