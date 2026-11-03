# Toroka — State-of-the-Art Build 1

**Build date:** 3 November 2026  
**Scope:** Evidence graph, merchant-location candidates, and historical website-scan intelligence.

## What changed

### 1. Per-investigation evidence graph

`services/api/app/evidence_graph.py` builds a bounded graph for each investigation. It connects:

- the submitted target (domain, public social handle, or shop name);
- source records and the domains publishing them;
- seller-published location claims and outbound links;
- candidate business listings returned by Google Places;
- historical urlscan.io records for a domain.

Every relationship carries its evidence ID, basis and strength. The graph is scoped to the current investigation; this build does not create a cross-user accusation database. It intentionally avoids storing phone numbers, payment identifiers or private victim narratives in graph nodes.

The graph distinguishes strong exact-identifier source matches from contextual mentions. Google Places listings and links from public social profiles remain contextual/candidate relationships, not proof of common ownership.

### 2. Google Places shop-location discovery

New connector: `packages/connectors/ssi_connectors/places.py`.

For shop investigations, Toroka can use the public seller name/handle and a seller-published location claim to search Google Places (Places API New, Text Search). It returns up to five candidate listings with available name, address, Maps link, website and business status. Candidate results are filtered for name overlap and labelled **possible name match — seller identity not confirmed**.

A listing does not establish that a social account owns or operates the physical business. A service-area business can also operate without a public storefront address. No candidate result does not prove that a shop does not exist.

Optional environment variable:

```dotenv
GOOGLE_PLACES_API_KEY=your_server_side_key
```

Set up a Google Cloud project, enable Places API (New), configure billing and create a server-side API key. Restrict the key to the Places API and to the backend's egress IP where possible. Review current Google Maps Platform pricing, terms and storage/attribution rules before production use.

Official documentation: <https://developers.google.com/maps/documentation/places/web-service/text-search>

### 3. urlscan.io historical domain intelligence

New connector: `packages/connectors/ssi_connectors/urlscan.py`.

Toroka can search urlscan.io's existing scan history for:

- a submitted domain target; or
- up to two external domains explicitly linked from a target-controlled public shop profile/page.

The integration searches by domain (`task.domain`) and returns a bounded set of historical records, including scan date, page title, verdict (when supplied), score, redirect context, visibility and a link to the original scan result.

**Privacy choice:** this integration does not submit or crawl a user's submitted URL. It sends only a normalized public domain to the historical search endpoint. This avoids disclosing URL paths, invite codes, tracking tokens, password-reset links or other query parameters to a third party.

A historical malicious verdict creates a supporting warning with a link to the scan. It does not, by itself, upgrade the Toroka verdict to high risk. A historical non-malicious result is not a clean bill of health. The scan can refer to an earlier version or a different path on the same domain.

Optional environment variable:

```dotenv
URLSCAN_API_KEY=your_urlscan_api_key
```

Create an account and obtain an API key from <https://urlscan.io/user/profile/>. Before embedding urlscan results in a commercial product, confirm the current plan, acceptable-use conditions, quota and redistribution/display rights with urlscan.io. Public scan submissions are deliberately not used in this build.

Official API documentation: <https://urlscan.io/docs/search/>

### 4. UI and language support

The existing investigation view now labels historical scanner evidence distinctly from seller profile observations, retrieved page content and public allegations. The connected evidence graph is rendered with relationships, source links and strength labels. New labels are available in English and Swahili.

The existing logo, guest/no-account flow and core chat interface are unchanged.

## Configuration and runtime behaviour

Both new connectors are optional. If no key is configured, Toroka reports the provider as **not configured / not checked**; it does not silently treat missing coverage as safe. No provider credentials are included in this source package.

Add the new settings to the backend's `.env` or hosting secret store:

```dotenv
GOOGLE_PLACES_API_KEY=
URLSCAN_API_KEY=
```

Restart/redeploy the backend after changing environment variables. Keep these keys on the server only; never put them in frontend JavaScript, a public repository or a client-side build.

## Tests and validation

Verified in this build workspace:

- Focused evidence graph, Google Places, urlscan and investigation regressions: **35 passed**.
- Connector suite: **27 passed**.
- `python -m compileall -q services/api/app packages/connectors/ssi_connectors`: passed.
- `node --check services/api/app/static/app.js`: passed.
- `node --check services/api/app/static/i18n.js`: passed.

A broader API test run did not complete cleanly in this workspace: pytest stalled before printing a final summary. A full-project green result is therefore **not claimed**. No live Google Places or urlscan credentials were configured, so these integrations were tested with mocked provider responses rather than live API calls.

## Important next build items

1. Add RDAP registration details and certificate-transparency history as contextual domain evidence.
2. Add DNS/hosting/IP/ASN enrichment with safe DNS resolution and infrastructure correlation.
3. Add Kenyan authoritative verification adapters (NEA recruitment-agency register, BRS business records) using approved access routes and a source freshness policy.
4. Add merchant payment identity checks only through authorized Safaricom, bank or payment-provider agreements. Do not attempt arbitrary private M-PESA recipient lookups.
5. Add a reviewed community incident intake, deduplication and appeal/correction workflow before using community reports in risk scoring.
6. Add provider health, quotas, costs, caching and per-provider timeout dashboards.

These are planned capabilities, not claims that they are already implemented in this build.
