# Toroka evidence transparency and shop discovery update

Date: 3 November 2026

This update extends Toroka's existing investigation intelligence so the user can inspect why a result was reached, and what public information exists about a shop's location and online storefronts.

## What changed

### Evidence behind the verdict

- Results now include a structured explanation tied to the current verdict.
- Each explanation reason can show the exact excerpt found in the submitted message, the issue it raises, and an evidence-strength description.
- Related public sources are linked directly to the reason when a source reference is available.
- Sources are distinguished as seller profile observations, retrieved target pages, public search leads, third-party allegations, and Toroka's own verified-registry matches.
- Standard text-only checks also show exact submitted wording that triggered findings, even when there is no URL or social profile to investigate.
- Unavailable checks and uncertainty remain visible; absence of a public report is not treated as proof of legitimacy.

### Shop location and online presence

For shop investigations Toroka now collects, when public sources provide them:

- A stated physical shop or business address.
- A location stated in the seller's profile (for example, a town or county).
- Delivery areas, clearly distinguished from physical shop addresses.
- Social storefront profile links and websites linked from the seller's public profile.
- The source and excerpt behind each location claim, plus a Google Maps search link for a stated address or profile location.

### How Toroka labels location data

- **Seller-published:** the seller's own public profile or a page on the exact target website states the detail. This is a self-declared claim, not independent verification.
- **Third-party mention:** another source mentions the location. Toroka does not present it as the seller's confirmed address.
- **Delivery area:** a service/delivery area is not treated as a shop address and does not get a shop-address Maps link.
- **No location found:** Toroka says no public location claim was found; it does not assume that the seller has no physical shop.

The Google Maps link opens a search for the stated place. It is not proof that the business operates there or a verified map pin. Profile-linked websites are shown as links found on the profile, not as proof of common legal ownership.

## Verification

- Backend tests: **367 passed**.
- Python API compile check: passed.
- JavaScript syntax checks for `app.js` and `i18n.js`: passed.
- Browser end-to-end tests were not run in this environment.
- Live provider API checks were not run; provider-dependent tests are mocked and live use still requires the appropriate API credentials.
- `packages/rules/tests/test_robustness.py` is excluded from the reported suite because Hypothesis is not installed in this environment.

## Main files changed in this update

- `services/api/app/investigation_intelligence.py`
- `services/api/app/routes_core.py`
- `services/api/app/social_intelligence.py`
- `services/api/app/static/app.js`
- `services/api/app/static/i18n.js`
- `services/api/app/static/styles.css`
- `services/api/tests/test_investigation_quality.py`
- `TOROKA-INTELLIGENCE-MERGE-REPORT.md`

The existing no-account/guest access path, logo, and English/Swahili UI were retained.

## State-of-the-art Build 1 additions (3 November 2026)

This update adds a bounded per-investigation evidence graph, candidate business listings from Google Places, and urlscan.io historical domain search. Historical scanner records are supporting context only; they do not independently make an entity high risk. The urlscan adapter sends a normalized domain to search existing scans and does not submit the user's URL for a new scan.

See [TOROKA-STATE-OF-THE-ART-BUILD-1.md](TOROKA-STATE-OF-THE-ART-BUILD-1.md) for setup, privacy controls, provider terms and test results.
