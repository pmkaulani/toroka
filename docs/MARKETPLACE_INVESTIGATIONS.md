# Marketplace link investigations

Toroka now recognises selected marketplace hosts and treats their product pages as a distinct investigation type. The current host list includes Jumia, Kilimall, Jiji, Masoko, Pigiame, Amazon, eBay, AliExpress, Temu and SHEIN. Host matching uses DNS-label boundaries; a lookalike such as `jumia.co.ke.attacker.example` is not classified as Jumia.

## What Toroka can extract

When the safe fetcher receives readable HTML, it inspects visible page text, Open Graph/product meta tags, canonical links and bounded Schema.org JSON-LD. Where the page exposes them, the report can display product name, description, brand, SKU, price/currency, availability, seller name, seller rating, product rating/counts and short review excerpts. The report labels these as information displayed by the page, not independently verified facts.

The platform identity and seller identity are separate. A recognised Jumia or other marketplace domain is not evidence that a particular seller, listing, product or delivery is genuine. Toroka therefore keeps an independent seller-verification item as `not_checked` unless a separate source actually verifies it.

## Access restrictions and limitations

The safe fetcher does not execute JavaScript and does not bypass login walls, CAPTCHAs, bot protections, rate limits or other marketplace access controls. If a marketplace returns HTTP 401/403 or 429, Toroka reports that the listing was not read. HTTP 404/410 is reported as not found; other non-2xx responses are not counted as successful inspections. A readable HTML page with no exposed product metadata is reported as a partial extraction, not as a fully read product listing.

Product pages that only reveal details after client-side JavaScript, account sign-in or an app session may still provide no extractable product metadata. Do not tell users Toroka has read a listing unless the `marketplace_product_details` coverage result says it was checked or partially extracted.

## Configuration and tests

Direct retrieval remains controlled by the existing `ENABLE_LINK_FETCH` setting and the existing SSRF-hardened fetcher. The marketplace extractor uses the same bounded response size, timeout, redirect validation, DNS checks and IP pinning; it does not create a separate network client or fetch image URLs.

Regression tests cover JSON-LD Product/Offer/Seller extraction, domain-boundary matching, marketplace category detection, blocked/rate-limited/not-found HTTP responses, listing decision content, seller-verification caveats, disabled fetching and Swahili report copy.
