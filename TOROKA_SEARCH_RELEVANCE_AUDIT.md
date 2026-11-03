# Toroka Search Relevance & Investigation Audit

Date: 26 October 2026

## Scope

This pass focused on the reported `@base_menswear` Instagram investigation, search-result relevance, accurate coverage wording, URL canonicalisation, and preventing case context from leaking between unrelated investigations.

## Changes made

- Canonicalise supported social profile URLs and discard unnecessary tracking parameters from the canonical identity. The original submitted URL remains available as input evidence where needed.
- Rank public search results against the exact platform handle or target domain before attaching them to an investigation.
- Keep results that match the target distinct from general safety articles and unrelated/lookalike entities.
- Do not treat a profile or post mentioning `@base_menswear` as proof of a complaint, fraud, or legitimacy.
- Include the real result counts and explain when a search result is only an unverified lead.
- Keep source inspection status as `not_checked` when a platform profile cannot be inspected directly.
- Return an inconclusive assessment when profile inspection is unavailable and no relevant, corroborated adverse evidence is found.
- Filter out bare URLs and profile handles as low-value model-generated “findings”; a submitted URL is not itself a red flag.
- Remove context-specific LLM replies from the URL evidence cache. The evidence can be cached, but the explanation must be generated for the current user request/context.
- Include provider-configuration state in cache keys so a cached response cannot continue claiming that a newly configured provider is unavailable.
- Keep the seed champion active and remove a test-only rollback pointer from the shipped model pointer. No unreviewed shadow model is presented as an approved rollback champion.

## Regression case: `@base_menswear`

For a search response containing five sample results, the regression test confirms that only the result whose content explicitly mentions `@base_menswear` remains as an account-related lead. The unrelated `baseusclothing.com` review, a generic seller-warning post about another account, and unrelated YouTube content are excluded from the account-specific source list.

The matched Instagram post is treated as an account reference only. It is not treated as evidence of a complaint or proof of wrongdoing. If direct Instagram inspection is unavailable and no corroborated report is found, the result remains **Inconclusive**.

## Test results

- Search relevance, URL investigation, and evidence grounding: all suites passing.
- Rules and autonomous-ML tests: all passing.
- Connector tests: all passing.
- Community, verified registry, and operations API tests: all passing.
- API checks & static web-shell tests: all passing.
- 372 / 372 tests passing across the test suite.
