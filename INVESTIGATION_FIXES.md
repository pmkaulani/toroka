# Toroka shop and unsolicited-SMS investigation improvements

This patch addresses online-shop identity lookup, cross-platform handle ambiguity, betting-promotion SMS, unsupported model claims, and the visibility of missing/live search coverage.

## Online shop and social-account behaviour

- Exact social profile URLs and bare `@handles` now flow through the conversational investigation path, not only the community-report lookup screen.
- The rules and report pipeline recognise platform-specific handles. A bare handle is treated as ambiguous across platforms, and matches are displayed separately rather than merging an Instagram account and TikTok account solely because they share a username.
- Users can submit and search reports against supported social handles or exact profile URLs.
- Shop classification does not itself prove a deposit scam. Advice focuses on verifying exact account identity, recipient, terms, delivery arrangements and available buyer protection; a physical shop, video call, or pay-on-delivery is not universally required.
- Public search uses only constructed queries derived from public identifiers, not raw private SMS, complete chat histories, phone numbers, PINs, OTPs or screenshots.
- If Tavily is not configured or fails, Toroka says live search was not performed and supplies a user-initiated Google search link in both the chat and structured result. The link is clearly labelled as a manual search not checked by Toroka.
- Search results are unverified leads, not verified facts. Root platform domains are not treated as the shop's own website, and fuzzy/ambiguous handle identities are not silently merged.
- The result UI visibly distinguishes what was checked, what was not checked, limitations and source/search leads.

## Betting and prize-promotion SMS

- A free-bet, Aviator or casino promotion by itself stays inconclusive. It is described as a promotion, not automatically a scam or proof of cash winnings.
- When a user says the messages are unwanted or that they never registered/bet, Toroka explains that the bonus is not cash or guaranteed earnings, and the SMS does not prove that the recipient has an account or that the offer is genuine.
- Advice says not to click/register/deposit merely to inspect the offer or share identity/credentials. Users should start from the provider's official menu/app/site rather than trusting a link in the text.
- The opt-out string `*456*9*5#` is not declared fake merely because it appears in an unsolicited SMS; its appearance does not authenticate the sender or offer. Safaricom documented the sequence as a promotional opt-out in a 2019 report. Current advice is to use the official `*456#` menu or contact the provider through an independently obtained official channel.
- Repeated unsolicited messages are a carrier complaint first; if unresolved, users can escalate to the Communications Authority of Kenya (CA). Keep the sender ID and screenshots.

## Evidence integrity and cross-case contamination

- Unrelated previous chat context is cleared when new investigation evidence arrives, while a relevant user context (for example, “I don't bet and keep getting these messages”) is preserved for a betting promotion.
- Model-generated summaries and free-form findings are not treated as factual evidence. A model-added observation must quote a substring present in the supplied message/OCR, and that observation is not itself proof of fraud.
- A payout document or word like `redemption` alone stays inconclusive. A clear promised payout plus demand for an upfront release fee receives a high-risk advance-fee warning, without inventing amounts, names, or regulatory claims.
- Generic customs/parcel fees do not automatically activate a specialised diplomatic-parcel scam classification.
- Taxonomy risk bands are aligned to the final evidence-policy label.

## Live search configuration

The optional Tavily adapter requires `TAVILY_API_KEY` in the server environment for Toroka-initiated public searches. Without the key, the application does **not** claim to have searched live sources; it exposes a user-clicked manual search instead. Live Instagram/TikTok profile crawling remains subject to platform access limits. Manual Google results are external and are not checked by Toroka.

## Validation

The following checks were run from the project root:

```bash
PYTHONPATH=packages/rules:packages/connectors:services/api pytest -q -o filterwarnings=ignore --ignore=packages/rules/tests/test_robustness.py
python -m compileall -q services/api/app packages/rules/ssi_rules packages/connectors/ssi_connectors
node --check services/api/app/static/app.js
node --check services/api/app/static/i18n-chat.js
node --check web-tests/browser.mjs
```

Latest result: **260 tests passed**. Python compile and JavaScript syntax checks passed. The property-based robustness suite was excluded because the environment lacks the `hypothesis` dependency. Full browser-based visual/end-to-end verification was not completed in this environment, and a live Tavily search was not tested without a configured key.

## Deploy safely

- Keep the original `.env`, private database and evidence store separate; they are not included in source archives.
- Rotate any API key that was previously included in an uploaded archive or shared outside its secret store.
- Set provider keys in the deployment secret store, not in frontend code or Git.
- Restart/redeploy after applying the source files.
- Test an ordinary Instagram handle, a TikTok handle with the same name, a known moderated report, an unreported shop, a betting-promotion SMS, a payout-with-release-fee message, and a neutral parcel fee before launch.
