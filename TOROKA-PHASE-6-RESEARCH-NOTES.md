# Phase 6 Provider, Platform and Compliance Research

Research checked on **4 November 2026**. This is implementation guidance, not legal advice. Re-check current API approvals and contractual terms before a commercial release.

## Social platforms

### TikTok

Official Display API documentation describes profile and public video display endpoints and scopes such as `user.info.basic` and `video.list`. The developer onboarding flow requires a TikTok developer account, Login Kit, Display API product approval, and granted scopes. This supports an authorized creator-display connector—not general scraping or arbitrary account discovery.

- Overview: https://developers.tiktok.com/docs/en/display-api-overview
- Get started: https://developers.tiktok.com/docs/en/display-api-get-started
- Scopes: https://developers.tiktok.com/docs/en/tiktok-api-scopes

### Instagram / Meta

The current Instagram API products are permission- and account-type-limited. Meta's documented Facebook Login path is for professional Instagram accounts (Business/Creator), requires linked Page/permissions, and does not provide general access to consumer personal accounts. Treat the actual API product and scopes approved for Toroka as authoritative; if Toroka cannot lawfully retrieve a seller profile through an approved API, use the seller's public profile link and user-provided capture instead of scraping.

- Meta Instagram API collection (Postman): https://www.postman.com/meta/instagram/documentation/6yqw8pt/instagram-api
- Recheck current Meta developer documentation/permissions before shipping: https://developers.facebook.com/docs/instagram-platform/

## Website safety

OWASP warns that domain allowlisting alone does not stop DNS rebinding. The outbound client must validate all DNS answers at connection time and pin the HTTP connection to the validated address while preserving hostname/TLS verification. Redirect targets require their own validation. Phase 6 includes preflight helpers only; it is not an HTTP fetcher.

- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- MDN SSRF reference: https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/SSRF

## Image provenance and reuse

C2PA Content Credentials are a technical provenance standard for signed media assertions. A valid manifest is information about signed media history, not proof the depicted content is factually accurate. Metadata/credentials can be removed through screenshots, re-encoding, cropping or platform processing. Absence must never be turned into an AI-generation accusation. The package interprets a status supplied by a maintained verifier; it does not implement C2PA cryptographic validation.

- C2PA specifications: https://spec.c2pa.org/
- OpenAI content provenance guidance: https://developers.openai.com/api/docs/guides/content-provenance
- C2PA overview/support in ChatGPT: https://help.openai.com/en/articles/8912793-c2pa-in-chatgpt-images

## Audio transcription

Current OpenAI Speech-to-Text documentation recommends `gpt-transcribe` for completed audio and `gpt-live-transcribe` for live audio. The file transcription guide lists the accepted file types and 25 MB size cap. Confirm current availability, rates, data handling and supported languages in the provider contract and test representative Kiswahili/Sheng/English/Swahili-mixed samples. The Phase 6 package only analyzes text returned by the host's approved transcription service.

- File transcription: https://developers.openai.com/api/docs/guides/speech-to-text
- Transcription workflows: https://developers.openai.com/api/docs/guides/transcription

## Kenyan business records

BRS directs users to eCitizen for company official searches (CR12) and its FAQ explicitly says a business name is not a legal entity. Do not infer that a seller's social account, bank/M-PESA recipient or fulfillment operation belongs to a registered entity merely because the name matches. A user-uploaded certificate is not independently verified by upload. Use an authorized official search/response and retain source provenance.

- BRS FAQ: https://brs.go.ke/wp-content/uploads/2024/05/FAQs.pdf
- BRS services: https://brs.go.ke/
- eCitizen/BRS: https://brsv2.ecitizen.go.ke/

## Maps and locations

Google Places requires appropriate attribution and display. Its current policy prohibits pre-fetching, caching or storing Places API content except permitted exceptions; Place IDs are exempt from caching restrictions. If results display on a map, show them on a Google Map with Google logo and required attribution. If displayed without a Google Map, show Google attribution per policy. A map listing is only a candidate location, not official registration or proof of seller control.

- Places API policies: https://developers.google.com/maps/documentation/places/web-service/policies

## Kenya data protection

The ODPC describes data-subject rights including information, access, objection, correction and deletion of false/misleading data; its guidance also states purpose limitation, minimization, accuracy, retention limits, security and safeguards for transfers. Toroka should have a clear notice/lawful basis, an audio-specific consent flow, retention/deletion controls, correction channel and a DPIA/registration review as applicable.

- ODPC data-subject rights: https://www.odpc.go.ke/rights-of-a-data-subject/
- ODPC regulatory framework: https://www.odpc.go.ke/data-protection-laws-kenya/
- Data Protection Act, 2019: https://new.kenyalaw.org/akn/ke/act/2019/24/eng%402019-11-15/source

## Decisions and things not included

- No arbitrary public-profile scraping, account takeover, cookie/session import, or anti-bot evasion.
- No universal Instagram/TikTok search connector is assumed.
- No direct BRS/eCitizen API is assumed.
- No public arbitrary M-PESA recipient lookup is assumed.
- No AI/deepfake voice detector is implemented.
- No actual reverse-image search vendor is configured.
- No C2PA cryptographic verifier, OCR engine, live transcription client, or website HTTP fetcher is bundled.
- Google Places, Meta and TikTok are not enabled by API key alone; approvals, scopes and display/storage rules must be satisfied first.
