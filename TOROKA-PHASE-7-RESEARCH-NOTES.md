# Phase 7 — Research, Provider Governance & Limitations

Research checked on **4 November 2026**. This note is an engineering decision record, not legal advice. Recheck current terms and obtain qualified advice before provider enablement.

## Provider decisions

### PhishTank
- Current terms page: https://phishtank.org/terms.php
- FAQ: https://phishtank.org/faq.php
- API documentation: https://phishtank.org/api_info.php
- The current terms page links to Cisco's current EULA and marks older terms as archived, while the FAQ still describes API use as available for commercial and non-commercial projects. Because these pages may not provide a complete, current grant for every product use/display/redistribution scenario, Phase 7 leaves the provider disabled pending review of the exact governing terms and written permission where required.

### OpenPhish
- Terms: https://www.openphish.com/terms.html
- Its published terms restrict commercial operational use (including threat intelligence, security operations, product development and customer protection) without prior written consent. Do not enable for Toroka's commercial product without written permission covering the intended use and display.

### urlscan.io
- Terms: https://urlscan.io/terms/
- API documentation / quotas: https://urlscan.io/docs/api/
- Respect account-specific rate limits, private/public scan choices and product integration terms. Do not submit customer URLs or expose scan details without an explicit privacy/terms decision and plan approval.

### URLhaus
- API documentation: https://urlhaus.abuse.ch/api/
- Confirm current commercial use, redistribution and attribution conditions for the exact feed before enabling it. The package does not assume that an open API equals unrestricted redistribution.

### Google Places
- Policies: https://developers.google.com/maps/documentation/places/web-service/policies
- Follow attribution, caching/storage and display restrictions. A Places result is a location/business candidate, not proof of registration or ownership.

## Kenya-specific intelligence

- National KE-CIRT/CC alerts and advisories: https://ke-cirt.go.ke/alerts-advisories/
- National KE-CIRT/CC quarterly reports: https://ke-cirt.go.ke/quarterly-reports/
- National KE-CIRT/CC: https://ke-cirt.go.ke/
- Communications Authority cyber security: https://ca.go.ke/cyber-security

These official pages provide national cybersecurity context. Phase 7 uses manually reviewed citations with authority, source URL, publication/retrieval timestamps and reviewer reference. A quarterly report or general advisory is not automatically a malicious domain/phone indicator. Only a clearly specified, independently validated indicator should enter an indicator feed, and only after the source's terms permit it.

## Kenyan data protection

- Office of the Data Protection Commissioner: https://www.odpc.go.ke/
- ODPC FAQ: https://www.odpc.go.ke/faqs/
- ODPC Data Protection Compliance: https://www.odpc.go.ke/data-protection-compliance/
- Data Protection Act, 2019 and related regulations are linked from the official ODPC/legal resources.

ODPC materials identify phone numbers, location, online identifiers, photographs and audio/video as personal data. The FAQ describes an exemption threshold involving turnover/revenue and employee count, but also lists processing purposes/categories that are not exempt, including crime-prevention/prosecution-related activity. Do not infer that Toroka qualifies for an exemption; obtain qualified Kenyan counsel/ODPC guidance on roles, lawful basis, registration, notices, DPIA, retention, user rights and international transfers.

## Standards

- OASIS STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/
- OASIS TAXII 2.1: https://docs.oasis-open.org/cti/taxii/v2.1/

Phase 7 implements a **limited STIX 2.1 indicator-pattern subset**. It does not implement full STIX object semantics or a TAXII client. Do not describe it as full STIX/TAXII support.

## Design decisions

1. Keep every provider disabled until terms, scope and permission are checked.
2. Separate internal checking, end-user display and redistribution rights.
3. Use source timestamps and expiry; retain last-known-good snapshots on failures but label them stale.
4. Use leases, retry/backoff and circuit breaking for provider reliability.
5. Share Phase 3 HMAC entity identity only with the same stable server-side key.
6. Keep unreviewed reports private, independently corroborate source families and support correction/expiry.
7. Treat English/Kiswahili/Sheng rule results as signals. Campaign-level evaluation and language subgroup metrics are mandatory; tests are not production accuracy claims.
8. Keep Phase 2 final verdict authority; no automatic public allegations or enforcement actions.
