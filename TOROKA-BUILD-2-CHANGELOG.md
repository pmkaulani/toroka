# Build 2 changelog

## Added
- Bounded passive DNS, RDAP, IP/ASN and Certificate Transparency intelligence.
- IANA bootstrap-based authoritative RDAP service selection for domains, IPs and ASNs.
- Team Cymru BGP origin lookup with prefix containment validation.
- Certificate Transparency search requiring an explicitly configured API key.
- BRS and NEA official manual verification instructions in the normal investigation response.
- Evidence graph v2 infrastructure nodes and contextual relationships.
- English and Kiswahili UI for domain infrastructure and registry guidance.
- Opt-in settings and mocked connector/integration tests.

## Preserved
- Existing Build 1 evidence graph, Places discovery, historical urlscan.io search, guest chat and branding.

## Safety boundaries
- At most two infrastructure domains per investigation.
- Only submitted domains and seller-published outbound links are eligible for infrastructure lookup.
- No raw URL paths or query tokens are sent to infrastructure providers.
- Shared infrastructure is not common-ownership proof and cannot by itself produce a fraud verdict.
