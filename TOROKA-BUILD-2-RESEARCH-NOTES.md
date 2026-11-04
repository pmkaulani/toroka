# Toroka Build 2 — Provider and standards notes

These notes describe the implementation choices. They are not a claim that a provider has granted Toroka commercial rights; operators must verify current contracts and permitted use before deployment.

## RDAP bootstrap

- IANA publishes RDAP bootstrap registries for domain names, IPv4, IPv6 and ASNs.
- RFC 9224 defines the RDAP bootstrap discovery mechanism and matching rules. Toroka chooses the most-specific matching DNS suffix or IP prefix rather than querying one hard-coded registry.
- References: https://data.iana.org/rdap/ and https://www.rfc-editor.org/rfc/rfc9224.html

## DNS over HTTPS

- Google Public DNS documents a JSON API at `https://dns.google/resolve` for DNS-over-HTTPS lookups.
- The implementation limits queries to A, AAAA, MX, NS, CAA, TXT and DMARC TXT; it redacts arbitrary TXT data.
- The DNSSEC display is based on the resolver's AD bit. It is not an independent cryptographic validation performed by Toroka.
- Reference: https://developers.google.com/speed/public-dns/docs/doh/json

## IP to ASN

- Team Cymru documents an IP-to-origin-ASN mapping service that returns BGP prefix, ASN and registry context.
- Toroka verifies the returned prefix contains the queried address. A registry country code is not server geolocation.
- Reference: https://www.team-cymru.com/ip-asn-mapping
- RIPEstat's Data API is not used as the default commercial provider because its usage terms describe non-commercial use; obtain separate permission or select another licensed provider before using it commercially.
- Reference: https://stat.ripe.net/docs/data_api

## Certificate Transparency

- SSLMate Cert Spotter provides an API for searching logged certificate issuances and associated DNS names.
- Its unauthenticated limited querying is for personal/evaluation use; production use requires an account/key and a plan that permits the intended operational/commercial usage. API access alone should not be treated as a blanket redistribution licence.
- Reference: https://sslmate.com/help/certspotter/api/
- Certificate Transparency is a public append-only certificate logging/audit ecosystem. A logged certificate name is not proof that the host is currently active or that the subject controls a particular business.
- Reference: https://www.rfc-editor.org/rfc/rfc9162.html

## Kenyan official checks

- BRS official services are available through https://brs.go.ke/ and its eCitizen service https://brs.ecitizen.go.ke/ . Build 2 provides a manual workflow; it does not scrape or claim automated BRS verification.
- NEA's official recruitment-agency verification portal is https://www.diaspora.go.ke/verify . Users should check current licence status and validity on the date of lookup.
- A business name/company registration or recruitment licence does not establish that a particular social-media account or job advertiser is controlled by that entity.

## Privacy, security and scope

- Provider requests use a normalized hostname, not user-submitted URL paths, query strings, credentials or fragment values.
- Public IP lookup only: non-global addresses are excluded from ASN/RIR requests.
- Redirects are disabled for RDAP/CT provider calls. RDAP endpoints are selected from IANA's HTTPS bootstrap data.
- No port scanning, active website crawling, arbitrary URL submission or internal-network fetch was added.
- CT search is disabled unless a provider key is explicitly configured.
- Build 2 does not infer physical location from an IP registration country.
