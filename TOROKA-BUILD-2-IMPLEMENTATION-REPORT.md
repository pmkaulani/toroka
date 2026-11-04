# Toroka Build 2 — Domain, Infrastructure & Official Identity Intelligence

**Status:** Implemented in the Build 1 source tree; local regression-tested.  
**Build baseline:** Uploaded `Toroka(5).zip` (Build 1).  
**Feature switch:** `ENABLE_DOMAIN_INTELLIGENCE=1` (off by default).

## What changed

Build 1 already had a basic RDAP/domain-age connector. Build 2 expands the normal `/v1/checks` investigation path with a bounded passive-infrastructure bundle instead of duplicating that old RDAP connector.

### 1. Domain registration (RDAP)

- Downloads IANA RDAP bootstrap registries for DNS, IPv4, IPv6 and ASN.
- Selects authoritative RDAP services by longest matching domain suffix, IP prefix or ASN range.
- Retrieves a minimal set of public domain registration events, registrar label where published, nameservers and registry statuses.
- For public IPs, retrieves the RIR network allocation object; for a BGP origin ASN, it can retrieve the ASN allocation object.
- Does not collect registrant names, postal addresses, emails, phone numbers or other RDAP contact data.

### 2. DNS and DNSSEC observations

- Queries A, AAAA, MX, NS, CAA, TXT and `_dmarc` TXT records through Google Public DNS JSON DoH.
- Returns public IPs for ASN/RIR lookup only; private and special-use answers are never sent to those services.
- Redacts TXT values that may contain verification tokens, DKIM key material or arbitrary secrets. SPF and DMARC are summarized as policy observations.
- Distinguishes a valid empty/NXDOMAIN result from resolver errors such as SERVFAIL.
- Reports DNSSEC only when the resolver response includes the authenticated-data flag; this is a resolver observation, not a separate Toroka DNSSEC validation implementation.

### 3. IP and ASN routing context

- Uses Team Cymru's documented IP-to-origin-ASN service through DNS-over-HTTPS.
- Verifies that the returned BGP prefix actually contains the queried IP.
- Uses IANA bootstrap to fetch corresponding RIR IP/ASN RDAP registration context.
- Labels registry country as allocation metadata, never as the physical location of a server or business.

### 4. Certificate Transparency

- Integrates SSLMate Cert Spotter issuance search.
- Does not perform the lookup unless `CERTSPOTTER_API_KEY` is configured.
- `DOMAIN_INTEL_INCLUDE_SUBDOMAINS=0` is the default to limit query breadth; subdomain expansion is separately opt-in.
- Enforces exact DNS-name or dot-boundary subdomain matching, avoiding false matches such as `badexample.com` for `example.com`.
- A CT entry means a name appeared in a logged certificate; it does not mean the name is active, controlled by the seller, or malicious.

### 5. Main investigation and evidence graph

- Calls infrastructure lookup only for the submitted domain, or for a domain explicitly linked from a target-controlled public profile/page.
- Maximum of two infrastructure domains per investigation, even when several targets are extracted.
- Adds DNS, RDAP, IP/ASN and CT observations to the same `investigation_intelligence.evidence` array used by the existing chat result.
- Adds contextual graph nodes for IPs, ASNs, prefixes, nameservers, mail exchanges and certificate names.
- Infrastructure relationships always use `strength=context`; no shared IP, nameserver, ASN or CT result can establish common ownership or fraud.
- Cache identity includes feature state, CT key presence and subdomain mode, so an old disabled-provider result is not reused after configuration changes.

### 6. Official Kenyan verification guidance

For shop and job investigations, the result now includes official verification steps:

- **BRS/eCitizen:** manual search of the exact legal or registered business name and appropriate official company record.
- **NEA:** manual verification of recruitment agency licence status and validity for job/recruitment investigations.

These are explicitly labelled `manual_verification_required`; Toroka does not scrape either registry or claim an automated lookup happened. Registration/licence records must still be matched to the exact seller/account or job advertisement.

### 7. User interface

- English and Kiswahili evidence panels display RDAP registration dates/registrar, DNS records, IP/ASN context, CT observations, provider status and official registry instructions.
- Existing Toroka logo, guest chat flow, Google Places shop discovery and urlscan.io historical-domain search are preserved.
- No new user account requirement is introduced.

## Configuration

Add these entries to the backend `.env` (do not commit `.env`):

```dotenv
ENABLE_DOMAIN_INTELLIGENCE=1
CERTSPOTTER_API_KEY=
DOMAIN_INTEL_INCLUDE_SUBDOMAINS=0
```

`ENABLE_DOMAIN_INTELLIGENCE=0` is the default. The Cert Spotter key is optional; without it the CT provider returns `not_configured` and does not make a request. Before commercial/production use of CT search, obtain a plan/credential that permits this use and confirm display, caching, rate and redistribution terms.

## Files changed

- `packages/connectors/ssi_connectors/domain_intelligence.py` (new)
- `services/api/app/config.py`
- `services/api/app/investigation_intelligence.py`
- `services/api/app/evidence_graph.py`
- `services/api/app/static/app.js`
- `services/api/app/static/i18n.js`
- `services/api/app/static/styles.css`
- `.env.example`
- `services/api/tests/test_build2_domain_intelligence.py` (new)

## Verification

- API + connector tests: **525 passed**.
- Rules/ML tests: **202 passed**.
- Combined reported total: **727 passed**.
- JavaScript syntax: `node --check` passed for `app.js` and `i18n.js`.
- Python compilation: `compileall` passed for connector and API modules.
- Provider tests use mocked HTTP responses; no live provider credentials or live service lookups were used.
- `packages/rules/tests/test_robustness.py` was not run because the environment does not have the optional `hypothesis` dependency installed. Browser-based end-to-end testing was not run.

Existing FastAPI/Alembic deprecation warnings remain; these are unrelated to Build 2 and did not fail tests.

## Install

1. Back up the current project and keep the original `.env` private.
2. Extract the full updated-project archive to a new folder, or apply the source patch over the existing project root.
3. Merge the three Build 2 environment entries into the backend `.env` manually. Do not overwrite the existing API keys or secrets.
4. Start with `ENABLE_DOMAIN_INTELLIGENCE=0` if you want to deploy the code before enabling provider lookups. Set it to `1` only after reviewing provider terms and operational budget.
5. Configure a permitted Cert Spotter plan/key only when approved. Keep subdomain expansion disabled initially.
6. Restart the backend and test a disposable public domain, then test a social profile that explicitly links to a public domain.

Run the relevant tests from the `smart-scam-identifier` project root:

```bash
pytest -q services/api/tests packages/connectors/tests
pytest -q packages/rules/tests --ignore=packages/rules/tests/test_robustness.py
node --check services/api/app/static/app.js
node --check services/api/app/static/i18n.js
```
