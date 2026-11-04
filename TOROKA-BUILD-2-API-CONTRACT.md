# Build 2 API response contract (embedded in existing check response)

Build 2 does not add a new public endpoint. When `ENABLE_DOMAIN_INTELLIGENCE=1`, the existing `investigation_intelligence` object returned through the established `/v1/checks` flow gains these optional properties:

```json
{
  "domain_infrastructure": [
    {
      "domain": "example.com",
      "status": "checked",
      "providers": [
        {"provider": "Google Public DNS (DoH)", "operation": "dns_records", "status": "checked"},
        {"provider": "Authoritative RDAP via IANA bootstrap", "operation": "domain_registration_and_nameservers", "status": "checked"},
        {"provider": "SSLMate Cert Spotter CT", "operation": "certificate_transparency_search", "status": "not_configured"}
      ],
      "dns": {"records": [], "addresses": [], "dnssec_validated": false},
      "rdap": {"events": {}, "registrar": null, "nameservers": []},
      "ip_observations": [],
      "certificate_transparency": {"status": "not_configured", "issuances": []},
      "evidence": [],
      "interpretation_note": "Infrastructure links are contextual observations, not ownership or fraud proof."
    }
  ],
  "official_registry_checks": [
    {
      "registry": "Business Registration Service (BRS)",
      "status": "manual_verification_required",
      "automated_lookup_performed": false,
      "official_portal_url": "https://brs.ecitizen.go.ke/",
      "what_to_verify": []
    }
  ],
  "evidence_graph": {"version": "evidence-graph-v2", "nodes": [], "edges": []}
}
```

Actual records are bounded and omitted when unavailable. `status` values distinguish `checked`, `checked_no_records`, `checked_no_match`, `not_configured`, `not_checked`, `rate_limited` and `failed`; a provider failure is never interpreted as a clean result.

Every infrastructure evidence record uses `verified=false`, `polarity=context` and `claim_status=automated_infrastructure_observation`. Graph edges are contextual and point back to the supporting evidence ID.
