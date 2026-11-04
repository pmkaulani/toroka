# Toroka Build 3 — Changelog

## Added
- NEA public-register CSV parser with strict official-source validation, field minimisation, date/status interpretation, deduplication, and per-snapshot/content hashing.
- Persistent NEA snapshot and entry tables, with freshness labels and superseded snapshot history.
- Public NEA search endpoint with precise snapshot limitations.
- Moderator-only BRS record review endpoint storing only a keyed registration identifier, masked number, minimum entity fields and evidence digest.
- Moderator-only website/social/email-domain association review and revocation.
- Reverse entity matching by reviewed website, social profile or email domain.
- Additive entity verification context in normal `/v1/checks` investigations.
- English and Kiswahili result panels for NEA/BRS status and digital associations.
- Alembic migration `0004` and focused Build 3 test coverage.

## Security and correctness
- NEA import restricted to exact official source URLs, HTTPS, default port and no query/fragment.
- 5 MB and 5,000-row import caps; original CSV is not retained.
- Full email addresses are reduced to domains; email local-parts are not stored.
- BRS registration numbers are HMAC-indexed and masked in responses; original numbers are not stored.
- BRS evidence URL restricted to official BRS/eCitizen hosts.
- Moderator confirmation required for each digital association; associations are time-bounded and revocable.
- Social/email links require evidence from an already reviewed official website.
- Build 3 only appends evidence context; it does not change the deterministic risk label.
- Generic TLD suffixes are no longer confused with shared-hosting domains; shared platform hosts and selected public-suffix roots are blocked.

## Not included
- No BRS/eCitizen credentials, private API, or automated scraping.
- No direct NEA API or always-on downloader; official CSV import is manual.
- No assertion that registration proves representative identity or offer legitimacy.
