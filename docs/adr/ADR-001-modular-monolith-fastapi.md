# ADR-001: Modular monolith in Python (FastAPI) with a pure rules package

**Status:** Proposed
**Date:** 2026-10-20
**Deciders:** Kaulani (founder). Add the first engineer or advisor when there is one.

## Context
Solo founder, no users yet, one wedge to prove first (official-source verification plus a rules-based red-flag reader; see the blueprint review, section 2). The blueprint recommends a modular monolith with background workers. Constraints: cheap to run, testable without network access, low-bandwidth Kenyan users, privacy by default, and a rules engine that must stay auditable.

## Decision
Build a modular monolith. `packages/rules` is pure Python with no I/O and holds all assessment logic. `services/api` is a thin FastAPI layer. Workers (OCR, URL fetching) are added later as separate processes behind a queue. The web client is a separate Next.js PWA when the API contract settles.

## Options Considered

### Option A: Modular monolith, Python (FastAPI) + pure rules package
| Dimension | Assessment |
|-----------|------------|
| Complexity | Low |
| Cost | Low: one deployable, one database |
| Scalability | Enough for the pilot; rules are stateless so horizontal scaling is easy |
| Team familiarity | Frontend strong (React MVPs on Vercel). Python/FastAPI comfort is **unconfirmed** |

**Pros:** best ecosystem for OCR and text processing later; rules package is trivially unit-tested and can be reused by workers; matches the blueprint.
**Cons:** two languages once the PWA exists; needs a host that is not Vercel-only.

### Option B: Next.js full-stack (TypeScript, API routes on Vercel, hosted Postgres)
| Dimension | Assessment |
|-----------|------------|
| Complexity | Low |
| Cost | Low at pilot scale; function time limits and cold starts matter for OCR and fetching |
| Scalability | Good for web; awkward for long-running workers |
| Team familiarity | High |

**Pros:** one language, fastest path if Python is unfamiliar.
**Cons:** OCR, SSRF-safe fetching and queue workers sit awkwardly in serverless; rules logic would live inside a web framework unless carefully separated.

### Option C: Microservices
Rejected: operational cost with no user to justify it.

## Trade-off Analysis
The real trade is **familiarity (B) against fit for later workers (A)**. The rules package has no framework dependency, so the cost of being wrong is small: it can be ported to TypeScript in days if Python proves a drag, because the golden-case tests define the behaviour.

## Consequences
- Easier: auditing rules, running tests offline, adding workers later.
- Harder: deploying (needs a container host), and keeping two toolchains.
- Revisit: if Python slows you down after the first two weeks of building, switch to Option B and keep the golden cases as the contract.

## Action Items
1. [ ] Confirm Python/FastAPI comfort (or choose Option B).
2. [ ] Pick a host and region (ADR-004, open: cost, latency from Nairobi, data-protection implications).
3. [ ] Replace the in-memory store with Postgres and migrations.
4. [ ] Add CI: lint plus `pytest` on every push; golden cases gate rule changes.
