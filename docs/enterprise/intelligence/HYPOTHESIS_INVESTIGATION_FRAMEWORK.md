# Toroka Enterprise — Competing Hypothesis Investigation Framework

## 1. Overview & Forensic Methodology

In regulatory compliance and financial-crime investigations, jumping to a single conclusion produces confirmation bias and unjust disciplinary actions.

Toroka adopts the **Analysis of Competing Hypotheses (ACH)** standard. For any correlated case, Toroka supports creating and simultaneously testing mutually exclusive hypotheses:

```
                              [Case File Under Review]
                                          │
            ┌─────────────────────────────┼─────────────────────────────┐
            ▼                             ▼                             ▼
    [Hypothesis A]                 [Hypothesis B]                 [Hypothesis C]
  Unauthorized Action          Legitimate Client Service       Compromised Session
  Status: OPEN                 Status: OPEN                   Status: OPEN
  Supporting Signals: 2        Supporting Signals: 0          Supporting Signals: 1
  Contradicting Signals: 0     Contradicting Signals: 1       Contradicting Signals: 0
  Confidence: 0.50             Confidence: 0.50               Confidence: 0.20
```

---

## 2. Hypothesis Lifecycle & Statuses

| Status | Description | Required Criteria |
|---|---|---|
| `OPEN` | Initial unverified hypothesis | Plausible explanation based on preliminary event timeline |
| `SUPPORTED` | Corroborated by verified evidence | Signals linked; missing evidence retrieved and confirms hypothesis |
| `WEAKENED` | Contradicted by new evidence | Verified document (e.g. signed customer ticket) refutes suspicion |
| `DISPROVEN` | Formally ruled out | Concrete proof (e.g. branch biometric entry log confirms client presence) |

---

## 3. Human-in-the-Loop Closure Requirement

Under no circumstances can a hypothesis transition to `SUPPORTED` or `DISPROVEN` solely through algorithmic automation.
- Hypotheses can only be created, modified, or closed by authenticated Investigators (`ROLE_INVESTIGATOR`) and Authorisers (`ROLE_AUTHORISER`).
- Every update generates an immutable `AuditRecord` in the cryptographic audit hash chain.
