# Baseline Poisoning Protection

## 1. Threat Model: Baseline Shifting Attacks

In an adaptive detection system, an adversary (or colluding insider) may attempt to **poison the behavioral baseline** by gradually escalating transaction frequency or volume over weeks. If the system naively incorporates all ingested events into rolling averages, the baseline slowly shifts upward until large fraudulent transactions no longer trigger anomalies.

```text
Volume
  ▲
  │                                    *  Target Fraudulent Transaction
  │                              *  *     (Admitted as "Normal" if Unchecked)
  │                        *  *
  │                  *  *
  │            *  *
  │  *  *  *  * (Baseline gradually shifted by attacker)
  └────────────────────────────────────────────────────────► Time
```

---

## 2. Auditable Baseline Admission Policy

To prevent baseline poisoning, Toroka Enterprise implements an explicit admission gate: `should_enter_baseline()`. An incoming banking event can **never** enter historical baseline distributions unless it passes all five verification checks:

```python
def should_enter_baseline(
    *,
    event_is_verified: bool,
    event_is_under_investigation: bool,
    event_is_correction: bool,
    event_is_test_data: bool,
    event_is_compromised: bool = False,
) -> BaselineAdmissionDecision: ...
```

### Rejection Gates

1. **`event_not_verified`**:
   Unverified transactions, provisional ledger entries, and unacknowledged switch packets are rejected until confirmed by authoritative systems of record.
2. **`event_under_investigation`**:
   Any event attached to an active investigation, open case, or preliminary alert is permanently quarantined from baseline distributions until resolved and cleared.
3. **`correction_event`**:
   Accounting adjustments, reversal entries, and manual reclassifications reflect corrections rather than standard behavioral flow and are excluded.
4. **`test_data`**:
   Synthetic load-testing records, integration sandbox events, and UAT artifacts are flagged and rejected.
5. **`compromised_event`**:
   Events identified as originating from compromised accounts, hijacked sessions, or credential-stuffing attacks are barred.

---

## 3. Auditable Admission Log

Every admission decision is immutably recorded in `enterprise_baseline_admissions` with:
- `installation_id`
- `event_id`
- `subject_id`
- `accepted` (True / False)
- `reason` (e.g. `eligible`, `event_under_investigation`, `event_not_verified`)
- `created_at` timestamp

This ensures that model auditors and banking regulators can inspect exactly which transactions shaped an employee's behavioral profile.
