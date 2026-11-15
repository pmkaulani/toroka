"""Tests for baseline poisoning protection and auditable admission policies."""
from __future__ import annotations

import pytest
from toroka_enterprise.intelligence.baseline_guard import (
    BaselineAdmissionDecision,
    should_enter_baseline,
)
from toroka_enterprise.intelligence.deviation import calculate_deviation


def test_admission_policy_standard_gates():
    # Verified, benign production event
    dec_ok = should_enter_baseline(
        event_is_verified=True,
        event_is_under_investigation=False,
        event_is_correction=False,
        event_is_test_data=False,
        event_is_compromised=False,
    )
    assert dec_ok.accepted
    assert dec_ok.reason == "eligible"

    # Unverified event
    dec_unverified = should_enter_baseline(
        event_is_verified=False,
        event_is_under_investigation=False,
        event_is_correction=False,
        event_is_test_data=False,
    )
    assert not dec_unverified.accepted
    assert dec_unverified.reason == "event_not_verified"

    # Event under investigation
    dec_investigation = should_enter_baseline(
        event_is_verified=True,
        event_is_under_investigation=True,
        event_is_correction=False,
        event_is_test_data=False,
    )
    assert not dec_investigation.accepted
    assert dec_investigation.reason == "event_under_investigation"

    # Ledger correction event
    dec_correction = should_enter_baseline(
        event_is_verified=True,
        event_is_under_investigation=False,
        event_is_correction=True,
        event_is_test_data=False,
    )
    assert not dec_correction.accepted
    assert dec_correction.reason == "correction_event"

    # Synthetic / test data
    dec_test = should_enter_baseline(
        event_is_verified=True,
        event_is_under_investigation=False,
        event_is_correction=False,
        event_is_test_data=True,
    )
    assert not dec_test.accepted
    assert dec_test.reason == "test_data"

    # Explicitly flagged compromised activity
    dec_comp = should_enter_baseline(
        event_is_verified=True,
        event_is_under_investigation=False,
        event_is_correction=False,
        event_is_test_data=False,
        event_is_compromised=True,
    )
    assert not dec_comp.accepted
    assert dec_comp.reason == "compromised_event"


def test_adversarial_gradual_poisoning_attempt():
    """Adversarial Test 1: Attacker attempts to slowly increase daily transaction values

    to poison the baseline into accepting high values as 'normal'.
    Unverified or flagged events are strictly rejected from entering the baseline.
    """
    initial_baseline = [100.0, 105.0, 95.0, 100.0, 110.0, 90.0, 100.0, 105.0, 95.0, 100.0]
    
    # Attacker tries to inject a sequence of escalating transactions: 200, 350, 500, 800...
    escalating_attempts = [200.0, 350.0, 500.0, 800.0, 1500.0]
    accepted_baseline = list(initial_baseline)

    for val in escalating_attempts:
        # Check against existing baseline
        dev = calculate_deviation(val, accepted_baseline)
        
        # When an anomaly is detected, the event becomes subject to investigation
        event_under_investigation = dev.is_anomalous

        decision = should_enter_baseline(
            event_is_verified=True,
            event_is_under_investigation=event_under_investigation,
            event_is_correction=False,
            event_is_test_data=False,
        )

        if decision.accepted:
            accepted_baseline.append(val)
        else:
            # Poisoning attempt rejected!
            assert decision.reason == "event_under_investigation"

    # Verify baseline was protected and did not admit the escalating attacks
    assert len(accepted_baseline) == len(initial_baseline)
    assert max(accepted_baseline) == 110.0


def test_adversarial_replayed_suspicious_activity():
    """Adversarial Test 2: Replayed suspicious activity attached to an open case

    must not enter baseline distribution.
    """
    replayed_event_dec = should_enter_baseline(
        event_is_verified=True,
        event_is_under_investigation=True,  # attached to active casework
        event_is_correction=False,
        event_is_test_data=False,
    )
    assert not replayed_event_dec.accepted
    assert replayed_event_dec.reason == "event_under_investigation"


def test_adversarial_compromised_account_activity():
    """Adversarial Test 7: Compromised account generates activity that mimics employee behavior.

    When identified as compromised, admission must be refused.
    """
    compromised_dec = should_enter_baseline(
        event_is_verified=True,
        event_is_under_investigation=False,
        event_is_correction=False,
        event_is_test_data=False,
        event_is_compromised=True,
    )
    assert not compromised_dec.accepted
    assert compromised_dec.reason == "compromised_event"
