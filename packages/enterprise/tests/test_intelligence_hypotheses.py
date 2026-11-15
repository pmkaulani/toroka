"""Tests for investigation hypotheses, bundles, competing explanations, and summary generation."""
from __future__ import annotations

from datetime import datetime, timezone
import pytest

from toroka_enterprise.intelligence.entities import EntityRef, EntityType, Relationship
from toroka_enterprise.intelligence.events import IntelligenceEvent
from toroka_enterprise.intelligence.hypotheses import HypothesisStatus, InvestigationHypothesis
from toroka_enterprise.intelligence.investigation import InvestigationBundle
from toroka_enterprise.intelligence.signals import CorrelationSignal, SignalSeverity
from toroka_enterprise.intelligence.summary import summarize


def test_investigation_bundle_and_competing_hypotheses():
    bundle = InvestigationBundle(
        investigation_id="inv-001",
        installation_id="bank-inst-1",
        anchor_event_ids=["evt-anchor-1"],
    )

    t0 = datetime(2026, 11, 16, 10, 0, 0, tzinfo=timezone.utc)
    event = IntelligenceEvent(
        installation_id="bank-inst-1",
        event_id="evt-anchor-1",
        event_type="customer_record_access",
        event_time=t0,
        actor="emp_01",
    )
    bundle.add_event(event)
    assert len(bundle.events) == 1

    # Signal
    sig = CorrelationSignal(
        signal_id="sig-01",
        signal_type="access_before_sensitive_change",
        severity=SignalSeverity.MEDIUM,
        title="Access preceded profile change",
        explanation="Employee accessed customer record shortly before beneficiary change.",
        event_ids=("evt-anchor-1",),
        confidence=0.82,
        alternative_explanations=("Legitimate service desk ticket.",),
        missing_evidence=("customer_service_ticket",),
    )
    bundle.add_signal(sig)

    # Competing Hypotheses
    h1 = InvestigationHypothesis(
        hypothesis_id="H1-unauthorized-action",
        title="Unauthorized Employee Account Manipulation",
        description="Employee acted outside authorized branch protocol for personal gain.",
        status=HypothesisStatus.OPEN,
        supporting_signal_ids=("sig-01",),
        confidence=0.45,
    )
    h2 = InvestigationHypothesis(
        hypothesis_id="H2-legitimate-service",
        title="Legitimate Customer Service Activity",
        description="Employee acted on customer instructions received in person at branch.",
        status=HypothesisStatus.OPEN,
        contradicting_signal_ids=(),
        confidence=0.55,
        investigator_note="Awaiting ticket logs from CRM team.",
    )
    bundle.add_hypothesis(h1)
    bundle.add_hypothesis(h2)

    assert len(bundle.hypotheses) == 2
    assert bundle.hypotheses[0].hypothesis_id == "H1-unauthorized-action"
    assert bundle.hypotheses[1].hypothesis_id == "H2-legitimate-service"

    # Summarize bundle
    summary = summarize(bundle)
    assert summary.requires_human_review is True
    assert summary.confidence == 0.82
    assert "Access preceded profile change" in summary.supporting_facts
    assert "Legitimate service desk ticket." in summary.alternative_explanations
    assert "customer_service_ticket" in summary.missing_evidence


def test_bundle_installation_isolation():
    bundle = InvestigationBundle(
        investigation_id="inv-002",
        installation_id="bank-inst-alpha",
    )
    t0 = datetime(2026, 11, 16, 10, 0, 0, tzinfo=timezone.utc)
    alien_event = IntelligenceEvent(
        installation_id="bank-inst-beta",
        event_id="alien-evt-01",
        event_type="login",
        event_time=t0,
    )

    with pytest.raises(ValueError, match="installation mismatch"):
        bundle.add_event(alien_event)

    alien_rel = Relationship(
        installation_id="bank-inst-beta",
        source=EntityRef("bank-inst-beta", EntityType.EMPLOYEE, "emp_1"),
        target=EntityRef("bank-inst-beta", EntityType.ACCOUNT, "acc_1"),
        relationship_type="accessed",
    )
    with pytest.raises(ValueError, match="installation mismatch"):
        bundle.add_relationship(alien_rel)


def test_empty_investigation_summary():
    bundle = InvestigationBundle(
        investigation_id="inv-empty",
        installation_id="bank-inst-1",
    )
    summary = summarize(bundle)
    assert summary.requires_human_review is False
    assert summary.confidence == 0.0
    assert "No correlated risk signal" in summary.finding
