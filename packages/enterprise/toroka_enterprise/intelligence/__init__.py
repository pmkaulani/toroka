"""Toroka Enterprise — Cross-System Fraud Intelligence & Insider-Risk Correlation.

Provides entity resolution, temporal correlation windows, explainable risk signals,
competing hypotheses, and investigation bundling without automated accusations.
"""
from __future__ import annotations

from .entities import EntityRef, EntityType, Relationship
from .events import IntelligenceEvent
from .correlation import CorrelationWindow, build_window, events_in_window
from .signals import CorrelationSignal, SignalSeverity
from .rules import (
    employee_access_before_sensitive_change,
    privileged_login_before_unusual_transaction,
    role_change_before_sensitive_activity,
    employee_activity_before_reversal_or_closure,
    customer_complaint_correlated_employee_activity,
    authentication_anomaly_with_sensitive_action,
    run_all_correlation_rules,
)
from .hypotheses import HypothesisStatus, InvestigationHypothesis
from .investigation import InvestigationBundle
from .summary import InvestigationSummary, summarize

__all__ = [
    "EntityType",
    "EntityRef",
    "Relationship",
    "IntelligenceEvent",
    "CorrelationWindow",
    "build_window",
    "events_in_window",
    "SignalSeverity",
    "CorrelationSignal",
    "employee_access_before_sensitive_change",
    "privileged_login_before_unusual_transaction",
    "role_change_before_sensitive_activity",
    "employee_activity_before_reversal_or_closure",
    "customer_complaint_correlated_employee_activity",
    "authentication_anomaly_with_sensitive_action",
    "run_all_correlation_rules",
    "HypothesisStatus",
    "InvestigationHypothesis",
    "InvestigationBundle",
    "InvestigationSummary",
    "summarize",
]
