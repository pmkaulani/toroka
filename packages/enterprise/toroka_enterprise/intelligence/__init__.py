"""Toroka Enterprise — Cross-System Fraud Intelligence & Insider-Risk Correlation.

Provides entity resolution, temporal correlation windows, explainable risk signals,
competing hypotheses, behavioral baselines, anomaly detection, and investigation
prioritization without automated accusations.
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

# Phase 6 additions: Baselines, Statistics, Deviations, Anomalies, Prioritization, Governance
from .baselines import BaselineDimension, BaselineWindow, MaturityState
from .statistics import BaselineStatistics, calculate_statistics
from .deviation import DeviationResult, median, calculate_deviation
from .profiles import BehavioralProfile
from .anomalies import AnomalySeverity, BehavioralAnomaly
from .scoring import severity_from_deviation
from .baseline_guard import BaselineAdmissionDecision, should_enter_baseline
from .governance import ModelStatus, DetectionMethod
from .detection import DetectionContext, DetectionResult, Detector
from .sources import (
    SourceSystem,
    SourceReliability,
    DEFAULT_SOURCE_RELIABILITIES,
    get_source_reliability,
)
from .prioritization import InvestigationPriority, calculate_priority

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
    # Phase 6
    "BaselineDimension",
    "BaselineWindow",
    "MaturityState",
    "BaselineStatistics",
    "calculate_statistics",
    "DeviationResult",
    "median",
    "calculate_deviation",
    "BehavioralProfile",
    "AnomalySeverity",
    "BehavioralAnomaly",
    "severity_from_deviation",
    "BaselineAdmissionDecision",
    "should_enter_baseline",
    "ModelStatus",
    "DetectionMethod",
    "DetectionContext",
    "DetectionResult",
    "Detector",
    "SourceSystem",
    "SourceReliability",
    "DEFAULT_SOURCE_RELIABILITIES",
    "get_source_reliability",
    "InvestigationPriority",
    "calculate_priority",
]
