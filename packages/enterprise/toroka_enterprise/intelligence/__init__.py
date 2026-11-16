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

# Phase 7 additions: Attack Reconstruction Engine, Transitions, Change Vector, Attack Path, Contradictions, Evidence Debt, Scenarios
from .reconstruction import ReconstructionStep, AttackReconstruction
from .transitions import StateTransition, identify_transition, extract_transitions_from_events
from .change_vector import ChangeVector, build_change_vector
from .attack_path import AttackPathNode, AttackPathEdge, AttackPath, build_attack_path_from_relationships
from .contradictions import ContradictionSeverity, EvidenceContradiction, detect_evidence_contradictions
from .evidence_completeness import EvidenceRequirement, EvidenceCompleteness, calculate_evidence_completeness
from .reconstruction_engine import reconstruct
from .scenarios import InvestigationScenario, generate_competing_scenarios

# Phase 8 additions: Counterfactual Investigation Simulator
from .simulation import (
    CandidateDetection,
    CaseOutcome,
    MetricsDelta,
    OutcomeLabel,
    ReplayObservation,
    SimulatedDetection,
    SimulationComparisonResult,
    SimulationMetrics,
    SimulationRunResult,
    SimulationStrategy,
    calculate_metrics,
    calculate_metrics_delta,
    compare_strategies,
    make_rule_runner,
    replay_strategy,
    resolve_rule_name,
    run_strategy_detectors,
)

# Phase 9 additions: Fraud DNA & Institutional Memory Engine
from .memory import (
    CaseFingerprint,
    FingerprintEvidence,
    build_case_fingerprint,
    EVENT_FEATURES,
    EXPECTED_SOURCE_SYSTEMS,
    SEQUENCE_RULES,
    CaseSimilarity,
    FeatureComparison,
    compare_fingerprints,
    feature_weight,
    PatternStatus,
    InstitutionalPattern,
    PatternValidationPolicy,
    PatternValidationResult,
    PatternReview,
    evaluate_pattern,
    approve_pattern,
    reject_pattern,
    suspend_pattern,
    reinstate_pattern,
    retire_pattern,
    ControlWeaknessType,
    ControlWeaknessEvidence,
    CONTROL_WEAKNESS_DESCRIPTIONS,
    detect_control_weaknesses,
    PatternMatch,
    retrieve_similar_historical_cases,
    match_case_against_patterns,
    discover_candidate_patterns,
)

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
    # Phase 7
    "ReconstructionStep",
    "AttackReconstruction",
    "StateTransition",
    "identify_transition",
    "extract_transitions_from_events",
    "ChangeVector",
    "build_change_vector",
    "AttackPathNode",
    "AttackPathEdge",
    "AttackPath",
    "build_attack_path_from_relationships",
    "ContradictionSeverity",
    "EvidenceContradiction",
    "detect_evidence_contradictions",
    "EvidenceRequirement",
    "EvidenceCompleteness",
    "calculate_evidence_completeness",
    "reconstruct",
    "InvestigationScenario",
    "generate_competing_scenarios",
    # Phase 8
    "CandidateDetection",
    "CaseOutcome",
    "MetricsDelta",
    "OutcomeLabel",
    "ReplayObservation",
    "SimulatedDetection",
    "SimulationComparisonResult",
    "SimulationMetrics",
    "SimulationRunResult",
    "SimulationStrategy",
    "calculate_metrics",
    "calculate_metrics_delta",
    "compare_strategies",
    "make_rule_runner",
    "replay_strategy",
    "resolve_rule_name",
    "run_strategy_detectors",
    # Phase 9
    "CaseFingerprint",
    "FingerprintEvidence",
    "build_case_fingerprint",
    "EVENT_FEATURES",
    "EXPECTED_SOURCE_SYSTEMS",
    "SEQUENCE_RULES",
    "CaseSimilarity",
    "FeatureComparison",
    "compare_fingerprints",
    "feature_weight",
    "PatternStatus",
    "InstitutionalPattern",
    "PatternValidationPolicy",
    "PatternValidationResult",
    "PatternReview",
    "evaluate_pattern",
    "approve_pattern",
    "reject_pattern",
    "suspend_pattern",
    "reinstate_pattern",
    "retire_pattern",
    "ControlWeaknessType",
    "ControlWeaknessEvidence",
    "CONTROL_WEAKNESS_DESCRIPTIONS",
    "detect_control_weaknesses",
    "PatternMatch",
    "retrieve_similar_historical_cases",
    "match_case_against_patterns",
    "discover_candidate_patterns",
]
