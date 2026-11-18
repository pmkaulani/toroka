"""SQLAlchemy models for intelligence events, entity relationships, risk signals, and investigation bundles."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


class IntelligenceBase(DeclarativeBase):
    """Declarative base for Toroka Enterprise cross-system intelligence persistence."""
    pass


class IntelligenceEventRecord(IntelligenceBase):
    """Normalized cross-system event with provenance and relationship metadata."""
    __tablename__ = "enterprise_intelligence_events"

    event_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    event_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)

    actor: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    subject: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)

    source_system: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    source_record_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    entities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    provenance_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class IntelligenceRelationshipRecord(IntelligenceBase):
    """Graph edge between resolved entities with provenance and confidence."""
    __tablename__ = "enterprise_intelligence_relationships"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    source_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    relationship_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    source_system: Mapped[str | None] = mapped_column(String(100), nullable=True)
    source_record_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    __table_args__ = (
        UniqueConstraint(
            "installation_id", "source_type", "source_id", "target_type", "target_id", "relationship_type",
            name="uq_intelligence_relationship_edge",
        ),
    )


class IntelligenceSignalRecord(IntelligenceBase):
    """Detected cross-system correlation signal associated with cases or anchor events."""
    __tablename__ = "enterprise_intelligence_signals"

    signal_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    signal_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(30), nullable=False, index=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)

    event_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    alternative_explanations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    missing_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class InvestigationBundleRecord(IntelligenceBase):
    """Structured, exportable intelligence bundle linked to an investigation or case."""
    __tablename__ = "enterprise_investigation_bundles"

    investigation_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    anchor_event_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    finding: Mapped[str] = mapped_column(String(255), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    requires_human_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    bundle_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class InvestigationHypothesisRecord(IntelligenceBase):
    """Investigation hypothesis tracking competing explanations and investigator notes."""
    __tablename__ = "enterprise_investigation_hypotheses"

    hypothesis_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    status: Mapped[str] = mapped_column(String(30), nullable=False, default="open", index=True)

    supporting_signal_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    contradicting_signal_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    investigator_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class BehavioralProfileRecord(IntelligenceBase):
    """Aggregated behavioral baseline profile for a bank entity/subject."""
    __tablename__ = "enterprise_behavioral_profiles"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    subject_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    subject_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    maturity: Mapped[str] = mapped_column(String(30), nullable=False, default="insufficient", index=True)

    observation_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    observation_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    dimensions: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "installation_id", "subject_type", "subject_id",
            name="uq_behavioral_profile_subject",
        ),
    )


class BehavioralAnomalyRecord(IntelligenceBase):
    """Behavioral anomaly record representing deviation from an established baseline."""
    __tablename__ = "enterprise_behavioral_anomalies"

    anomaly_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    subject_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    dimension: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    observed_value: Mapped[float] = mapped_column(Float, nullable=False)
    expected_value: Mapped[float] = mapped_column(Float, nullable=False)
    deviation: Mapped[float] = mapped_column(Float, nullable=False)

    severity: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    baseline_sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    baseline_mature: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    limitations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class DetectionMethodRecord(IntelligenceBase):
    """Governance record for deterministic or statistical detection methods."""
    __tablename__ = "enterprise_detection_methods"

    method_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    version: Mapped[str] = mapped_column(String(50), primary_key=True)

    status: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    training_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    validation_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)

    limitations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class BaselineAdmissionRecord(IntelligenceBase):
    """Auditable log of events evaluated against the baseline admission policy."""
    __tablename__ = "enterprise_baseline_admissions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    event_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    accepted: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class AttackReconstructionRecord(IntelligenceBase):
    """Chronological attack reconstruction timeline and state progression."""
    __tablename__ = "enterprise_attack_reconstructions"

    reconstruction_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)

    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    steps: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    entities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    unresolved_questions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    contradictions: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AttackPathRecord(IntelligenceBase):
    """Evidence-backed causal graph edge-node network."""
    __tablename__ = "enterprise_attack_paths"

    path_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    reconstruction_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    nodes: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    edges: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)

    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class EvidenceContradictionRecord(IntelligenceBase):
    """Surfaced cross-system evidence discrepancy requiring human resolution."""
    __tablename__ = "enterprise_evidence_contradictions"

    contradiction_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    event_a: Mapped[str] = mapped_column(String(255), nullable=False)
    event_b: Mapped[str] = mapped_column(String(255), nullable=False)

    field: Mapped[str] = mapped_column(String(100), nullable=False)
    value_a: Mapped[str] = mapped_column(Text, nullable=False)
    value_b: Mapped[str] = mapped_column(Text, nullable=False)

    severity: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    resolution_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    status: Mapped[str] = mapped_column(String(30), nullable=False, default="unresolved", index=True)
    resolved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class InvestigationScenarioRecord(IntelligenceBase):
    """Structured competing explanation scenario linked to an investigation."""
    __tablename__ = "enterprise_investigation_scenarios"

    scenario_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)
    case_id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    required_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    supporting_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    contradicting_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    missing_evidence: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    relative_support: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class SimulationStrategyRecord(IntelligenceBase):
    """Counterfactual detection strategy definition with versioning and thresholds."""
    __tablename__ = "enterprise_simulation_strategies"

    strategy_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    rules_enabled: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    min_severity: Mapped[str] = mapped_column(String(30), nullable=False, default="medium")
    min_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)

    status: Mapped[str] = mapped_column(String(30), nullable=False, default="draft", index=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class SimulationCaseOutcomeRecord(IntelligenceBase):
    """Ground truth adjudication for an investigated case within an installation."""
    __tablename__ = "enterprise_simulation_case_outcomes"

    case_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    label: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    first_fraud_event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    adjudicated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    adjudicated_by: Mapped[str] = mapped_column(String(255), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class SimulationRunRecord(IntelligenceBase):
    """Historical replay run execution record and evaluated metrics."""
    __tablename__ = "enterprise_simulation_runs"

    simulation_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    strategy_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    strategy_version: Mapped[int] = mapped_column(Integer, nullable=False)

    baseline_strategy_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    baseline_strategy_version: Mapped[int | None] = mapped_column(Integer, nullable=True)

    executed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    simulation_cutoff: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    baseline_metrics: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    delta: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    total_events_replayed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    delayed_events_filtered: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    case_detections: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)


class SimulationApprovalRecord(IntelligenceBase):
    """Dual-control (maker-checker) approval review for strategy promotion."""
    __tablename__ = "enterprise_simulation_approvals"

    approval_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    strategy_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    strategy_version: Mapped[int] = mapped_column(Integer, nullable=False)

    requester_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    request_rationale: Mapped[str] = mapped_column(Text, nullable=False)

    simulation_run_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

    status: Mapped[str] = mapped_column(String(30), nullable=False, default="pending", index=True)
    reviewer_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    review_decision: Mapped[str | None] = mapped_column(String(30), nullable=True)
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)


# =============================================================================
# Phase 9: Fraud DNA & Institutional Memory Models
# =============================================================================


class CaseFingerprintRecord(IntelligenceBase):
    """Zero-PII structured behavioral signature for an investigated case."""
    __tablename__ = "enterprise_case_fingerprints"

    case_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    extractor_version: Mapped[str] = mapped_column(String(50), nullable=False, default="v1")
    features: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    source_systems: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    source_coverage: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    total_events: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    first_event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    control_weaknesses: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    adjudicated_label: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CaseMemoryFeatureRecord(IntelligenceBase):
    """Normalized index of individual behavioral dimensions for fast matching."""
    __tablename__ = "enterprise_case_memory_features"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    dimension: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    feature_value: Mapped[str] = mapped_column(String(255), nullable=False)

    event_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    source_systems: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class InstitutionalPatternRecord(IntelligenceBase):
    """Governed recurring fraud typology or control circumvention pattern."""
    __tablename__ = "enterprise_institutional_patterns"

    pattern_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    feature_signature: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    extractor_version: Mapped[str] = mapped_column(String(50), nullable=False, default="v1")
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="candidate", index=True)

    curator_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    reviewer_subject: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    validation_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)

    limitations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    control_weaknesses: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    independent_source_systems: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    supporting_event_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PatternCaseLinkRecord(IntelligenceBase):
    """Association between an institutional pattern and an adjudicated case."""
    __tablename__ = "enterprise_pattern_case_links"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    pattern_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    case_role: Mapped[str] = mapped_column(String(32), nullable=False)  # confirmed_fraud, confirmed_legitimate, candidate_contributor

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class PatternReviewRecord(IntelligenceBase):
    """Audit log of validation evaluations, reviews, approvals, and retirements."""
    __tablename__ = "enterprise_pattern_reviews"

    review_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    pattern_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    pattern_version: Mapped[int] = mapped_column(Integer, nullable=False)

    reviewer_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(30), nullable=False)  # submit_for_review, validate, reject, suspend, reinstate, retire
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    evaluation_metrics: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class PatternVersionRecord(IntelligenceBase):
    """Immutable audit trail of historical pattern revisions."""
    __tablename__ = "enterprise_pattern_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    pattern_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    feature_signature: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)

    changed_by: Mapped[str] = mapped_column(String(255), nullable=False)
    change_summary: Mapped[str] = mapped_column(Text, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class MemoryMatchResultRecord(IntelligenceBase):
    """Persisted record of explainable similarity match evaluations."""
    __tablename__ = "enterprise_memory_match_results"

    match_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    query_case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    matched_type: Mapped[str] = mapped_column(String(30), nullable=False)  # "case" or "pattern"
    target_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    similarity_index: Mapped[float | None] = mapped_column(Float, nullable=True)
    comparison_coverage: Mapped[float] = mapped_column(Float, nullable=False)
    matched_features: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    different_features: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    target_outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class MemoryAuditEventRecord(IntelligenceBase):
    """Auditable log of institutional memory access, matching, and governance actions."""
    __tablename__ = "enterprise_memory_audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    actor_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(50), nullable=False)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    safe_metadata: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


# =============================================================================
# Phase 10: Network Intelligence & Collaborative Fraud Graphs Models
# =============================================================================


class NetworkNodeRecord(IntelligenceBase):
    """Normalized network node representing a resolved entity in an installation."""
    __tablename__ = "enterprise_network_nodes"

    node_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    entity_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    pseudonymous_label: Mapped[str] = mapped_column(String(255), nullable=False)

    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class NetworkEdgeRecord(IntelligenceBase):
    """Evidence-backed relationship or transaction edge between two nodes."""
    __tablename__ = "enterprise_network_edges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    source_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    relationship_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    evidence_basis: Mapped[str] = mapped_column(String(50), nullable=False, index=True)

    event_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    source_record_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    source_systems: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    directed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    __table_args__ = (
        UniqueConstraint(
            "installation_id", "source_key", "target_key", "relationship_type", "evidence_basis",
            name="uq_network_edge_record",
        ),
    )


class EntityLinkCandidateRecord(IntelligenceBase):
    """Candidate relationship proposed via shared attribute or resolution engine."""
    __tablename__ = "enterprise_entity_link_candidates"

    candidate_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    source_entity_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_entity_key: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    attribute_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    attribute_value: Mapped[str] = mapped_column(String(255), nullable=False)
    match_type: Mapped[str] = mapped_column(String(30), nullable=False)

    status: Mapped[str] = mapped_column(String(40), nullable=False, default="SHARED_ATTRIBUTE_ONLY", index=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)

    supporting_evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    contradicting_evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    source_systems: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    first_observed: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    review_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)

    proposed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    first_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    first_review_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    second_reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    second_reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    second_review_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class EntityLinkReviewRecord(IntelligenceBase):
    """Immutable audit log of human review decisions on entity link candidates."""
    __tablename__ = "enterprise_entity_link_reviews"

    review_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    candidate_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    reviewer_subject: Mapped[str] = mapped_column(String(255), nullable=False)

    decision: Mapped[str] = mapped_column(String(40), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)

    previous_status: Mapped[str] = mapped_column(String(40), nullable=False)
    new_status: Mapped[str] = mapped_column(String(40), nullable=False)

    reviewed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class NetworkFindingRecord(IntelligenceBase):
    """Detected network pattern or motif finding with explainability metadata."""
    __tablename__ = "enterprise_network_findings"

    finding_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    pattern_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    anchor_entity: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    related_entities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    event_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    detection_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_limitations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    alternative_legitimate_explanations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    supporting_source_systems: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    transaction_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    monetary_total: Mapped[str | None] = mapped_column(String(50), nullable=True)
    currency: Mapped[str | None] = mapped_column(String(10), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    pattern_version: Mapped[str] = mapped_column(String(50), nullable=False, default="v1")

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class NetworkFindingEvidenceRecord(IntelligenceBase):
    """Persisted compact evidence subgraph for an individual network finding."""
    __tablename__ = "enterprise_network_finding_evidence"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    finding_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    subgraph_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class NetworkSnapshotRecord(IntelligenceBase):
    """Historical point-in-time snapshot summary of an installation's network graph."""
    __tablename__ = "enterprise_network_snapshots"

    snapshot_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    as_of: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    node_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    edge_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    nodes_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    edges_digest: Mapped[str] = mapped_column(String(64), nullable=False)

    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class NetworkAnalysisRunRecord(IntelligenceBase):
    """Auditable execution record of a network intelligence analysis run."""
    __tablename__ = "enterprise_network_analysis_runs"

    run_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    executed_by: Mapped[str] = mapped_column(String(255), nullable=False)

    seed_entities: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    nodes_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    edges_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    result_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    result_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)

    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


# ==============================================================================
# Phase 11 Models: AI Investigation Copilot
# ==============================================================================

class CopilotThreadRecord(IntelligenceBase):
    """Investigation conversation thread bound strictly to an installation and case."""
    __tablename__ = "enterprise_copilot_threads"

    thread_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    is_archived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class CopilotMessageRecord(IntelligenceBase):
    """Single message in a copilot thread with claims, citations, and grounding report."""
    __tablename__ = "enterprise_copilot_messages"

    message_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    thread_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    role: Mapped[str] = mapped_column(String(20), nullable=False)  # user, assistant, system
    content: Mapped[str] = mapped_column(Text, nullable=False)

    task_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    claims: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    citations: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    tool_calls: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    grounding_report: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class CopilotReportDraftRecord(IntelligenceBase):
    """AI-drafted investigation report subject to human investigator review and governance."""
    __tablename__ = "enterprise_copilot_report_drafts"

    draft_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    thread_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)

    report_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    content_markdown: Mapped[str] = mapped_column(Text, nullable=False)
    investigator_edits_markdown: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(String(30), nullable=False, default="DRAFT", index=True)
    evidence_context_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    citations: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    model_info: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_by: Mapped[str] = mapped_column(String(255), nullable=False, default="system")
    edited_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    edit_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    grounding_status: Mapped[str] = mapped_column(String(30), nullable=False, default="UNVERIFIED")
    grounding_report: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    evidence_context_snapshot: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class CopilotFeedbackRecord(IntelligenceBase):
    """Investigator feedback on copilot responses for quality tracking."""
    __tablename__ = "enterprise_copilot_feedbacks"

    feedback_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    message_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    rating: Mapped[int] = mapped_column(Integer, nullable=False)  # 1 for thumbs up, -1 for thumbs down
    feedback_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


# ==============================================================================
# Phase 12 Models: Production Governance, Model Risk & Bank Deployment
# ==============================================================================

class GovernedComponentRecord(IntelligenceBase):
    """Governed lifecycle tracking for all rules, detectors, models, prompts, and policies."""
    __tablename__ = "enterprise_governed_components"

    component_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    version: Mapped[str] = mapped_column(String(50), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    component_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="draft", index=True)
    risk_tier: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    owner_team: Mapped[str] = mapped_column(String(100), nullable=False)

    source_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    configuration_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approval_record_id: Mapped[str | None] = mapped_column(String(100), nullable=True, unique=True)
    approved_validation_run_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    approved_validation_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approval_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    suspended_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retired_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ValidationRunRecord(IntelligenceBase):
    """Auditable execution record of a model or detector validation run against approved datasets."""
    __tablename__ = "enterprise_validation_runs"

    run_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    component_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    component_version: Mapped[str] = mapped_column(String(50), nullable=False)

    dataset_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    configuration_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    metrics: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    result: Mapped[str] = mapped_column(String(30), nullable=False, index=True)  # pass, fail, inconclusive
    evaluator: Mapped[str] = mapped_column(String(255), nullable=False)
    limitations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ProductionReleaseRecord(IntelligenceBase):
    """Immutable release manifest bundling components, validation evidence, and approval sign-offs."""
    __tablename__ = "enterprise_production_releases"

    release_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    version: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    environment: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, index=True)

    components_manifest: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    validation_runs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    approval_records: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    readiness_gates: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)

    manifest_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_bundle: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    promoted_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rollback_target_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ReadinessAttestationRecord(IntelligenceBase):
    """Evidence-backed readiness attestation for mandatory production gates."""
    __tablename__ = "enterprise_readiness_attestations"

    attestation_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    release_version: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    gate_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    verified_by: Mapped[str] = mapped_column(String(255), nullable=False)
    verified_role: Mapped[str] = mapped_column(String(100), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    evidence_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    # History is append-only. A partial unique index permits one active attestation
    # per release/gate while retaining any number of superseded records.


class SuspensionAuditRecord(IntelligenceBase):
    """Kill-switch component suspension ledger for immediate operational fault containment."""
    __tablename__ = "enterprise_suspension_records"

    suspension_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    component_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    component_version: Mapped[str] = mapped_column(String(50), nullable=False)

    suspended_by: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    incident_id: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)

    suspended_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    resumed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    resumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resume_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class GovernanceIncidentRecord(IntelligenceBase):
    """Operational incident record connecting model/data failures directly to affected casework."""
    __tablename__ = "enterprise_governance_incidents"

    incident_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(30), nullable=False, index=True)

    affected_components: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    affected_case_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    detection_source: Mapped[str] = mapped_column(String(100), nullable=False)

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    owner: Mapped[str] = mapped_column(String(255), nullable=False)

    remediation_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    post_incident_review: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class DriftRecordEntity(IntelligenceBase):
    """Statistical, data, or AI-quality drift detection record for proactive risk monitoring."""
    __tablename__ = "enterprise_drift_records"

    drift_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    drift_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    component_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    metric_name: Mapped[str] = mapped_column(String(100), nullable=False)

    baseline_value: Mapped[float] = mapped_column(Float, nullable=False)
    observed_value: Mapped[float] = mapped_column(Float, nullable=False)
    threshold: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String(30), nullable=False)

    recommended_response: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class EvidencePassportRecord(IntelligenceBase):
    """Toroka Evidence Passport: Cryptographically bound audit provenance for findings."""
    __tablename__ = "enterprise_evidence_passports"

    passport_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    finding_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    finding_type: Mapped[str] = mapped_column(String(100), nullable=False)
    finding_status: Mapped[str] = mapped_column(String(50), nullable=False)

    component_versions: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    configuration_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source_systems: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    detection_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    earliest_event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence_at_detection_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    delayed_evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    contradictions_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence_debt_level: Mapped[str] = mapped_column(String(30), nullable=False, default="LOW")
    alternative_explanations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    validation_result: Mapped[str] = mapped_column(String(30), nullable=False, default="PASS")
    human_review_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    passport_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_bundle: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    merkle_proof: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class GovernedAIProviderRecord(IntelligenceBase):
    """Third-party AI provider governance, model parameters, and bank data retention compliance."""
    __tablename__ = "enterprise_ai_provider_records"

    provider_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    provider_name: Mapped[str] = mapped_column(String(100), nullable=False)
    model_identifier: Mapped[str] = mapped_column(String(100), nullable=False)
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)

    hosting_location: Mapped[str] = mapped_column(String(100), nullable=False)
    data_retention_policy: Mapped[str] = mapped_column(String(100), nullable=False)
    training_on_customer_data_permitted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Providers remain unapproved until a separate institution-authorized review.
    is_approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    risk_tier: Mapped[str] = mapped_column(String(30), nullable=False)

    evaluation_summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    last_evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


# ==============================================================================
# Phase 13.0 Models: PKI Signatures, Quantitative Risk & Shadow Governance
# ==============================================================================

class QuantitativeDriftEvaluationRecord(IntelligenceBase):
    """OCC SR 11-7 / Fed SR 15-18 quantitative model risk & PSI drift evaluation record."""
    __tablename__ = "enterprise_quantitative_drift_evaluations"

    evaluation_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    component_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    component_version: Mapped[str] = mapped_column(String(50), nullable=False)

    psi_score: Mapped[float] = mapped_column(Float, nullable=False)
    psi_severity: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    requires_mitigation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    ks_statistic: Mapped[float] = mapped_column(Float, nullable=False)
    ks_p_value: Mapped[float] = mapped_column(Float, nullable=False)
    ks_drift_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    wasserstein_distance: Mapped[float] = mapped_column(Float, nullable=False)
    fairness_compliant: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    is_compliant: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    governance_findings: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    evaluation_details: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    evaluated_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class ChampionChallengerRunRecord(IntelligenceBase):
    """Operational shadow evaluation run comparing Challenger model against Champion in production."""
    __tablename__ = "enterprise_champion_challenger_runs"

    run_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    component_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    champion_version: Mapped[str] = mapped_column(String(50), nullable=False)
    challenger_version: Mapped[str] = mapped_column(String(50), nullable=False)

    decision: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    is_promotable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    fdr_delta: Mapped[float] = mapped_column(Float, nullable=False)
    f1_ratio: Mapped[float] = mapped_column(Float, nullable=False)
    latency_p95_delta_ms: Mapped[float] = mapped_column(Float, nullable=False)

    reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    champion_metrics: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    challenger_metrics: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    evaluated_by: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


# ==============================================================================
# Phase 13.1 Models: Court-Ready Forensic Dossiers & ISO 20022 In-Flight Records
# ==============================================================================

class ForensicDossierRecord(IntelligenceBase):
    """Court-ready forensic evidence dossier with Section 106B certificate and HSM signature."""
    __tablename__ = "enterprise_forensic_dossiers"

    dossier_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    case_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    incident_type: Mapped[str] = mapped_column(String(100), nullable=False)
    fraud_loss_amount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    currency: Mapped[str] = mapped_column(String(10), nullable=False, default="KES")

    examiner_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    examiner_role: Mapped[str] = mapped_column(String(100), nullable=False)
    case_summary: Mapped[str] = mapped_column(Text, nullable=False)

    attack_path_summary: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    identified_mule_nodes: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    evidence_records: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    chain_of_custody: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)

    section_106b_certificate: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    dossier_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_bundle: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    status: Mapped[str] = mapped_column(String(50), nullable=False, default="SEALED")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)


class InflightPaymentRiskRecord(IntelligenceBase):
    """Real-time in-flight transaction evaluation record for ISO 20022 payments."""
    __tablename__ = "enterprise_inflight_payment_evaluations"

    evaluation_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    installation_id: Mapped[str] = mapped_column(String(100), primary_key=True, index=True)

    end_to_end_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    clearing_rail: Mapped[str] = mapped_column(String(50), nullable=False)
    amount: Mapped[float] = mapped_column(Float, nullable=False)
    currency: Mapped[str] = mapped_column(String(10), nullable=False, default="KES")

    debtor_account: Mapped[str] = mapped_column(String(100), nullable=False)
    creditor_account: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    decision: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_tier: Mapped[str] = mapped_column(String(30), nullable=False)

    triggered_rules: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False)

    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)









