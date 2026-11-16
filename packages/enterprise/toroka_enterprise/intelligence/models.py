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




