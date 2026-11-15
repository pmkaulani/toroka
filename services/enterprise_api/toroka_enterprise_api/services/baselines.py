"""Service layer for behavioral baselines, anomaly evaluation, admission control, and prioritization."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import select, and_, desc
from sqlalchemy.orm import Session

from toroka_enterprise.intelligence.baselines import (
    BaselineDimension,
    MaturityState,
)
from toroka_enterprise.intelligence.statistics import calculate_statistics
from toroka_enterprise.intelligence.deviation import calculate_deviation
from toroka_enterprise.intelligence.scoring import severity_from_deviation
from toroka_enterprise.intelligence.baseline_guard import should_enter_baseline
from toroka_enterprise.intelligence.anomalies import AnomalySeverity, BehavioralAnomaly
from toroka_enterprise.intelligence.signals import CorrelationSignal, SignalSeverity
from toroka_enterprise.intelligence.prioritization import calculate_priority, InvestigationPriority
from toroka_enterprise.intelligence.governance import ModelStatus, DetectionMethod
from toroka_enterprise.intelligence.models import (
    BehavioralProfileRecord,
    BehavioralAnomalyRecord,
    DetectionMethodRecord,
    BaselineAdmissionRecord,
    IntelligenceSignalRecord,
    InvestigationHypothesisRecord,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


DEFAULT_DETECTION_METHODS: list[DetectionMethod] = [
    DetectionMethod(
        method_id="det_stat_mad_v1",
        version="1.0.0",
        status=ModelStatus.DETERMINISTIC,
        description="Median Absolute Deviation (MAD) modified Z-score statistical baseline detector.",
        training_data="Historical ledger and access logs from certified bank source systems.",
        validation_reference="VAL-ROBUST-STAT-2026",
        approved_by="Model Risk & Enterprise Governance Committee",
        limitations=(
            "Requires at least 20 historical observations for mature baseline confidence.",
            "Assumes non-stationary shifts require explicit baseline window recalculation.",
            "Operational triage priority only; not an assessment or probability of guilt or fraud.",
        ),
    ),
    DetectionMethod(
        method_id="det_rule_temporal_v1",
        version="1.0.0",
        status=ModelStatus.VALIDATED,
        description="Deterministic cross-system temporal correlation engine across Core Banking, IAM, HR, and SIEM.",
        training_data="Standard operational banking event models (GENCODE / ISO20022 alignment).",
        validation_reference="VAL-CORR-RULES-2026",
        approved_by="Enterprise Investigations Operations",
        limitations=(
            "Requires clock synchronization across participating source systems.",
            "Does not replace human case review or maker-checker authorization.",
        ),
    ),
]


class BaselineService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def ensure_default_detection_methods(self) -> None:
        """Seed default governance detection methods if they do not exist."""
        for m in DEFAULT_DETECTION_METHODS:
            stmt = select(DetectionMethodRecord).where(
                and_(
                    DetectionMethodRecord.method_id == m.method_id,
                    DetectionMethodRecord.version == m.version,
                )
            )
            existing = self.db.execute(stmt).scalar_one_or_none()
            if not existing:
                rec = DetectionMethodRecord(
                    method_id=m.method_id,
                    version=m.version,
                    status=m.status.value,
                    description=m.description,
                    training_data=m.training_data,
                    validation_reference=m.validation_reference,
                    approved_by=m.approved_by,
                    limitations=list(m.limitations),
                    created_at=utc_now(),
                )
                self.db.add(rec)
        self.db.commit()

    def get_or_create_profile(
        self,
        installation_id: str,
        subject_type: str,
        subject_id: str,
        initial_samples: list[float] | None = None,
        dimension_name: str = BaselineDimension.DAILY_ACTIVITY.value,
    ) -> BehavioralProfileRecord:
        """Retrieve or initialize a behavioral profile for a subject within an installation."""
        stmt = select(BehavioralProfileRecord).where(
            and_(
                BehavioralProfileRecord.installation_id == installation_id,
                BehavioralProfileRecord.subject_type == subject_type,
                BehavioralProfileRecord.subject_id == subject_id,
            )
        )
        profile = self.db.execute(stmt).scalar_one_or_none()

        if not profile:
            now = utc_now()
            dims: dict[str, Any] = {}
            count = 0
            if initial_samples and len(initial_samples) > 0:
                stats = calculate_statistics(initial_samples)
                count = len(initial_samples)
                dims[dimension_name] = {
                    "count": stats.count,
                    "mean": stats.mean,
                    "standard_deviation": stats.standard_deviation,
                    "minimum": stats.minimum,
                    "maximum": stats.maximum,
                    "median": stats.median,
                }

            # Determine maturity
            if count < 10:
                maturity = MaturityState.INSUFFICIENT.value
            elif count < 20:
                maturity = MaturityState.DEVELOPING.value
            else:
                maturity = MaturityState.MATURE.value

            profile = BehavioralProfileRecord(
                id=uuid.uuid4().hex,
                installation_id=installation_id,
                subject_id=subject_id,
                subject_type=subject_type,
                sample_count=count,
                maturity=maturity,
                observation_start=now,
                observation_end=now,
                dimensions=dims,
                created_at=now,
                updated_at=now,
            )
            self.db.add(profile)
            self.db.commit()
            self.db.refresh(profile)

        return profile

    def evaluate_observation(
        self,
        installation_id: str,
        subject_type: str,
        subject_id: str,
        dimension: str,
        observed_value: float,
        case_id: str | None = None,
        historical_samples: list[float] | None = None,
        observation_context: dict[str, Any] | None = None,
    ) -> BehavioralAnomalyRecord:
        """Evaluate an observation against the subject's baseline, recording an anomaly if abnormal."""
        profile = self.get_or_create_profile(
            installation_id=installation_id,
            subject_type=subject_type,
            subject_id=subject_id,
            initial_samples=historical_samples,
            dimension_name=dimension,
        )

        dim_stats = profile.dimensions.get(dimension)
        baseline_samples: list[float]
        if historical_samples and len(historical_samples) > 0:
            baseline_samples = historical_samples
        elif dim_stats and "median" in dim_stats and dim_stats["median"] is not None:
            # Reconstruct representative baseline from stats
            med = dim_stats["median"]
            std = dim_stats.get("standard_deviation", 1.0)
            baseline_samples = [med - std, med, med + std]
        else:
            # Default placeholder baseline when zero history exists
            baseline_samples = [observed_value]

        dev_result = calculate_deviation(observed_value, baseline_samples)
        is_mature = profile.maturity == MaturityState.MATURE.value

        deviation_val = dev_result.modified_z_score if dev_result.modified_z_score is not None else (
            10.0 if dev_result.is_anomalous else 0.0
        )
        severity = severity_from_deviation(deviation_val, mature=is_mature)

        expected_val = dev_result.baseline_median
        confidence = 0.9 if is_mature else (0.6 if profile.maturity == MaturityState.DEVELOPING.value else 0.3)

        explanation = (
            f"Observed {observed_value} on dimension '{dimension}' deviates from baseline "
            f"expected value {expected_val} (modified z-score: {dev_result.modified_z_score}). "
            f"Baseline state is {profile.maturity.upper()} with {profile.sample_count} historical samples."
        )

        anomaly_id = f"anom_{uuid.uuid4().hex[:12]}"
        now = utc_now()
        anomaly_rec = BehavioralAnomalyRecord(
            anomaly_id=anomaly_id,
            installation_id=installation_id,
            case_id=case_id,
            subject_id=subject_id,
            dimension=dimension,
            observed_value=float(observed_value),
            expected_value=float(expected_val),
            deviation=float(deviation_val),
            severity=severity.value,
            confidence=confidence,
            baseline_sample_count=profile.sample_count,
            baseline_mature=is_mature,
            explanation=explanation,
            limitations=[
                "Behavioral anomaly only; does not prove or establish fraudulent intent.",
                "Immature baselines carry lower operational severity and confidence.",
            ],
            provenance={
                "evaluated_at": now.isoformat(),
                "dimension": dimension,
                "context": observation_context or {},
                "detector": "det_stat_mad_v1",
            },
            created_at=now,
        )

        self.db.add(anomaly_rec)
        self.db.commit()
        self.db.refresh(anomaly_rec)
        return anomaly_rec

    def evaluate_admission(
        self,
        installation_id: str,
        event_id: str,
        subject_id: str,
        event_is_verified: bool,
        event_is_under_investigation: bool,
        event_is_correction: bool,
        event_is_test_data: bool,
        event_is_compromised: bool = False,
    ) -> BaselineAdmissionRecord:
        """Evaluate baseline admission policy to prevent baseline poisoning."""
        decision = should_enter_baseline(
            event_is_verified=event_is_verified,
            event_is_under_investigation=event_is_under_investigation,
            event_is_correction=event_is_correction,
            event_is_test_data=event_is_test_data,
            event_is_compromised=event_is_compromised,
        )

        now = utc_now()
        record = BaselineAdmissionRecord(
            id=uuid.uuid4().hex,
            installation_id=installation_id,
            event_id=event_id,
            subject_id=subject_id,
            accepted=decision.accepted,
            reason=decision.reason,
            created_at=now,
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        return record

    def list_anomalies(
        self,
        installation_id: str,
        subject_id: str | None = None,
        case_id: str | None = None,
        limit: int = 50,
    ) -> list[BehavioralAnomalyRecord]:
        """List behavioral anomalies for an installation, optionally filtered by subject or case."""
        conditions = [BehavioralAnomalyRecord.installation_id == installation_id]
        if subject_id:
            conditions.append(BehavioralAnomalyRecord.subject_id == subject_id)
        if case_id:
            conditions.append(BehavioralAnomalyRecord.case_id == case_id)

        stmt = (
            select(BehavioralAnomalyRecord)
            .where(and_(*conditions))
            .order_by(desc(BehavioralAnomalyRecord.created_at))
            .limit(limit)
        )
        return list(self.db.execute(stmt).scalars().all())

    def calculate_case_priority(
        self,
        installation_id: str,
        case_id: str,
    ) -> InvestigationPriority:
        """Calculate explainable investigation priority for a case."""
        # Retrieve correlation signals
        sig_stmt = select(IntelligenceSignalRecord).where(
            and_(
                IntelligenceSignalRecord.installation_id == installation_id,
                IntelligenceSignalRecord.case_id == case_id,
            )
        )
        sig_recs = list(self.db.execute(sig_stmt).scalars().all())

        domain_signals: list[CorrelationSignal] = []
        for s in sig_recs:
            try:
                sev = SignalSeverity(s.severity)
            except Exception:
                sev = SignalSeverity.MEDIUM
            domain_signals.append(
                CorrelationSignal(
                    signal_id=s.signal_id,
                    signal_type=s.signal_type,
                    severity=sev,
                    title=s.title,
                    explanation=s.explanation,
                    event_ids=tuple(s.event_ids or []),
                    confidence=s.confidence,
                    evidence=tuple(s.evidence or []),
                    alternative_explanations=tuple(s.alternative_explanations or []),
                    missing_evidence=tuple(s.missing_evidence or []),
                )
            )

        # Retrieve behavioral anomalies
        anom_stmt = select(BehavioralAnomalyRecord).where(
            and_(
                BehavioralAnomalyRecord.installation_id == installation_id,
                BehavioralAnomalyRecord.case_id == case_id,
            )
        )
        anom_recs = list(self.db.execute(anom_stmt).scalars().all())

        domain_anomalies: list[BehavioralAnomaly] = []
        for a in anom_recs:
            try:
                sev = AnomalySeverity(a.severity)
            except Exception:
                sev = AnomalySeverity.LOW
            domain_anomalies.append(
                BehavioralAnomaly(
                    anomaly_id=a.anomaly_id,
                    installation_id=a.installation_id,
                    subject_id=a.subject_id,
                    dimension=a.dimension,
                    observed_value=a.observed_value,
                    expected_value=a.expected_value,
                    deviation=a.deviation,
                    severity=sev,
                    confidence=a.confidence,
                    explanation=a.explanation,
                    baseline_sample_count=a.baseline_sample_count,
                    baseline_mature=a.baseline_mature,
                    limitations=tuple(a.limitations or []),
                    provenance=dict(a.provenance or {}),
                )
            )

        # Count unresolved contradictions/hypotheses
        hypo_stmt = select(InvestigationHypothesisRecord).where(
            and_(
                InvestigationHypothesisRecord.installation_id == installation_id,
                InvestigationHypothesisRecord.case_id == case_id,
            )
        )
        hypo_recs = list(self.db.execute(hypo_stmt).scalars().all())
        unresolved = sum(1 for h in hypo_recs if h.status in ("open", "weakened"))

        # Calculate priority
        return calculate_priority(
            signals=domain_signals,
            anomalies=domain_anomalies,
            unresolved_contradictions=unresolved,
        )

    def list_detection_methods(self) -> list[DetectionMethodRecord]:
        """List registered detection methods for model governance."""
        self.ensure_default_detection_methods()
        stmt = select(DetectionMethodRecord).order_by(DetectionMethodRecord.method_id)
        return list(self.db.execute(stmt).scalars().all())
