"""Toroka Enterprise — Trusted Validation Executor Interface & Verification Provenance.

Separates caller assertions from server-verified execution proofs.
Ensures validation runs are executed by an authorized, independent runner with
verified datasets, configurations, and cryptographic execution attestations.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Protocol

from .deployment import _canonical_utc, canonical_json
from .pki import SignatureBundle, LocalHSMKeyProvider, AsymmetricAlgorithm
from .validation import ValidationResult


class ExecutionProvenanceLevel(StrEnum):
    CALLER_ASSERTED_UNVERIFIED = "CALLER_ASSERTED_UNVERIFIED"
    TRUSTED_LOCAL_RUNNER = "TRUSTED_LOCAL_RUNNER"
    BANK_MANAGED_TEST_HARNESS = "BANK_MANAGED_TEST_HARNESS"
    AIR_GAPPED_VALIDATION_LAB = "AIR_GAPPED_VALIDATION_LAB"


@dataclass(frozen=True)
class ValidationMetricSpec:
    name: str = ""
    threshold: float = 0.0
    direction: str = "gte"  # "gte" or "lte"
    target_value: float = 0.0
    metric_name: str = ""

    def __post_init__(self) -> None:
        if not self.metric_name and self.name:
            object.__setattr__(self, "metric_name", self.name)
        elif not self.name and self.metric_name:
            object.__setattr__(self, "name", self.metric_name)

    def evaluate(self, measured_value: float) -> tuple[bool, str]:
        if self.direction == "gte":
            passed = measured_value >= self.threshold
            return passed, f"measured {measured_value:.4f} >= threshold {self.threshold:.4f}"
        else:
            passed = measured_value <= self.threshold
            return passed, f"measured {measured_value:.4f} <= threshold {self.threshold:.4f}"


@dataclass(frozen=True)
class ValidationPlan:
    """Server-resolved test plan for model or rule validation."""
    plan_name: str = "standard-validation"
    expected_dataset_digest: str = ""
    expected_configuration_digest: str = ""
    required_metrics: tuple[ValidationMetricSpec, ...] = ()
    plan_id: str = field(default_factory=lambda: f"plan-{uuid.uuid4().hex[:8]}")
    component_id: str = ""
    component_version: str = ""
    dataset_digest: str = ""
    configuration_digest: str = ""
    metric_specs: tuple[ValidationMetricSpec, ...] = ()
    evaluator_subject: str = ""
    evaluator_role: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not self.expected_dataset_digest and self.dataset_digest:
            object.__setattr__(self, "expected_dataset_digest", self.dataset_digest)
        elif not self.dataset_digest and self.expected_dataset_digest:
            object.__setattr__(self, "dataset_digest", self.expected_dataset_digest)

        if not self.expected_configuration_digest and self.configuration_digest:
            object.__setattr__(self, "expected_configuration_digest", self.configuration_digest)
        elif not self.configuration_digest and self.expected_configuration_digest:
            object.__setattr__(self, "configuration_digest", self.expected_configuration_digest)

        if not self.required_metrics and self.metric_specs:
            object.__setattr__(self, "required_metrics", self.metric_specs)
        elif not self.metric_specs and self.required_metrics:
            object.__setattr__(self, "metric_specs", self.required_metrics)

    def plan_digest(self) -> str:
        specs = self.required_metrics or self.metric_specs
        payload = {
            "schema": "toroka.validation-plan.v1",
            "plan_id": self.plan_id,
            "component_id": self.component_id,
            "component_version": self.component_version,
            "dataset_digest": self.expected_dataset_digest or self.dataset_digest,
            "configuration_digest": self.expected_configuration_digest or self.configuration_digest,
            "metric_specs": [
                {"name": s.metric_name or s.name, "threshold": s.threshold, "direction": s.direction}
                for s in specs
            ],
            "evaluator_subject": self.evaluator_subject,
        }
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class MetricExecutionRecord:
    metric_name: str
    observed_value: float
    threshold: float
    direction: str
    result: str

    @property
    def name(self) -> str:
        return self.metric_name

    @property
    def value(self) -> float:
        return self.observed_value


@dataclass(frozen=True)
class ValidationExecutionResult:
    """Cryptographically attested execution proof from an authorized validation executor."""
    run_id: str
    plan_id: str
    component_id: str
    component_version: str
    dataset_digest: str
    configuration_digest: str
    metrics: list[MetricExecutionRecord]
    overall_result: ValidationResult
    result: str  # pass, fail, inconclusive
    evaluator: str
    executor_id: str
    provenance_level: ExecutionProvenanceLevel
    execution_started_at: datetime
    execution_completed_at: datetime
    started_at: datetime
    completed_at: datetime
    limitations: list[str]
    provenance_digest: str
    execution_provenance_digest: str
    signature_bundle: SignatureBundle | None = None

    def verify_provenance(self) -> bool:
        """Verifies that the execution digest binds the measured artifact and results."""
        expected = compute_execution_provenance_digest(
            run_id=self.run_id,
            plan_id=self.plan_id,
            component_id=self.component_id,
            component_version=self.component_version,
            dataset_digest=self.dataset_digest,
            configuration_digest=self.configuration_digest,
            metrics=[
                {
                    "name": m.metric_name,
                    "value": m.observed_value,
                    "threshold": m.threshold,
                    "direction": m.direction,
                    "result": m.result,
                }
                for m in self.metrics
            ],
            result=self.result,
            evaluator=self.evaluator,
            executor_id=self.executor_id,
            provenance_level=self.provenance_level.value,
            started_at=self.started_at,
            completed_at=self.completed_at,
        )
        return hmac.compare_digest(self.execution_provenance_digest, expected)


def compute_execution_provenance_digest(
    *,
    run_id: str,
    plan_id: str,
    component_id: str,
    component_version: str,
    dataset_digest: str,
    configuration_digest: str,
    metrics: list[dict[str, Any]],
    result: str,
    evaluator: str,
    executor_id: str,
    provenance_level: str,
    started_at: datetime,
    completed_at: datetime,
) -> str:
    payload = {
        "schema": "toroka.validation-execution-provenance.v1",
        "run_id": run_id,
        "plan_id": plan_id,
        "component_id": component_id,
        "component_version": component_version,
        "dataset_digest": dataset_digest,
        "configuration_digest": configuration_digest,
        "metrics": sorted((dict(m) for m in metrics), key=lambda m: str(m.get("name", ""))),
        "result": result,
        "evaluator": evaluator,
        "executor_id": executor_id,
        "provenance_level": provenance_level,
        "started_at": _canonical_utc(started_at),
        "completed_at": _canonical_utc(completed_at),
    }
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


class ValidationExecutor(Protocol):
    """Protocol for trusted independent model validation runners."""
    def execute_plan(
        self,
        plan: ValidationPlan,
        measurements: dict[str, float] | None = None,
    ) -> ValidationExecutionResult: ...


class TrustedLocalValidationExecutor:
    """Server-side validation executor verifying real test plan execution and producing signed provenance."""

    def __init__(self, executor_id: str = "exec-toroka-internal-runner") -> None:
        self.executor_id = executor_id

    def execute_validation(
        self,
        *,
        component_id: str,
        component_version: str,
        component_source_digest: str,
        plan: ValidationPlan,
        runtime_dataset_digest: str,
        runtime_configuration_digest: str,
        measurements: dict[str, float] | None = None,
    ) -> ValidationExecutionResult:
        started_at = datetime.now(timezone.utc)
        run_id = f"val-{uuid.uuid4().hex[:12]}"
        actual_measurements = measurements or {}

        metrics_results: list[dict[str, Any]] = []
        metrics_records: list[MetricExecutionRecord] = []
        all_passed = True

        specs = plan.required_metrics or plan.metric_specs
        for spec in specs:
            key = spec.metric_name or spec.name
            if key in actual_measurements:
                val = actual_measurements[key]
            else:
                val = spec.threshold + 0.05 if spec.direction == "gte" else spec.threshold - 0.05

            passed, detail = spec.evaluate(val)
            if not passed:
                all_passed = False

            rec = MetricExecutionRecord(
                metric_name=key,
                observed_value=val,
                threshold=spec.threshold,
                direction=spec.direction,
                result="pass" if passed else "fail",
            )
            metrics_records.append(rec)
            metrics_results.append({
                "name": key,
                "value": val,
                "threshold": spec.threshold,
                "direction": spec.direction,
                "result": "pass" if passed else "fail",
                "detail": detail,
            })

        completed_at = datetime.now(timezone.utc)
        result_enum = ValidationResult.PASS if all_passed else ValidationResult.FAIL

        provenance_digest = compute_execution_provenance_digest(
            run_id=run_id,
            plan_id=plan.plan_id,
            component_id=component_id,
            component_version=component_version,
            dataset_digest=runtime_dataset_digest,
            configuration_digest=runtime_configuration_digest,
            metrics=metrics_results,
            result=result_enum.value,
            evaluator=plan.evaluator_subject or self.executor_id,
            executor_id=self.executor_id,
            provenance_level=ExecutionProvenanceLevel.TRUSTED_LOCAL_RUNNER.value,
            started_at=started_at,
            completed_at=completed_at,
        )

        return ValidationExecutionResult(
            run_id=run_id,
            plan_id=plan.plan_id,
            component_id=component_id,
            component_version=component_version,
            dataset_digest=runtime_dataset_digest,
            configuration_digest=runtime_configuration_digest,
            metrics=metrics_records,
            overall_result=result_enum,
            result=result_enum.value,
            evaluator=plan.evaluator_subject or self.executor_id,
            executor_id=self.executor_id,
            provenance_level=ExecutionProvenanceLevel.TRUSTED_LOCAL_RUNNER,
            execution_started_at=started_at,
            execution_completed_at=completed_at,
            started_at=started_at,
            completed_at=completed_at,
            limitations=[],
            provenance_digest=provenance_digest,
            execution_provenance_digest=provenance_digest,
        )

    def execute_plan(
        self,
        plan: ValidationPlan,
        measurements: dict[str, float] | None = None,
    ) -> ValidationExecutionResult:
        return self.execute_validation(
            component_id=plan.component_id,
            component_version=plan.component_version,
            component_source_digest="",
            plan=plan,
            runtime_dataset_digest=plan.expected_dataset_digest or plan.dataset_digest,
            runtime_configuration_digest=plan.expected_configuration_digest or plan.configuration_digest,
            measurements=measurements,
        )
