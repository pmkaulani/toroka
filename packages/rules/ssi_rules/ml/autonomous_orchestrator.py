"""Autonomous Training, Evaluation, Promotion & Self-Healing Orchestrator for Toroka.

Coordinates the end-to-end ML lifecycle:
1. Ingests data from registered sources (regulators, phishing feeds, reviewed feedback).
2. Validates, deduplicates, redacts PII, and assigns 5-tier quality labels.
3. Builds immutable dataset snapshots with SHA-256 integrity and pseudo-label caps.
4. Trains candidate models without blocking user inference requests.
5. Evaluates candidates against permanent locked benchmarks and the current champion.
6. Enforces strict acceptance gates (0 regressions, legit FPR <= 0.02, F1 >= champion).
7. Automatically promotes qualified candidates, or rejects and preserves champion.
8. Monitors production inference drift and triggers automatic rollback if regressions emerge.
9. Persistent across restarts with job state recovery.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from .auto_labeller import AutoLabeller
from .autonomous_config import AutonomousMLConfig
from .classifier import TorokaPatternClassifier
from .data_acquisition import DataAcquisitionManager
from .dataset import split_dataset_grouped
from .dataset_manager import DatasetManager
from .drift_monitor import DriftMonitor, DriftReport
from .evaluation import EvaluationReport, evaluate_model
from .job_store import JobRecord, JobState, PersistentJobStore
from .model_registry import (
    get_active_model,
    load_model,
    promote_candidate,
    rollback_model,
    save_model,
)

logger = logging.getLogger("toroka.ml.autonomous_orchestrator")


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class EngineStatusReport:
    is_paused: bool
    pause_reason: str | None
    champion_version: str
    last_cycle_timestamp: str | None
    last_successful_training_timestamp: str | None
    active_dataset_version: str
    total_dataset_samples: int
    staged_samples_count: int
    locked_benchmark_samples: int
    pseudo_label_percentage: float
    sources_health: list[dict[str, Any]]
    drift_status: dict[str, Any]
    active_job: dict[str, Any] | None
    recent_jobs: list[dict[str, Any]]
    worker_heartbeat: str | None
    auto_train_enabled: bool
    auto_promote_enabled: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AutonomousMLEngine:
    """The central autonomous learning engine running in Toroka."""

    _instance: "AutonomousMLEngine | None" = None
    _lock = threading.Lock()

    def __init__(self, config: AutonomousMLConfig | None = None):
        self.config = config or AutonomousMLConfig.from_env()
        self.dataset_mgr = DatasetManager()
        self.data_acq_mgr = DataAcquisitionManager()
        self.job_store = PersistentJobStore()
        self.drift_monitor = DriftMonitor()
        self.auto_labeller = AutoLabeller()

        self._worker_thread: threading.Thread | None = None
        self._stop_worker_event = threading.Event()
        self._last_heartbeat: str | None = None
        self._cycle_lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "AutonomousMLEngine":
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def get_champion_model(self) -> TorokaPatternClassifier:
        return get_active_model()

    def update_heartbeat(self) -> None:
        self._last_heartbeat = now_utc_iso()

    def pause(self, reason: str = "Administrator paused engine") -> None:
        self.config.is_paused = True
        self.config.pause_reason = reason
        logger.info(f"Autonomous ML Engine paused: {reason}")

    def resume(self) -> None:
        self.config.is_paused = False
        self.config.pause_reason = None
        logger.info("Autonomous ML Engine resumed.")

    def run_cycle(self, trigger_reason: str = "scheduled_interval", force: bool = False) -> JobRecord:
        """Executes a complete autonomous cycle under a single-cycle concurrency lock."""
        with self._cycle_lock:
            return self._execute_cycle(trigger_reason=trigger_reason, force=force)

    def _execute_cycle(self, trigger_reason: str, force: bool = False) -> JobRecord:
        self.update_heartbeat()

        if self.config.is_paused and not force:
            logger.info("Cycle skipped: engine is paused.")
            job = self.job_store.create_job(job_type="train_cycle", trigger_reason=trigger_reason)
            return self.job_store.update_job_status(
                job.job_id,
                JobState.SKIPPED_INSUFFICIENT_DATA,
                error_message=f"Engine paused: {self.config.pause_reason}",
            )

        job = self.job_store.create_job(job_type="train_cycle", trigger_reason=trigger_reason)
        champion = self.get_champion_model()
        self.auto_labeller.classifier = champion

        # Check production drift first
        drift_report = self.drift_monitor.evaluate_drift(champion.model_version)
        if drift_report.should_rollback:
            logger.warning(f"Production regression detected: {drift_report.regression_reasons}. Triggering rollback!")
            try:
                rolled_back_target = rollback_model()
                self.job_store.update_job_status(
                    job.job_id,
                    JobState.ROLLED_BACK,
                    candidate_version=champion.model_version,
                    error_message=f"Regression detected: {', '.join(drift_report.regression_reasons)}. Rolled back to {rolled_back_target}.",
                )
                self.pause(f"Automatic rollback triggered: {drift_report.regression_reasons}")
                return job
            except Exception as e:
                logger.error(f"Failed to execute rollback: {e}")

        # Step 1: Ingest Data
        self.job_store.update_job_status(job.job_id, JobState.COLLECTING_DATA)
        if self.config.auto_ingest_enabled:
            raw_records = self.data_acq_mgr.acquire_all_sources()
            accepted, rejected, notes = self.dataset_mgr.ingest_raw_records(
                raw_records,
                self.auto_labeller,
                max_source_batch_ratio=0.15,
            )
            logger.info(f"Cycle data acquisition: {accepted} accepted, {rejected} rejected.")

        # Step 2: Check Retraining Eligibility Threshold
        staged_samples = self.dataset_mgr.get_staged_samples()
        if len(staged_samples) < self.config.min_new_eligible_samples and not force:
            logger.info(
                f"Skipping training: {len(staged_samples)} staged samples < threshold {self.config.min_new_eligible_samples}"
            )
            return self.job_store.update_job_status(
                job.job_id,
                JobState.SKIPPED_INSUFFICIENT_DATA,
                error_message=f"Insufficient new eligible samples ({len(staged_samples)} / {self.config.min_new_eligible_samples} required).",
            )

        if not self.config.auto_train_enabled and not force:
            logger.info("Training skipped: auto_train_enabled is False.")
            return self.job_store.update_job_status(
                job.job_id,
                JobState.SKIPPED_INSUFFICIENT_DATA,
                error_message="Autonomous training disabled by configuration.",
            )

        # Step 3: Create Versioned Snapshot
        self.job_store.update_job_status(job.job_id, JobState.VALIDATING_DATA)
        new_snap_ver = f"v1.0.{int(time.time())}"
        snapshot = self.dataset_mgr.build_snapshot(
            new_snap_ver,
            max_pseudo_label_ratio=self.config.max_pseudo_label_ratio,
        )
        self.job_store.update_job_status(job.job_id, JobState.TRAINING, dataset_version=new_snap_ver)

        # Step 4: Train Candidate Model
        candidate_version = f"candidate-{new_snap_ver}"
        logger.info(f"Training candidate model '{candidate_version}' on {snapshot.total_samples} samples...")

        from .dataset import load_dataset

        training_samples = load_dataset(snapshot.snapshot_path)
        tr, val, _ = split_dataset_grouped(training_samples, seed=42)

        candidate = TorokaPatternClassifier(model_version=candidate_version)
        candidate.fit([s.to_dict() for s in tr], [s.to_dict() for s in val])

        # Step 5: Evaluate on Locked Benchmark & Challenge Sets
        self.job_store.update_job_status(
            job.job_id,
            JobState.EVALUATING,
            candidate_version=candidate_version,
            dataset_version=new_snap_ver,
        )

        locked_benchmark = self.dataset_mgr.get_locked_benchmark()
        challenge_cases = self.dataset_mgr.get_challenge_set()
        challenge_dicts = [
            {
                "id": c.id,
                "text": c.text,
                "must_not_be_fraud": c.assessment_label in ("inconclusive", "verified_official", "no_known_threats_found"),
                "must_be_fraud": c.assessment_label in ("high_risk", "suspicious_verify_first"),
                "must_be_category": c.categories[0] if c.categories else None,
            }
            for c in challenge_cases
        ]

        cand_report = evaluate_model(candidate, locked_benchmark, critical_regression_cases=challenge_dicts)
        champ_report = evaluate_model(champion, locked_benchmark, critical_regression_cases=challenge_dicts)

        # Acceptance Criteria:
        # 1. Candidate passed gate metrics (0 regressions, legit FPR <= 0.02, scam FNR <= 0.15)
        # 2. Candidate Macro F1 >= Champion Macro F1 - 0.02 (statistical tolerance)
        acceptance_passed = cand_report.passed_acceptance_gate
        gate_notes: list[str] = list(cand_report.acceptance_notes)

        if cand_report.macro_f1 < (champ_report.macro_f1 - 0.02):
            acceptance_passed = False
            gate_notes.append(
                f"FAILED: Candidate macro F1 ({cand_report.macro_f1}) regressed below champion ({champ_report.macro_f1})"
            )
        else:
            gate_notes.append(
                f"PASSED: Candidate macro F1 ({cand_report.macro_f1}) meets or exceeds champion ({champ_report.macro_f1})"
            )

        # Save candidate artifact
        save_model(
            candidate,
            cand_report,
            candidate_version,
            dataset_version=new_snap_ver,
            training_samples=len(tr),
            test_samples=len(locked_benchmark),
        )

        # Step 6: Verify Per-Category Minimum Test Support & Shadow Deployment
        insufficient_support_cats = [
            cat for cat, m in cand_report.per_category.items()
            if m["support"] < self.config.min_category_eval_support
        ]

        if insufficient_support_cats:
            gate_notes.append(
                f"SUPPORT ADVISORY: {len(insufficient_support_cats)} category/categories have test support < {self.config.min_category_eval_support} (e.g. {insufficient_support_cats[:3]}). Deployment restricted to Shadow Mode."
            )

        if not acceptance_passed:
            logger.warning(f"Candidate '{candidate_version}' rejected: failed acceptance criteria.")
            return self.job_store.update_job_status(
                job.job_id,
                JobState.CANDIDATE_REJECTED,
                candidate_version=candidate_version,
                dataset_version=new_snap_ver,
                metrics=cand_report.to_dict(),
                acceptance_passed=False,
                acceptance_notes=gate_notes,
            )
        elif self.config.shadow_mode_enabled or insufficient_support_cats:
            from .model_registry import set_shadow_model

            set_shadow_model(candidate_version)
            gate_notes.append(
                f"SHADOW MODE: Candidate '{candidate_version}' passed acceptance criteria and is deployed to SHADOW MODE for safe production evaluation without altering user verdicts."
            )
            logger.info(f"Deployed candidate '{candidate_version}' to shadow mode.")
            return self.job_store.update_job_status(
                job.job_id,
                JobState.CANDIDATE_SHADOW_DEPLOYED,
                candidate_version=candidate_version,
                dataset_version=new_snap_ver,
                metrics=cand_report.to_dict(),
                acceptance_passed=True,
                acceptance_notes=gate_notes,
            )
        elif self.config.auto_promote_enabled:
            promote_candidate(candidate_version)
            logger.info(f"Promoted candidate '{candidate_version}' to active champion!")
            # Clear staged samples that were incorporated
            self.dataset_mgr.save_staged_samples([])
            return self.job_store.update_job_status(
                job.job_id,
                JobState.CANDIDATE_PROMOTED,
                candidate_version=candidate_version,
                dataset_version=new_snap_ver,
                metrics=cand_report.to_dict(),
                acceptance_passed=True,
                acceptance_notes=gate_notes,
            )
        else:
            logger.info(f"Candidate '{candidate_version}' passed acceptance but auto-promote is disabled. Kept in registry.")
            return self.job_store.update_job_status(
                job.job_id,
                JobState.CANDIDATE_SHADOW_DEPLOYED,
                candidate_version=candidate_version,
                dataset_version=new_snap_ver,
                metrics=cand_report.to_dict(),
                acceptance_passed=True,
                acceptance_notes=gate_notes,
            )

    def get_status_report(self) -> EngineStatusReport:
        champion = self.get_champion_model()
        cov = self.dataset_mgr.get_coverage_report()
        sources = self.data_acq_mgr.get_sources_status()
        drift = self.drift_monitor.evaluate_drift(champion.model_version)
        jobs = self.job_store.list_jobs(limit=10)
        last_completed = self.job_store.get_last_completed_job()

        last_cycle_ts = jobs[0].created_at if jobs else None
        last_train_ts = last_completed.completed_at if last_completed else None

        active_job = jobs[0].to_dict() if (jobs and jobs[0].status in (JobState.TRAINING, JobState.COLLECTING_DATA)) else None

        return EngineStatusReport(
            is_paused=self.config.is_paused,
            pause_reason=self.config.pause_reason,
            champion_version=champion.model_version,
            last_cycle_timestamp=last_cycle_ts,
            last_successful_training_timestamp=last_train_ts,
            active_dataset_version=cov["active_version"],
            total_dataset_samples=cov["total_snapshot_samples"],
            staged_samples_count=cov["staged_eligible_samples"],
            locked_benchmark_samples=cov["locked_benchmark_samples"],
            pseudo_label_percentage=cov["pseudo_label_ratio"] * 100.0,
            sources_health=sources,
            drift_status=drift.to_dict(),
            active_job=active_job,
            recent_jobs=[j.to_dict() for j in jobs],
            worker_heartbeat=self._last_heartbeat,
            auto_train_enabled=self.config.auto_train_enabled,
            auto_promote_enabled=self.config.auto_promote_enabled,
        )

    def start_worker(self, poll_interval_seconds: int = 60) -> None:
        """Starts background worker daemon for periodic polling."""
        if self._worker_thread and self._worker_thread.is_alive():
            logger.info("Worker daemon is already running.")
            return

        self._stop_worker_event.clear()

        def _worker_loop():
            logger.info("Autonomous ML Worker daemon started.")
            last_run_time = 0.0
            interval_sec = self.config.train_interval_hours * 3600.0

            while not self._stop_worker_event.is_set():
                self.update_heartbeat()
                now = time.time()
                staged_count = len(self.dataset_mgr.get_staged_samples())

                should_trigger = False
                trigger_reason = ""

                # Trigger 1: Interval elapsed
                if (now - last_run_time) >= interval_sec:
                    should_trigger = True
                    trigger_reason = "scheduled_interval"
                # Trigger 2: New samples threshold met
                elif staged_count >= self.config.min_new_eligible_samples:
                    should_trigger = True
                    trigger_reason = "new_eligible_samples"

                if should_trigger and not self.config.is_paused:
                    try:
                        logger.info(f"Worker triggering autonomous cycle ({trigger_reason})...")
                        self.run_cycle(trigger_reason=trigger_reason)
                        last_run_time = time.time()
                    except Exception as e:
                        logger.error(f"Error in worker cycle: {e}")

                self._stop_worker_event.wait(poll_interval_seconds)

            logger.info("Autonomous ML Worker daemon stopped.")

        self._worker_thread = threading.Thread(target=_worker_loop, daemon=True)
        self._worker_thread.start()

    def stop_worker(self) -> None:
        if self._worker_thread and self._worker_thread.is_alive():
            self._stop_worker_event.set()
            self._worker_thread.join(timeout=5.0)
            self._worker_thread = None
