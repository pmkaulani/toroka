"""Persistent Job Store for Autonomous Machine Learning Lifecycle.

Provides durable, crash-resilient job tracking across restarts:
- Persisted to jobs.json in registry.
- Tracks states: SCHEDULED, COLLECTING_DATA, VALIDATING_DATA, TRAINING, EVALUATING,
  CANDIDATE_REJECTED, CANDIDATE_PROMOTED, ROLLED_BACK, FAILED, SKIPPED_INSUFFICIENT_DATA.
- Automatic crash recovery for interrupted jobs on worker startup.
"""
from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

logger = logging.getLogger("toroka.ml.job_store")


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class JobState(StrEnum):
    SCHEDULED = "scheduled"
    COLLECTING_DATA = "collecting_data"
    VALIDATING_DATA = "validating_data"
    TRAINING = "training"
    EVALUATING = "evaluating"
    CANDIDATE_REJECTED = "candidate_rejected"
    CANDIDATE_PROMOTED = "candidate_promoted"
    CANDIDATE_SHADOW_DEPLOYED = "candidate_shadow_deployed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    SKIPPED_INSUFFICIENT_DATA = "skipped_insufficient_data"


@dataclass
class JobRecord:
    job_id: str
    job_type: str  # "train_cycle", "ingest_only", "eval_only", "rollback"
    status: JobState
    trigger_reason: str  # "scheduled_interval", "new_eligible_samples", "drift_detected", "manual"
    created_at: str = field(default_factory=now_utc_iso)
    started_at: str | None = None
    completed_at: str | None = None
    dataset_version: str | None = None
    candidate_version: str | None = None
    evaluation_metrics: dict[str, Any] | None = None
    acceptance_passed: bool | None = None
    acceptance_notes: list[str] = field(default_factory=list)
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value if hasattr(self.status, "value") else str(self.status)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "JobRecord":
        d = dict(data)
        d["status"] = JobState(d.get("status", "scheduled"))
        return cls(**d)


class PersistentJobStore:
    """Manages atomic, persistent job lifecycle operations."""

    def __init__(self, store_file: str | None = None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.store_file = store_file or os.path.join(base_dir, "models", "jobs.json")
        os.makedirs(os.path.dirname(self.store_file), exist_ok=True)
        self.jobs: dict[str, JobRecord] = {}
        self._load_and_recover()

    def _load_and_recover(self) -> None:
        if not os.path.exists(self.store_file):
            return

        try:
            with open(self.store_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            recovered_any = False
            for jid, jdata in data.items():
                job = JobRecord.from_dict(jdata)
                # Crash recovery: if job was mid-execution when process died, mark as failed
                if job.status in (
                    JobState.SCHEDULED,
                    JobState.COLLECTING_DATA,
                    JobState.VALIDATING_DATA,
                    JobState.TRAINING,
                    JobState.EVALUATING,
                ):
                    job.status = JobState.FAILED
                    job.completed_at = now_utc_iso()
                    job.error_message = "Process interrupted / recovered after application restart"
                    recovered_any = True
                    logger.warning(f"Recovered interrupted job {jid} on startup; marked FAILED.")

                self.jobs[jid] = job

            if recovered_any:
                self.save()

        except Exception as e:
            logger.error(f"Error loading jobs store: {e}")

    def save(self) -> None:
        data = {jid: j.to_dict() for jid, j in self.jobs.items()}
        try:
            with open(self.store_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving jobs store: {e}")

    def create_job(self, job_type: str, trigger_reason: str) -> JobRecord:
        jid = f"job_{uuid.uuid4().hex[:12]}"
        job = JobRecord(
            job_id=jid,
            job_type=job_type,
            status=JobState.SCHEDULED,
            trigger_reason=trigger_reason,
            created_at=now_utc_iso(),
        )
        self.jobs[jid] = job
        self.save()
        return job

    def update_job_status(
        self,
        job_id: str,
        status: JobState,
        candidate_version: str | None = None,
        dataset_version: str | None = None,
        metrics: dict[str, Any] | None = None,
        acceptance_passed: bool | None = None,
        acceptance_notes: list[str] | None = None,
        error_message: str | None = None,
    ) -> JobRecord:
        job = self.jobs.get(job_id)
        if not job:
            raise KeyError(f"Job {job_id} not found in persistent store")

        job.status = status
        if status in (JobState.COLLECTING_DATA, JobState.TRAINING) and not job.started_at:
            job.started_at = now_utc_iso()

        if status in (
            JobState.CANDIDATE_PROMOTED,
            JobState.CANDIDATE_SHADOW_DEPLOYED,
            JobState.CANDIDATE_REJECTED,
            JobState.ROLLED_BACK,
            JobState.FAILED,
            JobState.SKIPPED_INSUFFICIENT_DATA,
        ):
            job.completed_at = now_utc_iso()

        if candidate_version:
            job.candidate_version = candidate_version
        if dataset_version:
            job.dataset_version = dataset_version
        if metrics:
            job.evaluation_metrics = metrics
        if acceptance_passed is not None:
            job.acceptance_passed = acceptance_passed
        if acceptance_notes:
            job.acceptance_notes.extend(acceptance_notes)
        if error_message:
            job.error_message = error_message

        self.save()
        return job

    def get_job(self, job_id: str) -> JobRecord | None:
        return self.jobs.get(job_id)

    def list_jobs(self, limit: int = 20) -> list[JobRecord]:
        sorted_jobs = sorted(self.jobs.values(), key=lambda j: j.created_at, reverse=True)
        return sorted_jobs[:limit]

    def get_last_completed_job(self) -> JobRecord | None:
        for j in sorted(self.jobs.values(), key=lambda j: j.created_at, reverse=True):
            if j.status in (JobState.CANDIDATE_PROMOTED, JobState.CANDIDATE_REJECTED):
                return j
        return None
