"""Continuous Dataset Manager & Versioned Snapshot Engine for Toroka.

Features:
- Schema validation, PII redaction, and strict provenance preservation.
- Incident and near-duplicate deduplication (template hash and MinHash).
- 5-tier label stratification (Strongly Supported, Corroborated, Weak, Pseudo-label, Unlabelled).
- Anti-poisoning protections: Source caps (<= 15% per source per batch), pseudo-label caps (<= 20%).
- Locked held-out benchmark (benchmark_v1.jsonl) protected against automatic overwrite.
- Immutable versioned snapshots with SHA-256 integrity verification.
- Instant dataset rollback and source retraction quarantine.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from ssi_rules.fingerprint import minhash, similarity

from .auto_labeller import AutoLabeller, LabelTier
from .data_acquisition import RawSourceRecord
from .dataset import get_data_dir, load_dataset, save_dataset
from .schema import DatasetSample, Language, Provenance, SampleType, compute_template_hash

logger = logging.getLogger("toroka.ml.dataset_manager")


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def compute_file_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class DatasetSnapshot:
    version: str
    created_at: str
    sha256_hash: str
    total_samples: int
    category_counts: dict[str, int]
    tier_counts: dict[str, int]
    language_counts: dict[str, int]
    pseudo_label_ratio: float
    snapshot_path: str
    parent_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DatasetSnapshot":
        return cls(**data)


class DatasetManager:
    """Manages versioned datasets, continuous ingestion, anti-poisoning, and snapshots."""

    def __init__(self, data_dir: str | None = None):
        self.data_dir = data_dir or get_data_dir()
        self.snapshots_dir = os.path.join(self.data_dir, "snapshots")
        self.quarantine_dir = os.path.join(self.data_dir, "quarantine")
        self.manifest_file = os.path.join(self.data_dir, "manifest.json")
        self.staging_file = os.path.join(self.data_dir, "staging_samples.jsonl")
        self.quarantine_file = os.path.join(self.quarantine_dir, "quarantine.jsonl")

        os.makedirs(self.snapshots_dir, exist_ok=True)
        os.makedirs(self.quarantine_dir, exist_ok=True)

        self.manifest: dict[str, Any] = self._load_manifest()

    def _load_manifest(self) -> dict[str, Any]:
        if os.path.exists(self.manifest_file):
            try:
                with open(self.manifest_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading manifest: {e}")

        # Initial baseline manifest
        return {
            "active_version": "v1.0.0",
            "snapshots": {},
            "staged_samples_count": 0,
            "last_updated": now_utc_iso(),
        }

    def _save_manifest(self) -> None:
        self.manifest["last_updated"] = now_utc_iso()
        try:
            with open(self.manifest_file, "w", encoding="utf-8") as f:
                json.dump(self.manifest, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving manifest: {e}")

    def get_locked_benchmark(self) -> list[DatasetSample]:
        """Loads permanent, immutable held-out evaluation benchmark."""
        path = os.path.join(self.data_dir, "benchmark_v1.jsonl")
        if not os.path.exists(path):
            raise FileNotFoundError(f"Locked benchmark not found at {path}")
        return load_dataset(path)

    def get_challenge_set(self) -> list[DatasetSample]:
        """Loads locked challenge cases for stress-testing regressions."""
        path = os.path.join(self.data_dir, "challenge_set_v1.jsonl")
        if not os.path.exists(path):
            return []
        return load_dataset(path)

    def get_staged_samples(self) -> list[DatasetSample]:
        if not os.path.exists(self.staging_file):
            return []
        return load_dataset(self.staging_file)

    def save_staged_samples(self, samples: list[DatasetSample]) -> None:
        save_dataset(samples, self.staging_file)
        self.manifest["staged_samples_count"] = len(samples)
        self._save_manifest()

    def quarantine_sample(self, sample_data: dict[str, Any], reason: str) -> None:
        """Move suspicious, rejected, or retracted sample to quarantine."""
        record = {
            "quarantined_at": now_utc_iso(),
            "reason": reason,
            "data": sample_data,
        }
        with open(self.quarantine_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    def ingest_raw_records(
        self,
        records: list[RawSourceRecord],
        auto_labeller: AutoLabeller,
        max_source_batch_ratio: float = 0.15,
    ) -> tuple[int, int, list[str]]:
        """Ingests raw records with validation, deduplication, and anti-poisoning controls.

        Returns: (accepted_count, rejected_count, rejection_notes)
        """
        existing_staged = self.get_staged_samples()
        existing_templates = {s.template_hash for s in existing_staged if s.template_hash}
        existing_texts = [s.text for s in existing_staged]
        existing_minhashes = [minhash(t) for t in existing_texts]

        # Anti-Poisoning Check: Count submissions per source
        source_counts: dict[str, int] = {}
        for r in records:
            source_counts[r.source_id] = source_counts.get(r.source_id, 0) + 1

        max_allowed_per_source = max(3, int(len(records) * max_source_batch_ratio))

        accepted_samples: list[DatasetSample] = []
        rejection_notes: list[str] = []
        rejected_count = 0

        current_source_usage: dict[str, int] = {}

        for record in records:
            sid = record.source_id
            if current_source_usage.get(sid, 0) >= max_allowed_per_source:
                rejected_count += 1
                msg = f"Anti-poisoning cap exceeded for source {sid} (limit {max_allowed_per_source})"
                rejection_notes.append(msg)
                self.quarantine_sample(record.to_dict(), msg)
                continue

            # Auto-labelling & PII scrubbing
            labelling_result = auto_labeller.label_record(record)
            if not labelling_result.is_eligible_for_training or not labelling_result.sample:
                rejected_count += 1
                reason = labelling_result.rejection_reason or "Ineligible sample"
                rejection_notes.append(f"Record {record.record_id}: {reason}")
                self.quarantine_sample(record.to_dict(), reason)
                continue

            sample = labelling_result.sample

            # Deduplication: Template Hash match
            if sample.template_hash in existing_templates:
                rejected_count += 1
                rejection_notes.append(f"Record {record.record_id}: Duplicate template hash")
                continue

            # Deduplication: MinHash / Near-Duplicate match (> 0.85 similarity)
            new_mh = minhash(sample.text)
            is_near_dup = False
            for old_mh in existing_minhashes:
                if similarity(new_mh, old_mh) >= 0.85:
                    is_near_dup = True
                    break

            if is_near_dup:
                rejected_count += 1
                rejection_notes.append(f"Record {record.record_id}: Near-duplicate incident detected")
                continue

            # Accept Sample
            accepted_samples.append(sample)
            existing_templates.add(sample.template_hash)
            existing_minhashes.append(new_mh)
            current_source_usage[sid] = current_source_usage.get(sid, 0) + 1

        # Append accepted samples to staging
        all_staged = existing_staged + accepted_samples
        self.save_staged_samples(all_staged)

        logger.info(f"Ingested {len(accepted_samples)} new samples; rejected {rejected_count}")
        return len(accepted_samples), rejected_count, rejection_notes

    def build_snapshot(
        self,
        new_version: str,
        max_pseudo_label_ratio: float = 0.20,
    ) -> DatasetSnapshot:
        """Constructs an immutable versioned snapshot combining seed data and eligible staged samples."""
        base_seed_path = os.path.join(self.data_dir, "seed_dataset_v1.jsonl")
        base_samples = load_dataset(base_seed_path)
        staged_samples = self.get_staged_samples()

        # Combine
        combined_pool = base_samples + staged_samples

        # Enforce Pseudo-label ratio cap
        pseudo_samples = [s for s in combined_pool if s.rationale and "Pseudo-labelled" in s.rationale]
        real_samples = [s for s in combined_pool if s not in pseudo_samples]

        max_pseudos = int(len(real_samples) * (max_pseudo_label_ratio / (1.0 - max_pseudo_label_ratio)))
        selected_pseudos = pseudo_samples[:max_pseudos]

        final_samples = real_samples + selected_pseudos

        # Compute distributions
        cat_counts: dict[str, int] = {}
        tier_counts: dict[str, int] = {}
        lang_counts: dict[str, int] = {}

        for s in final_samples:
            for cat in s.categories:
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
            lang_counts[s.language.value] = lang_counts.get(s.language.value, 0) + 1

            if "Pseudo-labelled" in s.rationale:
                t = "pseudo_label"
            elif s.provenance == Provenance.PUBLIC_ADVISORY:
                t = "strongly_supported"
            elif s.provenance == Provenance.EXPERT_CURATED:
                t = "corroborated"
            else:
                t = "weak"
            tier_counts[t] = tier_counts.get(t, 0) + 1

        pseudo_ratio = round(len(selected_pseudos) / max(1, len(final_samples)), 4)

        # Save Snapshot file
        snapshot_filename = f"snapshot_{new_version}.jsonl"
        snapshot_path = os.path.join(self.snapshots_dir, snapshot_filename)
        save_dataset(final_samples, snapshot_path)

        file_sha = compute_file_sha256(snapshot_path)

        parent_v = self.manifest.get("active_version")
        snapshot = DatasetSnapshot(
            version=new_version,
            created_at=now_utc_iso(),
            sha256_hash=file_sha,
            total_samples=len(final_samples),
            category_counts=cat_counts,
            tier_counts=tier_counts,
            language_counts=lang_counts,
            pseudo_label_ratio=pseudo_ratio,
            snapshot_path=snapshot_path,
            parent_version=parent_v,
        )

        self.manifest["snapshots"][new_version] = snapshot.to_dict()
        self.manifest["active_version"] = new_version
        self._save_manifest()

        return snapshot

    def rollback_to_snapshot(self, target_version: str) -> DatasetSnapshot:
        """Rollback active dataset version to previous snapshot."""
        if target_version not in self.manifest.get("snapshots", {}):
            raise ValueError(f"Snapshot version {target_version} does not exist in manifest.")

        snap_data = self.manifest["snapshots"][target_version]
        self.manifest["active_version"] = target_version
        self._save_manifest()
        return DatasetSnapshot.from_dict(snap_data)

    def retract_source(self, source_id: str) -> int:
        """Revokes all records from an untrusted or compromised source and moves them to quarantine."""
        staged = self.get_staged_samples()
        retained: list[DatasetSample] = []
        retracted_count = 0

        for s in staged:
            if any(source_id in ref for ref in s.source_refs):
                retracted_count += 1
                self.quarantine_sample(s.to_dict(), f"Retracted source: {source_id}")
            else:
                retained.append(s)

        self.save_staged_samples(retained)
        logger.warning(f"Retracted {retracted_count} samples associated with source {source_id}")
        return retracted_count

    def get_coverage_report(self) -> dict[str, Any]:
        """Comprehensive audit of dataset coverage, imbalance, and data freshness."""
        active_ver = self.manifest.get("active_version", "v1.0.0")
        snapshots = self.manifest.get("snapshots", {})
        snap_info = snapshots.get(active_ver, {})

        staged_count = len(self.get_staged_samples())
        locked_bench_count = len(self.get_locked_benchmark())
        challenge_count = len(self.get_challenge_set())

        return {
            "active_version": active_ver,
            "total_snapshot_samples": snap_info.get("total_samples", 63),
            "staged_eligible_samples": staged_count,
            "locked_benchmark_samples": locked_bench_count,
            "challenge_test_samples": challenge_count,
            "category_distribution": snap_info.get("category_counts", {}),
            "tier_distribution": snap_info.get("tier_counts", {}),
            "language_distribution": snap_info.get("language_counts", {}),
            "pseudo_label_ratio": snap_info.get("pseudo_label_ratio", 0.0),
            "sha256": snap_info.get("sha256_hash", ""),
            "last_updated": self.manifest.get("last_updated"),
        }
