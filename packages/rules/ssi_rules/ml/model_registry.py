"""Model Registry, Version Management, Promotion & Rollback for Toroka.

Ensures:
- Every trained candidate model is versioned and auditable.
- Model artifacts (weights, vectorizer, calibration parameters) are persisted cleanly.
- Candidates must pass the evaluation acceptance gate before being promoted to champion.
- One-command rollback restores the previous champion version.
"""
from __future__ import annotations

import json
import os
import threading
from typing import Any

from .classifier import TorokaPatternClassifier
from .evaluation import EvaluationReport
from .schema import ModelMetadata


def get_models_dir() -> str:
    env_dir = os.environ.get("TOROKA_MODELS_DIR")
    if env_dir:
        os.makedirs(env_dir, exist_ok=True)
        return env_dir
    base_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(base_dir, "models")
    os.makedirs(models_dir, exist_ok=True)
    return models_dir


def get_active_model_pointer_path() -> str:
    return os.path.join(get_models_dir(), "active_model.json")


def save_model(
    model: TorokaPatternClassifier,
    report: EvaluationReport,
    version: str,
    dataset_version: str = "v1.0",
    training_samples: int = 0,
    test_samples: int = 0,
) -> str:
    """Save model artifact and metadata to registry."""
    models_dir = get_models_dir()
    model_path = os.path.join(models_dir, f"model_{version}.json")

    # Serialize model weights and parameters
    model_data = model.to_dict()
    with open(model_path, "w", encoding="utf-8") as f:
        json.dump(model_data, f, ensure_ascii=False, indent=2)

    # Save metadata
    meta = ModelMetadata(
        version=version,
        created_at=report.confusion_matrix and report.confusion_matrix.get("created_at", "") or "",
        dataset_version=dataset_version,
        training_samples_count=training_samples,
        test_samples_count=test_samples,
        metrics=report.to_dict(),
        acceptance_passed=report.passed_acceptance_gate,
        is_active=False,
    )
    meta_path = os.path.join(models_dir, f"meta_{version}.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta.to_dict(), f, ensure_ascii=False, indent=2)

    return model_path


def load_model(version: str) -> TorokaPatternClassifier:
    """Load specific model version from registry."""
    model_path = os.path.join(get_models_dir(), f"model_{version}.json")
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model version '{version}' not found at {model_path}")
    with open(model_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return TorokaPatternClassifier.from_dict(data)


_ACTIVE_MODEL_CACHE: tuple[str, float, TorokaPatternClassifier] | None = None
_ACTIVE_MODEL_LOCK = threading.Lock()


def get_active_model() -> TorokaPatternClassifier:
    """Retrieve currently active champion model, or train a baseline if none exists (cached in memory)."""
    global _ACTIVE_MODEL_CACHE
    pointer_path = get_active_model_pointer_path()
    if os.path.exists(pointer_path):
        try:
            mtime = os.path.getmtime(pointer_path)
            with _ACTIVE_MODEL_LOCK:
                if _ACTIVE_MODEL_CACHE and _ACTIVE_MODEL_CACHE[1] == mtime:
                    return _ACTIVE_MODEL_CACHE[2]
            with open(pointer_path, "r", encoding="utf-8") as f:
                info = json.load(f)
            version = info.get("active_version")
            if version:
                clf = load_model(version)
                with _ACTIVE_MODEL_LOCK:
                    _ACTIVE_MODEL_CACHE = (version, mtime, clf)
                return clf
        except Exception:
            pass

    # Default: train baseline and promote it as champion
    from .dataset import load_dataset, split_dataset_grouped
    from .evaluation import evaluate_model

    samples = load_dataset()
    tr, val, te = split_dataset_grouped(samples, seed=42)
    clf = TorokaPatternClassifier("v1.0.0-baseline")
    clf.fit([s.to_dict() for s in tr], [s.to_dict() for s in val])
    report = evaluate_model(clf, te)

    save_model(clf, report, "v1.0.0-baseline", training_samples=len(tr), test_samples=len(te))
    promote_candidate("v1.0.0-baseline", force=True)
    return clf


def promote_candidate(version: str, force: bool = False) -> bool:
    """Promote candidate model to active champion if acceptance passed."""
    meta_path = os.path.join(get_models_dir(), f"meta_{version}.json")
    if not os.path.exists(meta_path) and not force:
        raise FileNotFoundError(f"Metadata for version '{version}' not found.")

    if not force:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        if not meta.get("acceptance_passed"):
            raise ValueError(f"Candidate '{version}' did not pass acceptance criteria and cannot be promoted.")

    pointer_path = get_active_model_pointer_path()
    previous_active = None
    if os.path.exists(pointer_path):
        try:
            with open(pointer_path, "r", encoding="utf-8") as f:
                cur = json.load(f)
            previous_active = cur.get("active_version")
        except Exception:
            pass

    record = {
        "active_version": version,
        "rollback_version": previous_active,
    }
    if os.path.exists(pointer_path):
        try:
            with open(pointer_path, "r", encoding="utf-8") as f:
                cur = json.load(f)
            if "shadow_version" in cur:
                record["shadow_version"] = cur["shadow_version"]
        except Exception:
            pass
    with open(pointer_path, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

    return True


def set_shadow_model(version: str) -> None:
    """Register candidate model to run in shadow mode alongside champion."""
    pointer_path = get_active_model_pointer_path()
    cur = {}
    if os.path.exists(pointer_path):
        try:
            with open(pointer_path, "r", encoding="utf-8") as f:
                cur = json.load(f)
        except Exception:
            pass
    cur["shadow_version"] = version
    with open(pointer_path, "w", encoding="utf-8") as f:
        json.dump(cur, f, indent=2)


def get_shadow_model() -> TorokaPatternClassifier | None:
    """Retrieve shadow candidate model for parallel evaluation if present."""
    pointer_path = get_active_model_pointer_path()
    if os.path.exists(pointer_path):
        try:
            with open(pointer_path, "r", encoding="utf-8") as f:
                cur = json.load(f)
            s_ver = cur.get("shadow_version")
            if s_ver:
                return load_model(s_ver)
        except Exception:
            pass
    return None


def rollback_model() -> str:
    """Roll back active model to previous accepted version."""
    pointer_path = get_active_model_pointer_path()
    if not os.path.exists(pointer_path):
        raise RuntimeError("No active model configuration exists to rollback.")

    with open(pointer_path, "r", encoding="utf-8") as f:
        cur = json.load(f)

    rollback_target = cur.get("rollback_version")
    if not rollback_target:
        raise RuntimeError("No rollback version is available for the current active model.")

    cur_active = cur.get("active_version")
    cur["active_version"] = rollback_target
    cur["rollback_version"] = cur_active  # Can re-toggle if needed

    with open(pointer_path, "w", encoding="utf-8") as f:
        json.dump(cur, f, indent=2)

    return rollback_target
