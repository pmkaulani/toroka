"""Reviewed Feedback Loop and Active Learning Queue for Toroka.

Ensures:
1. User feedback is collected anonymously and safely without requiring user accounts.
2. Unreviewed feedback never directly alters production weights or creates public scam records.
3. Active learning prioritizes examples with high uncertainty, ML-rule disagreement, or user-reported mistakes.
4. Reviewer adjudication verifies ground-truth labels before export into the versioned training set.
"""
from __future__ import annotations

import json
import os
import uuid
from typing import Any

from .dataset import get_data_dir
from .schema import AdjudicationStatus, DatasetSample, FeedbackItem, Language, Provenance, ReviewStatus, SampleType


def get_feedback_db_path() -> str:
    data_dir = get_data_dir()
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "feedback_queue.jsonl")


def submit_feedback(
    sample_text: str,
    predicted_label: str,
    predicted_category: str | None,
    user_feedback: str,  # "helpful" | "mistake_false_positive" | "mistake_false_negative" | "inaccurate_detail"
    user_comment: str = "",
    check_id: str | None = None,
    rule_label: str | None = None,
    prediction_confidence: float = 1.0,
) -> FeedbackItem:
    """Submit user feedback and calculate active learning priority."""
    # Compute active learning priority score:
    priority = 0.2  # baseline
    if user_feedback.startswith("mistake"):
        priority += 0.5  # User flagged an error
    if rule_label and predicted_label and rule_label != predicted_label:
        priority += 0.3  # Model disagreed with deterministic rules
    if 0.40 <= prediction_confidence <= 0.65:
        priority += 0.2  # Model was uncertain

    item = FeedbackItem(
        id=str(uuid.uuid4()),
        check_id=check_id,
        sample_text=" ".join(sample_text.strip().split()),
        predicted_label=predicted_label,
        predicted_category=predicted_category,
        user_feedback=user_feedback,
        user_comment=user_comment.strip(),
        active_learning_priority=round(min(1.0, priority), 3),
        review_status=ReviewStatus.PENDING,
    )

    # Persist to feedback log
    path = get_feedback_db_path()
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(item.to_dict(), ensure_ascii=False) + "\n")

    return item


def list_review_queue(
    status: ReviewStatus = ReviewStatus.PENDING,
    min_priority: float = 0.0,
    limit: int = 50,
) -> list[FeedbackItem]:
    """Return pending review items sorted by active learning priority descending."""
    path = get_feedback_db_path()
    if not os.path.exists(path):
        return []

    items: list[FeedbackItem] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    data = json.loads(line.strip())
                    item = FeedbackItem.from_dict(data)
                    if item.review_status == status and item.active_learning_priority >= min_priority:
                        items.append(item)
                except Exception:
                    continue

    items.sort(key=lambda x: x.active_learning_priority, reverse=True)
    return items[:limit]


def adjudicate_feedback(
    feedback_id: str,
    adjudicated_label: str,  # "high_risk" | "suspicious_verify_first" | "inconclusive" | "no_known_threats_found" | "verified_official"
    adjudicated_category: str,
    reviewer_notes: str = "",
    status: ReviewStatus = ReviewStatus.APPROVED_FOR_TRAINING,
) -> FeedbackItem | None:
    """Review and adjudicate a feedback item, approving it for inclusion in the dataset."""
    path = get_feedback_db_path()
    if not os.path.exists(path):
        return None

    all_items: list[FeedbackItem] = []
    target: FeedbackItem | None = None

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                item = FeedbackItem.from_dict(json.loads(line.strip()))
                if item.id == feedback_id:
                    item.adjudicated_label = adjudicated_label
                    item.adjudicated_category = adjudicated_category
                    item.reviewer_notes = reviewer_notes
                    item.review_status = status
                    item.reviewed_at = item.created_at  # updated
                    target = item
                all_items.append(item)

    if target:
        with open(path, "w", encoding="utf-8") as f:
            for it in all_items:
                f.write(json.dumps(it.to_dict(), ensure_ascii=False) + "\n")

    return target


def export_approved_feedback_to_dataset(target_dataset_path: str | None = None) -> int:
    """Export reviewer-approved feedback items into the versioned dataset."""
    from .dataset import get_default_dataset_path, load_dataset, save_dataset

    dest_path = target_dataset_path or get_default_dataset_path()
    existing_samples = load_dataset(dest_path)
    existing_texts = {s.text for s in existing_samples}

    approved_items = list_review_queue(status=ReviewStatus.APPROVED_FOR_TRAINING, limit=500)
    added = 0

    for item in approved_items:
        if item.sample_text not in existing_texts and item.adjudicated_label:
            new_sample = DatasetSample(
                id=f"fb_{item.id[:8]}",
                sample_type=SampleType.TEXT,
                text=item.sample_text,
                language=Language.UNKNOWN,
                categories=[item.adjudicated_category] if item.adjudicated_category else ["ambiguous_neutral"],
                assessment_label=item.adjudicated_label,
                rationale=f"Reviewer adjudicated from user feedback: {item.reviewer_notes}",
                provenance=Provenance.CONSENTED_USER,
                adjudication_status=AdjudicationStatus.REVIEWER_APPROVED,
                confidence=1.0,
                is_synthetic=False,
            )
            existing_samples.append(new_sample)
            existing_texts.add(item.sample_text)
            added += 1

    if added > 0:
        save_dataset(existing_samples, dest_path)

    return added
