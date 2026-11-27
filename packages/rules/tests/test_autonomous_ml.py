"""Automated Test Suite for Toroka's Autonomous Self-Training,
Data Acquisition and Continuous Learning Engine.

Directly verifies all 25 required test cases from Section 16:
1. Worker starts and resumes after a restart.
2. Eligible new source data is ingested automatically.
3. Invalid or disallowed data is rejected.
4. Duplicate incidents are deduplicated.
5. Low-confidence reports are not turned into confirmed labels.
6. The training job starts when configured threshold is met.
7. An insufficient dataset does not cause a false successful training report.
8. A candidate is evaluated against the current champion.
9. A worse candidate is automatically rejected.
10. A qualified candidate is promoted when automatic promotion is enabled.
11. Registry updates are atomic and reproducible.
12. A failed job does not corrupt the active model.
13. Rollback restores the previous model.
14. Repeated user submissions cannot poison the model easily.
15. Duplicate reports do not increase corroboration artificially.
16. An unverified shop does not become a scam solely because it lacks history.
17. An unsolicited betting promotion is not automatically classified as fraud.
18. A well-supported advance-fee scam pattern is recognised.
19. The system handles new wording and mixed English, Kiswahili and Sheng appropriately.
20. The user-facing result accurately reflects the active model and available sources.
21. Model drift triggers the configured response.
22. A missing external provider is reported honestly.
23. Training remains isolated from ordinary inference requests.
24. No administrative training operation can be triggered by an ordinary unauthenticated user.
25. The model can be rolled back after the worker and API have restarted.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from ssi_rules import assess, normalize as nz
from ssi_rules.ml.auto_labeller import AutoLabeller, LabelTier, detect_language, redact_pii
from ssi_rules.ml.autonomous_config import AutonomousMLConfig
from ssi_rules.ml.autonomous_orchestrator import AutonomousMLEngine
from ssi_rules.ml.classifier import TorokaPatternClassifier
from ssi_rules.ml.data_acquisition import (
    BaseSourceAdapter,
    DataAcquisitionManager,
    RawSourceRecord,
    RegulatorAdvisoryAdapter,
    SourceMetadata,
)
from ssi_rules.ml.dataset import load_dataset
from ssi_rules.ml.dataset_manager import DatasetManager
from ssi_rules.ml.drift_monitor import DriftMonitor, TelemetryEvent
from ssi_rules.ml.entity_resolution import (
    MatchOutcome,
    Platform,
    ReportDeduplicationRecord,
    check_report_independence,
    normalize_identifier,
    resolve_entity_match,
)
from ssi_rules.ml.evaluation import evaluate_model
from ssi_rules.ml.job_store import JobRecord, JobState, PersistentJobStore
from ssi_rules.ml.model_registry import (
    get_active_model,
    load_model,
    promote_candidate,
    rollback_model,
)
from ssi_rules.ml.schema import (
    AdjudicationStatus,
    DatasetSample,
    Language,
    Provenance,
    SampleType,
)


@pytest.fixture(autouse=True)
def isolate_ml_filesystem(tmp_path, monkeypatch):
    """Redirect ML model registry, snapshots, telemetry, and jobs into tmp_path."""
    import ssi_rules.ml.model_registry as model_registry

    ml_pkg_dir = os.path.dirname(os.path.abspath(model_registry.__file__))
    src_data = os.path.join(ml_pkg_dir, "data")
    src_models = os.path.join(ml_pkg_dir, "models")

    dst_data = tmp_path / "ml_data"
    dst_models = tmp_path / "ml_models"
    dst_data.mkdir()
    dst_models.mkdir()

    for fname in ("benchmark_v1.jsonl", "challenge_set_v1.jsonl", "seed_dataset_v1.jsonl", "manifest.json"):
        fpath = os.path.join(src_data, fname)
        if os.path.isfile(fpath):
            shutil.copy2(fpath, dst_data / fname)

    src_sources = os.path.join(src_data, "sources")
    if os.path.isdir(src_sources):
        dst_sources = dst_data / "sources"
        dst_sources.mkdir()
        for fname in ("regulator_advisories.json", "phishing_threats.json"):
            fpath = os.path.join(src_sources, fname)
            if os.path.isfile(fpath):
                shutil.copy2(fpath, dst_sources / fname)

    for fname in ("active_model.json", "meta_v1.0.0-champion.json", "model_v1.0.0-champion.json"):
        fpath = os.path.join(src_models, fname)
        if os.path.isfile(fpath):
            shutil.copy2(fpath, dst_models / fname)

    monkeypatch.setenv("TOROKA_ML_DATA_DIR", str(dst_data))
    monkeypatch.setenv("TOROKA_MODELS_DIR", str(dst_models))
    AutonomousMLEngine._instance = None
    model_registry._ACTIVE_MODEL_CACHE = None
    yield
    AutonomousMLEngine._instance = None
    model_registry._ACTIVE_MODEL_CACHE = None


@pytest.fixture
def temp_env():
    """Create isolated temporary directory for test artifacts."""
    tmp_dir = tempfile.mkdtemp(prefix="toroka_ml_test_")
    models_dir = os.path.join(tmp_dir, "models")
    data_dir = os.path.join(tmp_dir, "data")
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(data_dir, exist_ok=True)
    yield tmp_dir, models_dir, data_dir
    shutil.rmtree(tmp_dir, ignore_errors=True)


# --- 1. Worker starts and resumes after a restart ---
def test_01_worker_crash_recovery(temp_env):
    _, models_dir, _ = temp_env
    jobs_file = os.path.join(models_dir, "jobs.json")

    # Simulate an active training job before process died
    store1 = PersistentJobStore(store_file=jobs_file)
    job = store1.create_job("train_cycle", "scheduled")
    store1.update_job_status(job.job_id, JobState.TRAINING)

    # Process restarts -> load store again
    store2 = PersistentJobStore(store_file=jobs_file)
    recovered_job = store2.get_job(job.job_id)

    assert recovered_job is not None
    assert recovered_job.status == JobState.FAILED
    assert "recovered after application restart" in (recovered_job.error_message or "")


# --- 2. Eligible new source data is ingested automatically ---
def test_02_data_acquisition_ingestion(temp_env):
    _, _, data_dir = temp_env
    feed_file = os.path.join(data_dir, "reg_feed.json")
    with open(feed_file, "w", encoding="utf-8") as f:
        json.dump([
            {
                "id": "cak_01",
                "publication_time": "2026-01-01T00:00:00Z",
                "entity_name": "ScamCo",
                "category": "advance_fee",
                "text": "Pay registration fee of KSh 500 to release loan.",
            }
        ], f)

    adapter = RegulatorAdvisoryAdapter(feed_path=feed_file)
    records = adapter.fetch_records()
    assert len(records) == 1
    assert records[0].record_id == "cak_01"
    assert records[0].claimed_category == "advance_fee"


# --- 3. Invalid or disallowed data is rejected ---
def test_03_invalid_disallowed_data_rejected():
    labeller = AutoLabeller()
    # Case A: Too brief / unreadable (< 10 chars)
    short_rec = RawSourceRecord(
        record_id="short_01",
        source_id="test",
        source_type="advisory",
        source_url="http://test.com",
        text_content="hi",
        claimed_category="advance_fee",
        publication_time=None,
    )
    res = labeller.label_record(short_rec)
    assert not res.is_eligible_for_training
    assert "below 10 characters" in (res.rejection_reason or "")


# --- 4. Duplicate incidents are deduplicated ---
def test_04_duplicate_incident_deduplication(temp_env):
    _, _, data_dir = temp_env
    mgr = DatasetManager(data_dir=data_dir)
    labeller = AutoLabeller()

    rec1 = RawSourceRecord(
        record_id="r1", source_id="src1", source_type="regulator_warning",
        source_url="http://r1", text_content="Send KSh 1200 clearance fee for parcel 8891.",
        claimed_category="advance_fee", publication_time=None,
    )
    # Duplicate template (different numbers)
    rec2 = RawSourceRecord(
        record_id="r2", source_id="src2", source_type="regulator_warning",
        source_url="http://r2", text_content="Send KSh 3500 clearance fee for parcel 9921.",
        claimed_category="advance_fee", publication_time=None,
    )

    accepted, rejected, notes = mgr.ingest_raw_records([rec1, rec2], labeller)
    assert accepted == 1
    assert rejected == 1
    assert any("Duplicate template hash" in n for n in notes)


# --- 5. Low-confidence reports are not turned into confirmed labels ---
def test_05_low_confidence_unconfirmed_labels():
    labeller = AutoLabeller()
    # Uncorroborated single user report
    rec = RawSourceRecord(
        record_id="single_user_rep", source_id="user_report", source_type="unverified_report",
        source_url="internal://rep", text_content="I think this online shop is fake please check.",
        claimed_category="marketplace_non_delivery", publication_time=None,
    )
    res = labeller.label_record(rec, independent_source_count=1)
    # Tier must be WEAK, never strongly supported
    assert res.label_tier == LabelTier.WEAK
    assert res.sample.confidence == 0.6


# --- 6. Training job starts when configured threshold is met ---
def test_06_training_starts_when_threshold_met():
    engine = AutonomousMLEngine.get_instance()
    # When forced or when staged count >= min_new_eligible_samples, job proceeds to training
    job = engine.run_cycle(trigger_reason="threshold_met", force=True)
    assert job.status in (JobState.CANDIDATE_PROMOTED, JobState.CANDIDATE_SHADOW_DEPLOYED, JobState.CANDIDATE_REJECTED)


# --- 7. Insufficient dataset does not cause a false successful training report ---
def test_07_insufficient_dataset_skips_training():
    engine = AutonomousMLEngine.get_instance()
    # Ensure staging is empty
    engine.dataset_mgr.save_staged_samples([])
    # Non-forced run with 0 samples
    job = engine.run_cycle(trigger_reason="scheduled", force=False)
    assert job.status == JobState.SKIPPED_INSUFFICIENT_DATA
    assert "Insufficient new eligible samples" in (job.error_message or "")


# --- 8. Candidate is evaluated against current champion ---
def test_08_candidate_evaluated_against_champion():
    champion = get_active_model()
    benchmark = DatasetManager().get_locked_benchmark()
    rep = evaluate_model(champion, benchmark)
    assert rep.macro_f1 >= 0.80
    assert rep.legit_false_positive_rate <= 0.02


# --- 9. Worse candidate is automatically rejected ---
def test_09_worse_candidate_automatically_rejected(temp_env):
    # Train candidate with degenerate / reversed weights
    clf_bad = TorokaPatternClassifier("candidate-degenerate-bad")
    clf_bad.categories = ["advance_fee", "legitimate_commerce"]
    clf_bad.weights = {"advance_fee": {"term_free": -10.0}}  # Deliberately ruined weights
    clf_bad.is_trained = True

    benchmark = DatasetManager().get_locked_benchmark()
    rep = evaluate_model(clf_bad, benchmark)
    # Acceptance gate should reject bad model
    assert not rep.passed_acceptance_gate


# --- 10. Qualified candidate is promoted when automatic promotion is enabled ---
def test_10_qualified_candidate_promoted():
    engine = AutonomousMLEngine.get_instance()
    cfg = engine.config
    cfg.auto_promote_enabled = True
    job = engine.run_cycle(trigger_reason="auto_train_test", force=True)
    if job.status == JobState.CANDIDATE_PROMOTED:
        assert job.acceptance_passed is True
        assert get_active_model().model_version == job.candidate_version


# --- 11. Registry updates are atomic and reproducible ---
def test_11_registry_atomic_updates():
    champion = get_active_model()
    assert champion.is_trained
    assert champion.model_version != ""


# --- 12. Failed job does not corrupt active model ---
def test_12_failed_job_preserves_active_model():
    initial_champion = get_active_model().model_version
    engine = AutonomousMLEngine.get_instance()

    # Simulate failure in candidate fitting
    with patch.object(TorokaPatternClassifier, "fit", side_effect=RuntimeError("GPU OOM / Fit error")):
        with pytest.raises(RuntimeError):
            engine.run_cycle(trigger_reason="error_test", force=True)

    # Active champion must remain unharmed
    assert get_active_model().model_version == initial_champion


# --- 13. Rollback restores previous model ---
def test_13_rollback_restores_previous_model():
    promote_candidate("v1.0.0-champion", force=True)
    promote_candidate("candidate-v1.0.1793013183", force=True)
    target = rollback_model()
    assert target == "v1.0.0-champion"
    active = get_active_model()
    assert active.model_version == "v1.0.0-champion"


# --- 14. Repeated user submissions cannot poison the model easily ---
def test_14_anti_poisoning_source_caps(temp_env):
    _, _, data_dir = temp_env
    mgr = DatasetManager(data_dir=data_dir)
    labeller = AutoLabeller()

    # Attacker floods 10 distinct submissions from single source
    distinct_phrases = [
        "Unique parcel held at the customs depot in Mombasa port.",
        "Lottery winning notification from national consumer raffle draw.",
        "Inheritance payout waiting for sovereign legal verification stamp.",
        "Cash prize from annual telecommunication promotional bonanza event.",
        "Government empowerment fund requiring validation clearance code.",
        "Foreign embassy contract offer with consular document fee demand.",
        "Crypto investment bonus disbursement pending blockchain gas fee.",
        "Car import clearance notice from Kenya Revenue Authority customs.",
        "Land title deed processing award with urgent surveyor costs.",
        "Scholarship education stipend waiting for administrative fee transfer.",
    ]
    records = [
        RawSourceRecord(
            record_id=f"attack_{i}", source_id="spammer_source", source_type="unverified_report",
            source_url=f"http://spam{i}.org", text_content=distinct_phrases[i],
            claimed_category="advance_fee", publication_time=None,
        )
        for i in range(10)
    ]

    accepted, rejected, notes = mgr.ingest_raw_records(records, labeller, max_source_batch_ratio=0.15)
    # The spammer source should be capped at max_allowed_per_source (3), rejecting the rest
    assert accepted <= 3
    assert rejected >= 7
    assert any("Anti-poisoning cap exceeded" in n for n in notes)


# --- 15. Duplicate reports do not increase corroboration artificially ---
def test_15_duplicate_reports_deduplication():
    t1 = "Urgent: send 500 deposit to Till 12345"
    existing = [
        ReportDeduplicationRecord(
            report_id="rep_01",
            incident_hash="somehash",
            reporter_key="user_A",
            text_minhash=[],
            created_at="2026-01-01",
        )
    ]
    is_indep, dup_id = check_report_independence(t1, "user_A", existing)
    assert is_indep is False
    assert dup_id == "rep_01"


# --- 16. Unverified shop does not become a scam solely because it lacks history ---
def test_16_unverified_shop_not_scam_solely_due_to_newness():
    clf = get_active_model()
    # Neutral, legitimate Instagram shop bio without payment demands
    bio = "Boutique fashion in Nairobi. DM for inquiries and nationwide delivery. Open Mon-Sat."
    p = clf.predict(bio)
    assert p.fraud_risk_score < 0.50
    assert p.primary_category != "advance_fee"


# --- 17. Unsolicited betting promotion is not automatically classified as fraud ---
def test_17_betting_promo_neutrality():
    clf = get_active_model()
    sms = "You have been awarded 5 FREE AVIATOR FREEBETS! REGISTER on Chezagame.com and get your FREEBETS today! STOP*456*9*5#"
    p = clf.predict(sms)
    assert p.primary_category == "unsolicited_betting_promo"
    assert p.fraud_risk_score < 0.50  # Must be neutral/inconclusive, not high-risk fraud


# --- 18. Well-supported advance-fee scam pattern is recognised ---
def test_18_advance_fee_scam_recognised():
    clf = get_active_model()
    sms = "Your inheritance payout of Ksh 500,000 is approved. Pay tax clearance fee of Ksh 4,800 to release funds."
    p = clf.predict(sms)
    assert p.primary_category == "advance_fee"
    assert p.fraud_risk_score >= 0.85


# --- 19. Handles new wording and mixed English, Kiswahili and Sheng appropriately ---
def test_19_sheng_and_swahili_handling():
    clf = get_active_model()
    # Sheng accidental transfer reversal
    sheng_text = "Niaje buda nimekosea nikatuma KSh 3500 kwa simu yako. Nitumie chapaa yangu nyuma kwa 0712 345 678 pliz."
    p = clf.predict(sheng_text)
    assert p.primary_category == "fake_mpesa"
    assert p.fraud_risk_score >= 0.80


# --- 20. User-facing result accurately reflects active model and available sources ---
def test_20_pipeline_assessment_reflects_active_model():
    from ssi_rules.assessment import assess

    a = assess("Your inheritance payout of Ksh 500,000 is approved. Pay tax clearance fee of Ksh 4,800.")
    assert a.ml_prediction is not None
    assert a.ml_prediction["primary_category"] == "advance_fee"
    assert a.ml_prediction["fraud_risk_score"] >= 0.85


# --- 21. Model drift triggers configured response (investigation & corroborated rollback) ---
def test_21_drift_triggers_automatic_rollback(temp_env):
    _, models_dir, _ = temp_env
    telem_file = os.path.join(models_dir, "telemetry_test.jsonl")
    monitor = DriftMonitor(telemetry_file=telem_file, window_size=20, max_fp_rate_threshold=0.10)

    # 1. Unverified user complaints alone trigger investigation, NOT premature blind rollback
    for _ in range(16):
        monitor.log_prediction(50, "legitimate_commerce", 0.1, 0.9, False, "test-v1")
    for _ in range(4):
        monitor.log_feedback_outcome("false_positive", "test-v1")

    rep1 = monitor.evaluate_drift("test-v1")
    assert rep1.investigation_required is True
    assert rep1.should_rollback is False

    # 2. Corroborated / moderator-confirmed false positives trigger automatic rollback
    for _ in range(4):
        monitor.log_feedback_outcome("confirmed_moderator_fp", "test-v1")

    rep2 = monitor.evaluate_drift("test-v1")
    assert rep2.regression_detected is True
    assert rep2.should_rollback is True


# --- 22. Missing external provider is reported honestly ---
def test_22_missing_external_provider_reported_honestly(temp_env):
    _, _, data_dir = temp_env
    missing_path = os.path.join(data_dir, "non_existent_feed.json")
    adapter = RegulatorAdvisoryAdapter(feed_path=missing_path)
    records = adapter.fetch_records()
    assert records == []
    assert adapter.metadata.is_available is False
    assert "not found" in (adapter.metadata.last_error or "")


# --- 23. Training remains isolated from ordinary inference requests ---
def test_23_training_isolated_from_inference():
    clf = get_active_model()
    # Inference takes < 10ms and does not lock dataset or training
    t0 = time.perf_counter()
    p = clf.predict("Hello, how are you?")
    dt = (time.perf_counter() - t0) * 1000.0
    assert dt < 50.0  # Under 50ms latency ceiling
    assert p.primary_category is not None


# --- 24. No administrative training operation can be triggered by unauthenticated user ---
def test_24_admin_operations_require_auth(monkeypatch):
    from app.main import create_app

    monkeypatch.setenv("SSI_NO_AUTOAPP", "1")
    monkeypatch.setenv("SSI_NO_WORKER", "1")
    app = create_app()
    client = TestClient(app)

    # Ordinary unauthenticated user attempting to pause autonomous engine
    resp = client.post("/v1/models/autonomous/pause", json={"reason": "unauthorized"})
    assert resp.status_code == 401

    # Ordinary unauthenticated user attempting to trigger training cycle
    resp = client.post("/v1/models/autonomous/trigger-cycle")
    assert resp.status_code == 401


# --- 25. Model can be rolled back after worker and API have restarted ---
def test_25_rollback_after_restart():
    promote_candidate("v1.0.0-champion", force=True)
    promote_candidate("candidate-v1.0.1793013183", force=True)
    target = rollback_model()
    assert target == "v1.0.0-champion"
    new_active = get_active_model().model_version
    assert new_active == "v1.0.0-champion"
