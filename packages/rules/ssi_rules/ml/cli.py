"""Command Line Interface for Toroka's Machine Learning and Intelligence Pipeline.

Provides commands to:
- train: Train a candidate model on the versioned dataset.
- eval: Evaluate active model or candidate model with acceptance gate metrics.
- promote: Promote candidate model to active champion.
- rollback: Rollback active model to previous accepted version.
- feedback-list: View prioritized active learning review queue.
- feedback-export: Export approved reviewed cases into versioned dataset.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

try:
    from .classifier import TorokaPatternClassifier
    from .dataset import load_dataset, split_dataset_grouped
    from .evaluation import evaluate_model
    from .feedback_queue import adjudicate_feedback, export_approved_feedback_to_dataset, list_review_queue
    from .model_registry import (
        get_active_model,
        load_model,
        promote_candidate,
        rollback_model,
        save_model,
    )
    from .schema import ReviewStatus
except ImportError:
    from ssi_rules.ml.classifier import TorokaPatternClassifier
    from ssi_rules.ml.dataset import load_dataset, split_dataset_grouped
    from ssi_rules.ml.evaluation import evaluate_model
    from ssi_rules.ml.feedback_queue import adjudicate_feedback, export_approved_feedback_to_dataset, list_review_queue
    from ssi_rules.ml.model_registry import (
        get_active_model,
        load_model,
        promote_candidate,
        rollback_model,
        save_model,
    )
    from ssi_rules.ml.schema import ReviewStatus


def cmd_train(args: argparse.Namespace) -> int:
    version = args.version or f"v{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    print(f"[*] Loading dataset from {args.dataset or 'default repository'}...")
    samples = load_dataset(args.dataset)
    print(f"[*] Loaded {len(samples)} samples. Performing grouped split (seed={args.seed})...")
    tr, val, te = split_dataset_grouped(samples, seed=args.seed)
    print(f"    Train: {len(tr)}, Validation: {len(val)}, Held-out Test: {len(te)}")

    print(f"[*] Training candidate model '{version}'...")
    clf = TorokaPatternClassifier(model_version=version)
    clf.fit([s.to_dict() for s in tr], [s.to_dict() for s in val])

    print("[*] Evaluating candidate against acceptance criteria...")
    report = evaluate_model(clf, te)
    save_model(clf, report, version, training_samples=len(tr), test_samples=len(te))
    print(f"    Accuracy:                 {report.overall_accuracy}")
    print(f"    Macro F1:                 {report.macro_f1}")
    print(f"    Legitimate FPR:           {report.legit_false_positive_rate}")
    print(f"    Scam FNR:                 {report.scam_false_negative_rate}")
    print(f"    Brier Score:              {report.brier_score}")
    print(f"    ECE Calibration Error:    {report.expected_calibration_error}")
    print(f"    Mean Latency:             {report.mean_latency_ms} ms")
    print(f"    Critical Regressions:     {len(report.critical_test_regressions)}")
    for note in report.acceptance_notes:
        print(f"      - {note}")

    if report.passed_acceptance_gate:
        print(f"\n[+] SUCCESS: Candidate '{version}' PASSED acceptance gate!")
        if args.promote:
            promote_candidate(version)
            print(f"[+] Promoted '{version}' to active champion.")
        else:
            print(f"[*] Use 'python -m ssi_rules.ml.cli promote --version {version}' to deploy.")
        return 0
    else:
        print(f"\n[-] FAILED: Candidate '{version}' did not meet acceptance criteria.")
        return 1


def cmd_evaluate(args: argparse.Namespace) -> int:
    if args.version:
        clf = load_model(args.version)
        print(f"[*] Evaluating model version '{args.version}'...")
    else:
        clf = get_active_model()
        print(f"[*] Evaluating active champion model '{clf.model_version}'...")

    samples = load_dataset(args.dataset)
    _, _, te = split_dataset_grouped(samples, seed=args.seed)
    report = evaluate_model(clf, te)

    print(f"Results for {clf.model_version}:")
    print(f"  Samples:                {len(te)}")
    print(f"  Overall Accuracy:       {report.overall_accuracy}")
    print(f"  Macro F1:               {report.macro_f1}")
    print(f"  Legitimate FPR:         {report.legit_false_positive_rate}")
    print(f"  Scam FNR:               {report.scam_false_negative_rate}")
    print(f"  Brier Score:            {report.brier_score}")
    print(f"  Mean Latency:           {report.mean_latency_ms} ms")
    print(f"  Passed Acceptance Gate: {report.passed_acceptance_gate}")
    return 0 if report.passed_acceptance_gate else 1


def cmd_promote(args: argparse.Namespace) -> int:
    try:
        promote_candidate(args.version, force=args.force)
        print(f"[+] Successfully promoted '{args.version}' to active champion.")
        return 0
    except Exception as e:
        print(f"[-] Promotion failed: {e}")
        return 1


def cmd_rollback(args: argparse.Namespace) -> int:
    try:
        target = rollback_model()
        print(f"[+] Successfully rolled back active champion to '{target}'.")
        return 0
    except Exception as e:
        print(f"[-] Rollback failed: {e}")
        return 1


def cmd_feedback_list(args: argparse.Namespace) -> int:
    items = list_review_queue(min_priority=args.min_priority, limit=args.limit)
    print(f"[*] Found {len(items)} items in review queue (min_priority={args.min_priority}):\n")
    for it in items:
        print(f"ID: {it.id[:8]} | Priority: {it.active_learning_priority} | Feedback: {it.user_feedback}")
        print(f"  Text: {it.sample_text[:80]}...")
        print(f"  Predicted: {it.predicted_category} -> {it.predicted_label}")
        if it.user_comment:
            print(f"  Comment: {it.user_comment}")
        print("-" * 60)
    return 0


def cmd_feedback_export(args: argparse.Namespace) -> int:
    added = export_approved_feedback_to_dataset(args.dataset)
    print(f"[+] Exported {added} approved feedback item(s) to dataset.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    try:
        from .autonomous_orchestrator import AutonomousMLEngine
    except ImportError:
        from ssi_rules.ml.autonomous_orchestrator import AutonomousMLEngine

    engine = AutonomousMLEngine.get_instance()
    rep = engine.get_status_report()

    print("=" * 60)
    print("TOROKA AUTONOMOUS MACHINE LEARNING STATUS")
    print("=" * 60)
    print(f"  Active Champion:              {rep.champion_version}")
    print(f"  Engine State:                 {'PAUSED (' + rep.pause_reason + ')' if rep.is_paused else 'ACTIVE / OPERATIONAL'}")
    print(f"  Auto-Train Enabled:           {rep.auto_train_enabled}")
    print(f"  Auto-Promote Enabled:         {rep.auto_promote_enabled}")
    print(f"  Active Dataset Version:       {rep.active_dataset_version}")
    print(f"  Total Dataset Samples:        {rep.total_dataset_samples}")
    print(f"  Staged Eligible Samples:      {rep.staged_samples_count}")
    print(f"  Locked Benchmark Samples:     {rep.locked_benchmark_samples}")
    print(f"  Pseudo-Label Ratio:           {rep.pseudo_label_percentage:.1f}%")
    print(f"  Worker Heartbeat:             {rep.worker_heartbeat or 'N/A'}")
    print(f"  Last Successful Training:     {rep.last_successful_training_timestamp or 'None'}")

    print("\n--- Drift & Telemetry Monitor ---")
    drift = rep.drift_status
    print(f"  Samples in Window:            {drift.get('window_sample_count', 0)}")
    print(f"  High-Risk Prediction Rate:    {drift.get('high_risk_rate', 0.0):.1%}")
    print(f"  Inconclusive Rate:            {drift.get('inconclusive_rate', 0.0):.1%}")
    print(f"  User False Positive Rate:     {drift.get('user_false_positive_rate', 0.0):.1%}")
    print(f"  Regression Alert:             {'YES - ' + ', '.join(drift.get('regression_reasons', [])) if drift.get('regression_detected') else 'NO'}")

    print("\n--- Data Sources Health ---")
    for s in rep.sources_health:
        status_str = "ONLINE" if s.get("is_available") else f"OFFLINE ({s.get('last_error', 'unreachable')})"
        print(f"  [{status_str}] {s.get('source_id')}: {s.get('total_records_ingested', 0)} ingested, reliability {s.get('reliability_score')}")

    print("\n--- Recent Jobs ---")
    for j in rep.recent_jobs[:5]:
        print(f"  {j.get('created_at')} | {j.get('job_type')} | {j.get('status')} | {j.get('candidate_version') or 'N/A'}")
        if j.get("error_message"):
            print(f"    Note: {j.get('error_message')}")
    print("=" * 60)
    return 0


def cmd_cycle(args: argparse.Namespace) -> int:
    try:
        from .autonomous_orchestrator import AutonomousMLEngine
    except ImportError:
        from ssi_rules.ml.autonomous_orchestrator import AutonomousMLEngine

    print("[*] Initiating autonomous training cycle...")
    engine = AutonomousMLEngine.get_instance()
    job = engine.run_cycle(trigger_reason="cli_manual", force=args.force)

    print(f"[+] Cycle Job ID:       {job.job_id}")
    print(f"[+] Final Job Status:   {job.status.value}")
    if job.candidate_version:
        print(f"[+] Candidate Version:  {job.candidate_version}")
    if job.dataset_version:
        print(f"[+] Dataset Version:    {job.dataset_version}")
    if job.error_message:
        print(f"[*] Note / Reason:      {job.error_message}")
    for note in job.acceptance_notes:
        print(f"    - {note}")

    return 0 if job.status.value in ("candidate_promoted", "skipped_insufficient_data") else 1


def cmd_worker(args: argparse.Namespace) -> int:
    try:
        from .autonomous_orchestrator import AutonomousMLEngine
    except ImportError:
        from ssi_rules.ml.autonomous_orchestrator import AutonomousMLEngine

    engine = AutonomousMLEngine.get_instance()
    if args.once:
        print("[*] Running single autonomous cycle (--once)...")
        job = engine.run_cycle(trigger_reason="cli_worker_once", force=args.force)
        print(f"[+] Completed cycle: status {job.status.value}")
        return 0

    print(f"[*] Starting Toroka Autonomous Worker Daemon (interval: {args.interval}s)...")
    engine.start_worker(poll_interval_seconds=args.interval)
    try:
        import time

        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Stopping worker daemon...")
        engine.stop_worker()
        print("[+] Worker stopped cleanly.")
        return 0


def cmd_pause(args: argparse.Namespace) -> int:
    try:
        from .autonomous_orchestrator import AutonomousMLEngine
    except ImportError:
        from ssi_rules.ml.autonomous_orchestrator import AutonomousMLEngine

    engine = AutonomousMLEngine.get_instance()
    engine.pause(reason=args.reason)
    print(f"[+] Autonomous engine PAUSED: {args.reason}")
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    try:
        from .autonomous_orchestrator import AutonomousMLEngine
    except ImportError:
        from ssi_rules.ml.autonomous_orchestrator import AutonomousMLEngine

    engine = AutonomousMLEngine.get_instance()
    engine.resume()
    print("[+] Autonomous engine RESUMED.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m ssi_rules.ml.cli", description="Toroka ML Management CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # train
    p_train = sub.add_parser("train", help="Train a candidate model")
    p_train.add_argument("--version", default=None, help="Version tag for candidate")
    p_train.add_argument("--dataset", default=None, help="Custom dataset path")
    p_train.add_argument("--seed", type=int, default=42, help="Random split seed")
    p_train.add_argument("--promote", action="store_true", help="Automatically promote if passed")
    p_train.set_defaults(func=cmd_train)

    # eval
    p_eval = sub.add_parser("eval", help="Evaluate model performance")
    p_eval.add_argument("--version", default=None, help="Model version to evaluate")
    p_eval.add_argument("--dataset", default=None, help="Custom dataset path")
    p_eval.add_argument("--seed", type=int, default=42, help="Random split seed")
    p_eval.set_defaults(func=cmd_evaluate)

    # promote
    p_prom = sub.add_parser("promote", help="Promote candidate model to active champion")
    p_prom.add_argument("--version", required=True, help="Version to promote")
    p_prom.add_argument("--force", action="store_true", help="Force promotion even if acceptance failed")
    p_prom.set_defaults(func=cmd_promote)

    # rollback
    p_rb = sub.add_parser("rollback", help="Roll back active model to previous accepted version")
    p_rb.set_defaults(func=cmd_rollback)

    # feedback-list
    p_fbl = sub.add_parser("feedback-list", help="List active learning review queue")
    p_fbl.add_argument("--min-priority", type=float, default=0.0, help="Minimum active learning priority")
    p_fbl.add_argument("--limit", type=int, default=30, help="Max items to list")
    p_fbl.set_defaults(func=cmd_feedback_list)

    # feedback-export
    p_fbx = sub.add_parser("feedback-export", help="Export approved feedback to dataset")
    p_fbx.add_argument("--dataset", default=None, help="Target dataset path")
    p_fbx.set_defaults(func=cmd_feedback_export)

    # status
    p_stat = sub.add_parser("status", help="Display Autonomous ML engine health & operational status")
    p_stat.set_defaults(func=cmd_status)

    # cycle
    p_cyc = sub.add_parser("cycle", help="Execute an autonomous data ingestion, evaluation, and training cycle")
    p_cyc.add_argument("--force", action="store_true", help="Force cycle even if staged samples threshold not met")
    p_cyc.set_defaults(func=cmd_cycle)

    # worker
    p_wrk = sub.add_parser("worker", help="Run the autonomous worker daemon")
    p_wrk.add_argument("--once", action="store_true", help="Execute a single cycle and exit")
    p_wrk.add_argument("--interval", type=int, default=60, help="Polling interval in seconds (default: 60)")
    p_wrk.add_argument("--force", action="store_true", help="Force training on cycle")
    p_wrk.set_defaults(func=cmd_worker)

    # pause
    p_pau = sub.add_parser("pause", help="Pause the autonomous engine")
    p_pau.add_argument("--reason", default="Paused via CLI", help="Reason for pause")
    p_pau.set_defaults(func=cmd_pause)

    # resume
    p_res = sub.add_parser("resume", help="Resume the autonomous engine")
    p_res.set_defaults(func=cmd_resume)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
