import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

from toroka_core.graph.clustering import cluster_by_shared_identifiers

SHIMS = [
    ("toroka_evidence.models", "toroka_core.evidence.models"),
    ("toroka_evidence.scoring", "toroka_core.evidence.scoring"),
    ("toroka_evidence.profile", "toroka_core.evidence.profile"),
    ("toroka_evidence.engine", "toroka_core.evidence.engine"),
    ("toroka_evidence.normalize", "toroka_core.evidence.normalize"),
    ("toroka_evidence.memory", "toroka_core.evidence.memory"),
    ("toroka_evidence.providers.base", "toroka_core.evidence.provider_protocols"),
    ("toroka_phase3.identity_graph", "toroka_core.graph.identity_graph"),
    ("toroka_phase3.timeline", "toroka_core.timeline"),
    ("toroka_phase7.case_memory", "toroka_core.case_memory"),
    ("toroka_email_forensics.analyzer", "toroka_core.email_forensics.analyzer"),
]


@pytest.mark.parametrize("old,new", SHIMS)
def test_old_import_path_is_the_same_module_object(old, new):
    assert importlib.import_module(old) is importlib.import_module(new)


def test_core_imports_without_the_consumer_app_on_the_path():
    root = Path(__file__).resolve().parents[1]
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = str(root)
    code = ("import toroka_core.evidence, toroka_core.graph.identity_graph, toroka_core.graph.evidence_graph, "
            "toroka_core.graph.clustering, toroka_core.timeline, toroka_core.case_memory, toroka_core.email_forensics; print('ok')")
    done = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True)
    assert done.returncode == 0 and "ok" in done.stdout, done.stderr


def test_clusters_link_records_sharing_an_identifier_and_stay_candidates():
    recs = {"A": [("ben", "X")], "B": [("ben", "X"), ("dev", "D1")], "C": [("dev", "D1")], "D": [("ben", "Z")]}
    clusters = cluster_by_shared_identifiers(recs)
    assert [c.members for c in clusters] == [("A", "B", "C")]
    assert clusters[0].status == "candidate" and clusters[0].to_dict()["risk_propagation"] == "never_automatic"


def test_popular_identifiers_do_not_link_and_ignored_kinds_are_skipped():
    recs = {f"R{i}": [("branch", "NBO-01")] for i in range(60)}
    assert cluster_by_shared_identifiers(recs, max_identifier_fanout=50) == []
    assert cluster_by_shared_identifiers({"A": [("ben", "X")], "B": [("ben", "X")]}, ignore_kinds=["ben"]) == []


def test_cluster_ids_are_deterministic():
    recs = {"A": [("k", "1")], "B": [("k", "1")]}
    assert cluster_by_shared_identifiers(recs)[0].cluster_id == cluster_by_shared_identifiers(dict(reversed(list(recs.items()))))[0].cluster_id


def test_assess_handles_naive_and_expired_datetimes():
    from datetime import datetime, timezone
    from toroka_core.evidence.models import Evidence
    from toroka_core.evidence.scoring import assess

    naive_ev = Evidence(source='test', source_group='g', category='domain_registration',
                        polarity='risk', summary='s', observed_at=datetime(2026, 1, 1))
    verdict, index, conf, concl = assess([naive_ev], now=datetime.now(timezone.utc))
    assert verdict in ('high_risk', 'suspicious', 'insufficient_evidence')
