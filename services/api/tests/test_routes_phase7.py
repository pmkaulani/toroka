"""Tests for Phase 7 API routes."""
import pytest


def test_phase7_language_analyze_endpoint(env):
    payload = {"text": "Umeshinda pesa za serikali. Lipa ada ya usajili kwanza ili utoe pesa."}
    r = env.client.post("/v1/phase7/language/analyze", json=payload)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["language"] in {"sw", "en", "sheng", "undetermined"}
    assert "categories" in data
    assert "signals" in data
    assert "limitations" in data
    assert data["verdict"] is None  # Phase 7 never issues standalone seller verdicts


def test_phase7_ops_status_endpoint(env):
    r = env.client.get("/v1/phase7/ops/status")
    assert r.status_code == 200, r.text
    data = r.json()
    assert "status" in data
    assert "feeds" in data
    assert "alerts" in data


def test_phase7_ops_metrics_endpoint(env):
    r = env.client.get("/v1/phase7/ops/metrics")
    assert r.status_code == 200, r.text
    data = r.json()
    assert "feeds_total" in data
    assert "privacy_note" in data


def test_phase7_kenya_advisories_endpoint(env):
    r = env.client.get("/v1/phase7/advisories/kenya")
    assert r.status_code == 200, r.text
    data = r.json()
    assert "advisories" in data
    assert isinstance(data["advisories"], list)
