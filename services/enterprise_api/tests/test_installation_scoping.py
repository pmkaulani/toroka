"""Tests for multi-installation isolation across cases, runs, and reveals."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from toroka_enterprise_api.config import EnterpriseSettings
from toroka_enterprise_api.main import create_app
from toroka_enterprise_api.persistence.models import Base, RunRecord


@pytest.fixture
def multi_install_clients(tmp_path):
    op_db = tmp_path / "shared_op.db"
    vault_db = tmp_path / "shared_vault.db"

    settings_alpha = EnterpriseSettings(
        environment="development",
        auth_mode="development",
        database_url=f"sqlite:///{op_db}",
        vault_database_url=f"sqlite:///{vault_db}",
        installation_id="bank-alpha",
    )
    app_alpha = create_app(settings_alpha)

    settings_beta = EnterpriseSettings(
        environment="development",
        auth_mode="development",
        database_url=f"sqlite:///{op_db}",
        vault_database_url=f"sqlite:///{vault_db}",
        installation_id="bank-beta",
    )
    app_beta = create_app(settings_beta)

    Base.metadata.create_all(app_alpha.state.engine)
    Base.metadata.create_all(app_alpha.state.vault_engine)

    client_alpha = TestClient(app_alpha, client=("127.0.0.1", 50000))
    client_beta = TestClient(app_beta, client=("127.0.0.1", 50000))
    return client_alpha, client_beta


def test_installation_isolation_on_cases_and_runs(multi_install_clients):
    client_alpha, client_beta = multi_install_clients

    # 1. Record runs in Bank Alpha and Bank Beta
    with client_alpha.app.state.session_factory() as db:
        db.add(
            RunRecord(
                installation_id="bank-alpha",
                manifest_id="run-alpha-1",
                manifest={"manifest_id": "run-alpha-1"},
                created_by="system",
            )
        )
        db.add(
            RunRecord(
                installation_id="bank-beta",
                manifest_id="run-beta-1",
                manifest={"manifest_id": "run-beta-1"},
                created_by="system",
            )
        )
        db.commit()

    # 2. Bank Alpha runs list only shows run-alpha-1
    alpha_runs = client_alpha.get(
        "/api/enterprise/v1/runs",
        headers={"X-Dev-User": "auth-alpha", "X-Dev-Roles": "authoriser"},
    ).json()
    assert len(alpha_runs) == 1
    assert alpha_runs[0]["manifest_id"] == "run-alpha-1"

    # 3. Bank Beta runs list only shows run-beta-1
    beta_runs = client_beta.get(
        "/api/enterprise/v1/runs",
        headers={"X-Dev-User": "auth-beta", "X-Dev-Roles": "authoriser"},
    ).json()
    assert len(beta_runs) == 1
    assert beta_runs[0]["manifest_id"] == "run-beta-1"

    # 4. Intake cases into Bank Alpha
    res_alpha = client_alpha.post(
        "/api/enterprise/v1/cases/intake",
        headers={"X-Dev-User": "auth-alpha", "X-Dev-Roles": "authoriser"},
        json={
            "manifest_id": "run-alpha-1",
            "leads": [{"label": "REVIEW", "focus": "staff:S100"}],
            "assign_to_subject": "inv-alpha",
        },
    )
    assert res_alpha.status_code == 201

    # 5. Bank Alpha sees the case
    alpha_cases = client_alpha.get(
        "/api/enterprise/v1/cases",
        headers={"X-Dev-User": "auth-alpha", "X-Dev-Roles": "authoriser"},
    ).json()
    assert alpha_cases["total"] == 1

    # 6. Bank Beta sees 0 cases!
    beta_cases = client_beta.get(
        "/api/enterprise/v1/cases",
        headers={"X-Dev-User": "auth-beta", "X-Dev-Roles": "authoriser"},
    ).json()
    assert beta_cases["total"] == 0
