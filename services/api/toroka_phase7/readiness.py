from __future__ import annotations
from dataclasses import dataclass, asdict

@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    environment: str = "development"
    secret_manager_configured: bool = False
    tls_enforced: bool = False
    database_encryption_at_rest: bool = False
    backup_restore_tested: bool = False
    rate_limits_enabled: bool = False
    audit_logging_enabled: bool = False
    monitoring_alerts_enabled: bool = False
    data_governance_reviewed: bool = False
    odpc_registration_assessed: bool = False
    privacy_impact_review_completed: bool = False
    deletion_workflow_tested: bool = False
    provider_terms_reviewed: bool = False
    incident_response_runbook_tested: bool = False
    human_review_for_public_claims: bool = False


def production_readiness(config: RuntimeConfig) -> dict:
    if config.environment not in {"development","staging","production"}:
        raise ValueError("environment must be development, staging or production")
    checks={k:bool(v) for k,v in asdict(config).items() if k!="environment"}
    missing=[k for k,v in checks.items() if not v]
    return {"environment":config.environment,"ready":not missing if config.environment=="production" else True,
            "checks":checks,"missing_controls":missing if config.environment=="production" else [],
            "status":"ready" if config.environment!="production" or not missing else "blocked",
            "disclaimer":"Operational checklist only; it does not determine legal compliance or replace qualified security/privacy review."}
