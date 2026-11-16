"""Phase 12: Production Governance, Model Risk, Component Registry, Releases, Kill Switch, Incidents, Drift, and Evidence Passports.

Revision ID: 011_production_governance
Revises: 010_copilot
"""
from alembic import op
import sqlalchemy as sa

revision = "011_production_governance"
down_revision = "010_copilot"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. enterprise_governed_components
    op.create_table(
        "enterprise_governed_components",
        sa.Column("component_id", sa.String(100), primary_key=True),
        sa.Column("version", sa.String(50), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("component_type", sa.String(50), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="draft", index=True),
        sa.Column("risk_tier", sa.String(30), nullable=False, index=True),
        sa.Column("owner_team", sa.String(100), nullable=False),
        sa.Column("source_digest", sa.String(64), nullable=False),
        sa.Column("configuration_digest", sa.String(64), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suspended_by", sa.String(255), nullable=True),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_by", sa.String(255), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. enterprise_validation_runs
    op.create_table(
        "enterprise_validation_runs",
        sa.Column("run_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("component_id", sa.String(100), nullable=False, index=True),
        sa.Column("component_version", sa.String(50), nullable=False),
        sa.Column("dataset_digest", sa.String(64), nullable=False),
        sa.Column("configuration_digest", sa.String(64), nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column("result", sa.String(30), nullable=False, index=True),
        sa.Column("evaluator", sa.String(255), nullable=False),
        sa.Column("limitations", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 3. enterprise_production_releases
    op.create_table(
        "enterprise_production_releases",
        sa.Column("release_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("version", sa.String(50), nullable=False, index=True),
        sa.Column("environment", sa.String(30), nullable=False, index=True),
        sa.Column("status", sa.String(30), nullable=False, index=True),
        sa.Column("components_manifest", sa.JSON(), nullable=False),
        sa.Column("validation_runs", sa.JSON(), nullable=False),
        sa.Column("approval_records", sa.JSON(), nullable=False),
        sa.Column("readiness_gates", sa.JSON(), nullable=False),
        sa.Column("manifest_digest", sa.String(64), nullable=False),
        sa.Column("promoted_by", sa.String(255), nullable=True),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rollback_target_id", sa.String(100), nullable=True),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 4. enterprise_suspension_records
    op.create_table(
        "enterprise_suspension_records",
        sa.Column("suspension_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("component_id", sa.String(100), nullable=False, index=True),
        sa.Column("component_version", sa.String(50), nullable=False),
        sa.Column("suspended_by", sa.String(255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("incident_id", sa.String(100), nullable=True, index=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true"), index=True),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resumed_by", sa.String(255), nullable=True),
        sa.Column("resumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resume_reason", sa.Text(), nullable=True),
    )

    # 5. enterprise_governance_incidents
    op.create_table(
        "enterprise_governance_incidents",
        sa.Column("incident_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("category", sa.String(50), nullable=False, index=True),
        sa.Column("severity", sa.String(30), nullable=False, index=True),
        sa.Column("status", sa.String(30), nullable=False, index=True),
        sa.Column("affected_components", sa.JSON(), nullable=False),
        sa.Column("affected_case_ids", sa.JSON(), nullable=False),
        sa.Column("detection_source", sa.String(100), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("contained_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("owner", sa.String(255), nullable=False),
        sa.Column("remediation_notes", sa.Text(), nullable=True),
        sa.Column("post_incident_review", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 6. enterprise_drift_records
    op.create_table(
        "enterprise_drift_records",
        sa.Column("drift_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("drift_type", sa.String(50), nullable=False, index=True),
        sa.Column("component_id", sa.String(100), nullable=False, index=True),
        sa.Column("metric_name", sa.String(100), nullable=False),
        sa.Column("baseline_value", sa.Float(), nullable=False),
        sa.Column("observed_value", sa.Float(), nullable=False),
        sa.Column("threshold", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(30), nullable=False),
        sa.Column("recommended_response", sa.Text(), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 7. enterprise_evidence_passports
    op.create_table(
        "enterprise_evidence_passports",
        sa.Column("passport_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("finding_id", sa.String(100), nullable=False, index=True),
        sa.Column("case_id", sa.String(36), nullable=False, index=True),
        sa.Column("finding_type", sa.String(100), nullable=False),
        sa.Column("finding_status", sa.String(50), nullable=False),
        sa.Column("component_versions", sa.JSON(), nullable=False),
        sa.Column("configuration_digest", sa.String(64), nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column("source_systems", sa.JSON(), nullable=False),
        sa.Column("detection_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("earliest_event_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence_at_detection_count", sa.Integer(), nullable=False),
        sa.Column("delayed_evidence_count", sa.Integer(), nullable=False),
        sa.Column("contradictions_count", sa.Integer(), nullable=False),
        sa.Column("evidence_debt_level", sa.String(30), nullable=False),
        sa.Column("alternative_explanations", sa.JSON(), nullable=False),
        sa.Column("validation_result", sa.String(30), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("passport_digest", sa.String(64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 8. enterprise_ai_provider_records
    op.create_table(
        "enterprise_ai_provider_records",
        sa.Column("provider_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("provider_name", sa.String(100), nullable=False),
        sa.Column("model_identifier", sa.String(100), nullable=False),
        sa.Column("model_version", sa.String(50), nullable=False),
        sa.Column("hosting_location", sa.String(100), nullable=False),
        sa.Column("data_retention_policy", sa.String(100), nullable=False),
        sa.Column("training_on_customer_data_permitted", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_approved", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("risk_tier", sa.String(30), nullable=False),
        sa.Column("evaluation_summary", sa.JSON(), nullable=False),
        sa.Column("last_evaluated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("enterprise_ai_provider_records")
    op.drop_table("enterprise_evidence_passports")
    op.drop_table("enterprise_drift_records")
    op.drop_table("enterprise_governance_incidents")
    op.drop_table("enterprise_suspension_records")
    op.drop_table("enterprise_production_releases")
    op.drop_table("enterprise_validation_runs")
    op.drop_table("enterprise_governed_components")
