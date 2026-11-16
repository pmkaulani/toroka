"""Attack reconstruction, causal paths, evidence contradictions, and competing scenarios.

Revision ID: 006_attack_reconstruction
Revises: 005_baselines
"""
from alembic import op
import sqlalchemy as sa

revision = "006_attack_reconstruction"
down_revision = "005_baselines"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. enterprise_attack_reconstructions
    op.create_table(
        "enterprise_attack_reconstructions",
        sa.Column("reconstruction_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("case_id", sa.String(36), nullable=True, index=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("steps", sa.JSON(), nullable=False),
        sa.Column("entities", sa.JSON(), nullable=False),
        sa.Column("unresolved_questions", sa.JSON(), nullable=False),
        sa.Column("contradictions", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )

    # 2. enterprise_attack_paths
    op.create_table(
        "enterprise_attack_paths",
        sa.Column("path_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("reconstruction_id", sa.String(100), nullable=True, index=True),
        sa.Column("case_id", sa.String(36), nullable=True, index=True),
        sa.Column("nodes", sa.JSON(), nullable=False),
        sa.Column("edges", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 3. enterprise_evidence_contradictions
    op.create_table(
        "enterprise_evidence_contradictions",
        sa.Column("contradiction_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("case_id", sa.String(36), nullable=True, index=True),
        sa.Column("event_a", sa.String(255), nullable=False),
        sa.Column("event_b", sa.String(255), nullable=False),
        sa.Column("field", sa.String(100), nullable=False),
        sa.Column("value_a", sa.Text(), nullable=False),
        sa.Column("value_b", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(30), nullable=False, index=True),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("resolution_required", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("status", sa.String(30), nullable=False, server_default="unresolved", index=True),
        sa.Column("resolved_by", sa.String(255), nullable=True),
        sa.Column("resolution_note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )

    # 4. enterprise_investigation_scenarios
    op.create_table(
        "enterprise_investigation_scenarios",
        sa.Column("scenario_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("case_id", sa.String(36), primary_key=True, index=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("required_evidence", sa.JSON(), nullable=False),
        sa.Column("supporting_evidence", sa.JSON(), nullable=False),
        sa.Column("contradicting_evidence", sa.JSON(), nullable=False),
        sa.Column("missing_evidence", sa.JSON(), nullable=False),
        sa.Column("relative_support", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("enterprise_investigation_scenarios")
    op.drop_table("enterprise_evidence_contradictions")
    op.drop_table("enterprise_attack_paths")
    op.drop_table("enterprise_attack_reconstructions")
