"""Behavioral baselines, deviations, anomalies, and model governance.

Revision ID: 005_baselines
Revises: 004_intelligence
"""
from alembic import op
import sqlalchemy as sa

revision = "005_baselines"
down_revision = "004_intelligence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. enterprise_behavioral_profiles
    op.create_table(
        "enterprise_behavioral_profiles",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("subject_id", sa.String(255), nullable=False, index=True),
        sa.Column("subject_type", sa.String(50), nullable=False, index=True),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("maturity", sa.String(30), nullable=False, server_default="insufficient", index=True),
        sa.Column("observation_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("observation_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("dimensions", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "installation_id", "subject_type", "subject_id",
            name="uq_behavioral_profile_subject",
        ),
    )

    # 2. enterprise_behavioral_anomalies
    op.create_table(
        "enterprise_behavioral_anomalies",
        sa.Column("anomaly_id", sa.String(255), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("case_id", sa.String(36), nullable=True, index=True),
        sa.Column("subject_id", sa.String(255), nullable=False, index=True),
        sa.Column("dimension", sa.String(100), nullable=False, index=True),
        sa.Column("observed_value", sa.Float(), nullable=False),
        sa.Column("expected_value", sa.Float(), nullable=False),
        sa.Column("deviation", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(30), nullable=False, index=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("baseline_sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("baseline_mature", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("limitations", sa.JSON(), nullable=False),
        sa.Column("provenance", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 3. enterprise_detection_methods
    op.create_table(
        "enterprise_detection_methods",
        sa.Column("method_id", sa.String(100), primary_key=True),
        sa.Column("version", sa.String(50), primary_key=True),
        sa.Column("status", sa.String(30), nullable=False, index=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("training_data", sa.Text(), nullable=True),
        sa.Column("validation_reference", sa.String(255), nullable=True),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("limitations", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 4. enterprise_baseline_admissions
    op.create_table(
        "enterprise_baseline_admissions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("event_id", sa.String(255), nullable=False, index=True),
        sa.Column("subject_id", sa.String(255), nullable=False, index=True),
        sa.Column("accepted", sa.Boolean(), nullable=False, index=True),
        sa.Column("reason", sa.String(100), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("enterprise_baseline_admissions")
    op.drop_table("enterprise_detection_methods")
    op.drop_table("enterprise_behavioral_anomalies")
    op.drop_table("enterprise_behavioral_profiles")
