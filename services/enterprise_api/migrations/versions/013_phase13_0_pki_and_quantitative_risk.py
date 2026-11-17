"""Phase 13.0: PKI Digital Signatures, Quantitative Model Risk (PSI/KS) and Champion-Challenger Shadow Governance.

Revision ID: 013_phase13_0_pki_and_quantitative_risk
Revises: 012_phase12_6_integrity_controls
"""
from alembic import op
import sqlalchemy as sa

revision = "013_phase13_0_pki_and_quantitative_risk"
down_revision = "012_phase12_6_integrity_controls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. enterprise_quantitative_drift_evaluations table
    op.create_table(
        "enterprise_quantitative_drift_evaluations",
        sa.Column("evaluation_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("component_id", sa.String(100), nullable=False, index=True),
        sa.Column("component_version", sa.String(50), nullable=False),
        sa.Column("psi_score", sa.Float(), nullable=False),
        sa.Column("psi_severity", sa.String(30), nullable=False, index=True),
        sa.Column("requires_mitigation", sa.Boolean(), nullable=False, server_default=sa.text("false"), index=True),
        sa.Column("ks_statistic", sa.Float(), nullable=False),
        sa.Column("ks_p_value", sa.Float(), nullable=False),
        sa.Column("ks_drift_detected", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("wasserstein_distance", sa.Float(), nullable=False),
        sa.Column("fairness_compliant", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_compliant", sa.Boolean(), nullable=False, server_default=sa.text("true"), index=True),
        sa.Column("governance_findings", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("evaluation_details", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("evaluated_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. enterprise_champion_challenger_runs table
    op.create_table(
        "enterprise_champion_challenger_runs",
        sa.Column("run_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("component_id", sa.String(100), nullable=False, index=True),
        sa.Column("champion_version", sa.String(50), nullable=False),
        sa.Column("challenger_version", sa.String(50), nullable=False),
        sa.Column("decision", sa.String(50), nullable=False, index=True),
        sa.Column("is_promotable", sa.Boolean(), nullable=False, server_default=sa.text("false"), index=True),
        sa.Column("fdr_delta", sa.Float(), nullable=False),
        sa.Column("f1_ratio", sa.Float(), nullable=False),
        sa.Column("latency_p95_delta_ms", sa.Float(), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("champion_metrics", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("challenger_metrics", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("evaluated_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 3. Add signature_bundle to enterprise_production_releases
    with op.batch_alter_table("enterprise_production_releases") as batch_op:
        batch_op.add_column(sa.Column("signature_bundle", sa.JSON(), nullable=True))

    # 4. Add signature_bundle and merkle_proof to enterprise_evidence_passports
    with op.batch_alter_table("enterprise_evidence_passports") as batch_op:
        batch_op.add_column(sa.Column("signature_bundle", sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column("merkle_proof", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("enterprise_evidence_passports") as batch_op:
        batch_op.drop_column("merkle_proof")
        batch_op.drop_column("signature_bundle")

    with op.batch_alter_table("enterprise_production_releases") as batch_op:
        batch_op.drop_column("signature_bundle")

    op.drop_table("enterprise_champion_challenger_runs")
    op.drop_table("enterprise_quantitative_drift_evaluations")
