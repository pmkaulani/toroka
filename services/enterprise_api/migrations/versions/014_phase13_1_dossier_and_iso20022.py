"""Phase 13.1: Court-Ready Forensic Evidence Dossiers (Sec 106B) and ISO 20022 In-Flight Evaluations.

Revision ID: 014_phase13_1_dossier_and_iso20022
Revises: 013_phase13_0_pki_and_quantitative_risk
"""
from alembic import op
import sqlalchemy as sa

revision = "014_phase13_1_dossier_and_iso20022"
down_revision = "013_phase13_0_pki_and_quantitative_risk"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. enterprise_forensic_dossiers table
    op.create_table(
        "enterprise_forensic_dossiers",
        sa.Column("dossier_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("case_id", sa.String(36), nullable=False, index=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("incident_type", sa.String(100), nullable=False),
        sa.Column("fraud_loss_amount", sa.Float(), nullable=False, server_default=sa.text("0.0")),
        sa.Column("currency", sa.String(10), nullable=False, server_default=sa.text("'KES'")),
        sa.Column("examiner_subject", sa.String(255), nullable=False),
        sa.Column("examiner_role", sa.String(100), nullable=False),
        sa.Column("case_summary", sa.Text(), nullable=False),
        sa.Column("attack_path_summary", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("identified_mule_nodes", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("evidence_records", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("chain_of_custody", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("section_106b_certificate", sa.JSON(), nullable=True),
        sa.Column("dossier_digest", sa.String(64), nullable=False),
        sa.Column("signature_bundle", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default=sa.text("'SEALED'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. enterprise_inflight_payment_evaluations table
    op.create_table(
        "enterprise_inflight_payment_evaluations",
        sa.Column("evaluation_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("end_to_end_id", sa.String(100), nullable=False, index=True),
        sa.Column("clearing_rail", sa.String(50), nullable=False),
        sa.Column("amount", sa.Float(), nullable=False),
        sa.Column("currency", sa.String(10), nullable=False, server_default=sa.text("'KES'")),
        sa.Column("debtor_account", sa.String(100), nullable=False),
        sa.Column("creditor_account", sa.String(100), nullable=False, index=True),
        sa.Column("decision", sa.String(50), nullable=False, index=True),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("risk_tier", sa.String(30), nullable=False),
        sa.Column("triggered_rules", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("recommended_action", sa.Text(), nullable=False),
        sa.Column("latency_ms", sa.Float(), nullable=False),
        sa.Column("evaluated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("enterprise_inflight_payment_evaluations")
    op.drop_table("enterprise_forensic_dossiers")
