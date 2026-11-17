"""Phase 12.6: Production Integrity, Readiness Attestations, Report Provenance, and Two-Person Entity Link Controls.

Revision ID: 012_phase12_6_integrity_controls
Revises: 011_production_governance
"""
from alembic import op
import sqlalchemy as sa

revision = "012_phase12_6_integrity_controls"
down_revision = "011_production_governance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. enterprise_readiness_attestations table
    op.create_table(
        "enterprise_readiness_attestations",
        sa.Column("attestation_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("release_version", sa.String(50), nullable=False, index=True),
        sa.Column("gate_name", sa.String(100), nullable=False, index=True),
        sa.Column("status", sa.String(30), nullable=False, index=True),
        sa.Column("verified_by", sa.String(255), nullable=False),
        sa.Column("verified_role", sa.String(100), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("evidence_reference", sa.String(255), nullable=False),
        sa.Column("evidence_digest", sa.String(64), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("installation_id", "release_version", "gate_name", name="uq_readiness_attestation"),
    )

    # 2. Add columns to enterprise_governed_components
    with op.batch_alter_table("enterprise_governed_components") as batch_op:
        batch_op.add_column(sa.Column("approval_record_id", sa.String(100), nullable=True))
        batch_op.add_column(sa.Column("approved_validation_run_id", sa.String(100), nullable=True))
        batch_op.add_column(sa.Column("approved_validation_digest", sa.String(64), nullable=True))
        batch_op.add_column(sa.Column("approval_rationale", sa.Text(), nullable=True))
        batch_op.create_unique_constraint("uq_gov_comp_approval_record", ["approval_record_id"])

    # 3. Add columns to enterprise_copilot_report_drafts
    with op.batch_alter_table("enterprise_copilot_report_drafts") as batch_op:
        batch_op.add_column(sa.Column("created_by", sa.String(255), nullable=False, server_default="system"))
        batch_op.add_column(sa.Column("edited_by", sa.String(255), nullable=True))
        batch_op.add_column(sa.Column("edit_version", sa.Integer(), nullable=False, server_default="0"))
        batch_op.add_column(sa.Column("content_digest", sa.String(64), nullable=False, server_default=""))
        batch_op.add_column(sa.Column("grounding_status", sa.String(30), nullable=False, server_default="UNVERIFIED"))
        batch_op.add_column(sa.Column("grounding_report", sa.JSON(), nullable=False, server_default="{}"))
        batch_op.add_column(sa.Column("evidence_context_snapshot", sa.JSON(), nullable=False, server_default="{}"))

    # 4. Add columns to enterprise_entity_link_candidates
    with op.batch_alter_table("enterprise_entity_link_candidates") as batch_op:
        batch_op.add_column(sa.Column("proposed_by", sa.String(255), nullable=True))
        batch_op.add_column(sa.Column("first_reviewed_by", sa.String(255), nullable=True))
        batch_op.add_column(sa.Column("first_reviewed_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("first_review_rationale", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("second_reviewed_by", sa.String(255), nullable=True))
        batch_op.add_column(sa.Column("second_reviewed_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("second_review_rationale", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("evidence_digest", sa.String(64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("enterprise_entity_link_candidates") as batch_op:
        batch_op.drop_column("evidence_digest")
        batch_op.drop_column("second_review_rationale")
        batch_op.drop_column("second_reviewed_at")
        batch_op.drop_column("second_reviewed_by")
        batch_op.drop_column("first_review_rationale")
        batch_op.drop_column("first_reviewed_at")
        batch_op.drop_column("first_reviewed_by")
        batch_op.drop_column("proposed_by")

    with op.batch_alter_table("enterprise_copilot_report_drafts") as batch_op:
        batch_op.drop_column("evidence_context_snapshot")
        batch_op.drop_column("grounding_report")
        batch_op.drop_column("grounding_status")
        batch_op.drop_column("content_digest")
        batch_op.drop_column("edit_version")
        batch_op.drop_column("edited_by")
        batch_op.drop_column("created_by")

    with op.batch_alter_table("enterprise_governed_components") as batch_op:
        batch_op.drop_constraint("uq_gov_comp_approval_record", type_="unique")
        batch_op.drop_column("approval_rationale")
        batch_op.drop_column("approved_validation_digest")
        batch_op.drop_column("approved_validation_run_id")
        batch_op.drop_column("approval_record_id")

    op.drop_table("enterprise_readiness_attestations")
