"""Investigation Intelligence Layer and Tenant Security Hardening Migration.

Creates tables for:
- enterprise_evidence_artifacts
- enterprise_investigation_entities
- enterprise_investigation_relationships
- enterprise_investigation_transactions
- enterprise_investigation_findings
- enterprise_referral_packs

Adds tenant-isolation columns to:
- enterprise_runs (installation_id)
- enterprise_reveal_requests (reveal_token)

Revision ID: 023_investigation_intelligence_and_security_hardening
Revises: 022_phase16_0_global_frontier_complete
"""
from alembic import op
import sqlalchemy as sa

revision = "023_investigation_intelligence_and_security_hardening"
down_revision = "022_phase16_0_global_frontier_complete"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Update enterprise_runs with installation_id
    with op.batch_alter_table("enterprise_runs") as batch_op:
        batch_op.add_column(
            sa.Column(
                "installation_id",
                sa.String(100),
                nullable=False,
                server_default="toroka-default-installation",
            )
        )
        batch_op.create_index("ix_enterprise_runs_installation_id", ["installation_id"])

    # 2. Update enterprise_reveal_requests with reveal_token
    with op.batch_alter_table("enterprise_reveal_requests") as batch_op:
        batch_op.add_column(
            sa.Column("reveal_token", sa.Text(), nullable=True)
        )

    # 3. enterprise_evidence_artifacts
    op.create_table(
        "enterprise_evidence_artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("enterprise_cases.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("source_type", sa.String(40), nullable=False),
        sa.Column("source_system", sa.String(120), nullable=False),
        sa.Column("source_record_ref", sa.String(300), nullable=True),
        sa.Column("source_locator_ciphertext", sa.Text(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_by", sa.String(160), nullable=False),
        sa.Column("source_timezone", sa.String(80), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("media_type", sa.String(120), nullable=True),
        sa.Column("extractor_name", sa.String(120), nullable=True),
        sa.Column("extractor_version", sa.String(80), nullable=True),
        sa.Column("state", sa.String(30), nullable=False, server_default="observed"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 4. enterprise_investigation_entities
    op.create_table(
        "enterprise_investigation_entities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("enterprise_cases.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("identifier_token", sa.String(180), nullable=False),
        sa.Column("display_label", sa.String(180), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sensitivity", sa.String(30), nullable=False, server_default="restricted"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("installation_id", "case_id", "identifier_token", name="uq_entity_inst_case_token"),
    )

    # 5. enterprise_investigation_relationships
    op.create_table(
        "enterprise_investigation_relationships",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("enterprise_cases.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("source_entity_id", sa.String(36), sa.ForeignKey("enterprise_investigation_entities.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("target_entity_id", sa.String(36), sa.ForeignKey("enterprise_investigation_entities.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("relationship_type", sa.String(80), nullable=False),
        sa.Column("state", sa.String(30), nullable=False, server_default="hypothesis"),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 6. enterprise_investigation_transactions
    op.create_table(
        "enterprise_investigation_transactions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("enterprise_cases.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("source_entity_id", sa.String(36), sa.ForeignKey("enterprise_investigation_entities.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("destination_entity_id", sa.String(36), sa.ForeignKey("enterprise_investigation_entities.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("amount", sa.Numeric(20, 4), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("source_timezone", sa.String(80), nullable=False),
        sa.Column("channel", sa.String(80), nullable=False),
        sa.Column("source_system", sa.String(120), nullable=False),
        sa.Column("source_record_ref", sa.String(300), nullable=False),
        sa.Column("evidence_id", sa.String(36), sa.ForeignKey("enterprise_evidence_artifacts.id", ondelete="RESTRICT"), nullable=False, index=True),
        sa.Column("reference_token", sa.String(180), nullable=True),
        sa.Column("event_type", sa.String(40), nullable=False, server_default="transfer"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 7. enterprise_investigation_findings
    op.create_table(
        "enterprise_investigation_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("enterprise_cases.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("rule_id", sa.String(100), nullable=False),
        sa.Column("rule_version", sa.String(40), nullable=False),
        sa.Column("title", sa.String(180), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("state", sa.String(30), nullable=False, server_default="hypothesis"),
        sa.Column("evidence_ids", sa.JSON(), nullable=False),
        sa.Column("counter_evidence_ids", sa.JSON(), nullable=False),
        sa.Column("unresolved_questions", sa.JSON(), nullable=False),
        sa.Column("recommended_human_action", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 8. enterprise_referral_packs
    op.create_table(
        "enterprise_referral_packs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("enterprise_cases.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("status", sa.String(30), nullable=False, server_default="preview"),
        sa.Column("pack_hash", sa.String(64), nullable=False),
        sa.Column("recipient_org", sa.String(200), nullable=False),
        sa.Column("purpose", sa.String(500), nullable=False),
        sa.Column("legal_basis", sa.String(500), nullable=False),
        sa.Column("generating_principal", sa.String(255), nullable=False),
        sa.Column("approving_principals", sa.JSON(), nullable=False),
        sa.Column("manifest_data", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("enterprise_referral_packs")
    op.drop_table("enterprise_investigation_findings")
    op.drop_table("enterprise_investigation_transactions")
    op.drop_table("enterprise_investigation_relationships")
    op.drop_table("enterprise_investigation_entities")
    op.drop_table("enterprise_evidence_artifacts")

    with op.batch_alter_table("enterprise_reveal_requests") as batch_op:
        batch_op.drop_column("reveal_token")

    with op.batch_alter_table("enterprise_runs") as batch_op:
        batch_op.drop_index("ix_enterprise_runs_installation_id")
        batch_op.drop_column("installation_id")
