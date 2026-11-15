"""Intelligence events, entity relationships, risk signals, and investigation bundles.

Revision ID: 004_intelligence
Revises: 003_integrations
"""
from alembic import op
import sqlalchemy as sa

revision = "004_intelligence"
down_revision = "003_integrations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. enterprise_intelligence_events
    op.create_table(
        "enterprise_intelligence_events",
        sa.Column("event_id", sa.String(255), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("event_type", sa.String(100), nullable=False, index=True),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("actor", sa.String(255), nullable=True, index=True),
        sa.Column("subject", sa.String(255), nullable=True, index=True),
        sa.Column("source_system", sa.String(100), nullable=True, index=True),
        sa.Column("source_record_id", sa.String(255), nullable=True),
        sa.Column("entities", sa.JSON(), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("provenance_digest", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. enterprise_intelligence_relationships
    op.create_table(
        "enterprise_intelligence_relationships",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("source_type", sa.String(50), nullable=False),
        sa.Column("source_id", sa.String(255), nullable=False, index=True),
        sa.Column("target_type", sa.String(50), nullable=False),
        sa.Column("target_id", sa.String(255), nullable=False, index=True),
        sa.Column("relationship_type", sa.String(100), nullable=False, index=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("source_system", sa.String(100), nullable=True),
        sa.Column("source_record_id", sa.String(255), nullable=True),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "installation_id", "source_type", "source_id", "target_type", "target_id", "relationship_type",
            name="uq_intelligence_relationship_edge",
        ),
    )

    # 3. enterprise_intelligence_signals
    op.create_table(
        "enterprise_intelligence_signals",
        sa.Column("signal_id", sa.String(255), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("case_id", sa.String(36), nullable=True, index=True),
        sa.Column("signal_type", sa.String(100), nullable=False, index=True),
        sa.Column("severity", sa.String(30), nullable=False, index=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("event_ids", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("alternative_explanations", sa.JSON(), nullable=False),
        sa.Column("missing_evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 4. enterprise_investigation_bundles
    op.create_table(
        "enterprise_investigation_bundles",
        sa.Column("investigation_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("case_id", sa.String(36), nullable=True, index=True),
        sa.Column("anchor_event_ids", sa.JSON(), nullable=False),
        sa.Column("finding", sa.String(255), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("requires_human_review", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("bundle_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )

    # 5. enterprise_investigation_hypotheses
    op.create_table(
        "enterprise_investigation_hypotheses",
        sa.Column("hypothesis_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("case_id", sa.String(36), nullable=False, index=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="open", index=True),
        sa.Column("supporting_signal_ids", sa.JSON(), nullable=False),
        sa.Column("contradicting_signal_ids", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("investigator_note", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("enterprise_investigation_hypotheses")
    op.drop_table("enterprise_investigation_bundles")
    op.drop_table("enterprise_intelligence_signals")
    op.drop_table("enterprise_intelligence_relationships")
    op.drop_table("enterprise_intelligence_events")
