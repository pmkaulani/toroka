"""Phase 14.3: Multi-Tiered Mule Tracing & Graph Cascade Persistence.

Revision ID: 019_phase14_3_mule_cascade
Revises: 018_phase14_2_federated_mules
"""
from alembic import op
import sqlalchemy as sa

revision = "019_phase14_3_mule_cascade"
down_revision = "018_phase14_2_federated_mules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "enterprise_mule_cascade_traces",
        sa.Column("trace_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("root_account", sa.String(100), nullable=False, index=True),
        sa.Column("root_transaction_id", sa.String(100), nullable=True, index=True),
        sa.Column("root_fraud_amount", sa.Numeric(18, 4), nullable=False),
        sa.Column("currency", sa.String(10), nullable=False, server_default=sa.text("'KES'")),
        sa.Column("max_depth_reached", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("total_nodes_identified", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("total_frozen_or_held_amount", sa.Numeric(18, 4), nullable=False, server_default=sa.text("0.0")),
        sa.Column("recovery_potential_ratio", sa.Float(), nullable=False, server_default=sa.text("0.0")),
        sa.Column("graph_topology", sa.JSON(), nullable=False),
        sa.Column("directives", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, server_default=sa.text("'ACTIVE'"), index=True),
        sa.Column("initiated_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("enterprise_mule_cascade_traces")
