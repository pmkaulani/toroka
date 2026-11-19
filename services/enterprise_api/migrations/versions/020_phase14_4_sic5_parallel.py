"""Phase 14.4: Swiss SIC5 Sub-50ms Parallel Clearing Engine Telemetry.

Revision ID: 020_phase14_4_sic5_parallel
Revises: 019_phase14_3_mule_cascade
"""
from alembic import op
import sqlalchemy as sa

revision = "020_phase14_4_sic5_parallel"
down_revision = "019_phase14_3_mule_cascade"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("enterprise_inflight_payment_evaluations") as batch_op:
        batch_op.add_column(sa.Column("is_parallel_pipeline", sa.Boolean(), nullable=False, server_default=sa.text("0")))
        batch_op.add_column(sa.Column("sla_budget_ms", sa.Float(), nullable=False, server_default=sa.text("45.0")))
        batch_op.add_column(sa.Column("is_sla_compliant", sa.Boolean(), nullable=False, server_default=sa.text("1")))
        batch_op.add_column(sa.Column("feed_latencies", sa.JSON(), nullable=False, server_default=sa.text("'{}'")))


def downgrade() -> None:
    with op.batch_alter_table("enterprise_inflight_payment_evaluations") as batch_op:
        batch_op.drop_column("feed_latencies")
        batch_op.drop_column("is_sla_compliant")
        batch_op.drop_column("sla_budget_ms")
        batch_op.drop_column("is_parallel_pipeline")
