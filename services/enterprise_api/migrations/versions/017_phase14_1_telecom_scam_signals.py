"""Phase 14.1: Telecom Scam Signal Live Telemetry & Coercion Intelligence.

Revision ID: 017_phase14_1_telecom_scam_signals
Revises: 016_phase14_0_cop_inquiries
"""
from alembic import op
import sqlalchemy as sa

revision = "017_phase14_1_telecom_scam_signals"
down_revision = "016_phase14_0_cop_inquiries"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "enterprise_telecom_scam_signals",
        sa.Column("query_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("msisdn", sa.String(50), nullable=False, index=True),
        sa.Column("carrier", sa.String(50), nullable=False, server_default=sa.text("'SAFARICOM'")),
        sa.Column("call_status", sa.String(50), nullable=False, server_default=sa.text("'IDLE'")),
        sa.Column("call_duration_seconds", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("sim_swap_status", sa.String(50), nullable=False, server_default=sa.text("'NO_SWAP'")),
        sa.Column("sim_swap_age_hours", sa.Float(), nullable=True),
        sa.Column("scam_signal_score", sa.Float(), nullable=False, server_default=sa.text("0.0")),
        sa.Column("is_high_coercion_risk", sa.Boolean(), nullable=False, server_default=sa.text("0"), index=True),
        sa.Column("coercion_indicators", sa.JSON(), nullable=False),
        sa.Column("advisory_action", sa.String(100), nullable=False),
        sa.Column("statutory_warning", sa.Text(), nullable=True),
        sa.Column("query_digest", sa.String(64), nullable=False),
        sa.Column("actor_subject", sa.String(255), nullable=True),
        sa.Column("queried_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("enterprise_telecom_scam_signals")
