"""Phase 14.0: Confirmation of Payee (CoP) Inquiries & Outcomes.

Revision ID: 016_phase14_0_cop_inquiries
Revises: 015_phase13_2_security_controls
"""
from alembic import op
import sqlalchemy as sa

revision = "016_phase14_0_cop_inquiries"
down_revision = "015_phase13_2_security_controls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "enterprise_cop_inquiries",
        sa.Column("inquiry_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("intended_name", sa.String(255), nullable=False),
        sa.Column("registered_name", sa.String(255), nullable=False),
        sa.Column("account_number", sa.String(100), nullable=False, index=True),
        sa.Column("account_type", sa.String(50), nullable=False, server_default=sa.text("'PERSONAL'")),
        sa.Column("clearing_rail", sa.String(50), nullable=False, server_default=sa.text("'PESALINK'")),
        sa.Column("bank_bic", sa.String(50), nullable=False, server_default=sa.text("''")),
        sa.Column("status", sa.String(50), nullable=False, index=True),
        sa.Column("match_score", sa.Float(), nullable=False),
        sa.Column("suggested_name", sa.String(255), nullable=True),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("advisory_message", sa.Text(), nullable=False),
        sa.Column("inquiry_digest", sa.String(64), nullable=False),
        sa.Column("actor_subject", sa.String(255), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("enterprise_cop_inquiries")
