"""Case closure proposals and run installation scoping.

Revision ID: 002_case_closure_proposals
Revises: 001_initial_enterprise
"""
from alembic import op
import sqlalchemy as sa

revision = "002_case_closure_proposals"
down_revision = "001_initial_enterprise"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. enterprise_case_closure_proposals
    op.create_table(
        "enterprise_case_closure_proposals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "case_id",
            sa.String(36),
            sa.ForeignKey("enterprise_cases.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("requested_by", sa.String(255), nullable=False),
        sa.Column("disposition", sa.String(64), nullable=False),
        sa.Column("closing_note", sa.Text(), nullable=False),
        sa.Column("alternatives_considered", sa.Text(), nullable=True),
        sa.Column("expected_case_version", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="pending"),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column("review_note", sa.Text(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending','approved','rejected','withdrawn')",
            name="ck_closure_status",
        ),
    )
    op.create_index(
        "ix_closure_case_status",
        "enterprise_case_closure_proposals",
        ["case_id", "status"],
    )

    # 2. Add installation_id to enterprise_runs
    op.add_column(
        "enterprise_runs",
        sa.Column(
            "installation_id",
            sa.String(100),
            nullable=False,
            server_default="toroka-default-installation",
        ),
    )
    op.create_index(
        "ix_enterprise_runs_installation_id",
        "enterprise_runs",
        ["installation_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_enterprise_runs_installation_id", table_name="enterprise_runs")
    op.drop_column("enterprise_runs", "installation_id")
    op.drop_index("ix_closure_case_status", table_name="enterprise_case_closure_proposals")
    op.drop_table("enterprise_case_closure_proposals")
