"""Build 4: moderator dispositions for derived campaign candidates.

Revision ID: 0005
Revises: 0004
"""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "campaign_reviews",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("campaign_id", sa.String(length=40), nullable=False),
        sa.Column("campaign_type", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("reason_code", sa.String(length=40), nullable=True),
        sa.Column("notes_encrypted", sa.Text(), nullable=True),
        sa.Column("reviewer_id", sa.String(length=36), nullable=False),
        sa.Column("reviewed_at", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(["reviewer_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("campaign_id"),
    )
    with op.batch_alter_table("campaign_reviews") as batch_op:
        batch_op.create_index("ix_campaign_reviews_campaign_id", ["campaign_id"], unique=True)


def downgrade() -> None:
    op.drop_table("campaign_reviews")
