"""Initial Toroka Enterprise Identity Vault schema.

Revision ID: 001_initial_vault
Revises: 
"""
from alembic import op
import sqlalchemy as sa

revision = "001_initial_vault"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "enterprise_identity_vault",
        sa.Column("pseudonym", sa.String(255), primary_key=True),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("key_version", sa.String(32), nullable=False, server_default="v1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("enterprise_identity_vault")
