"""Vault tenant-isolation and atomic consumed grants schema.

Revision ID: 002_vault_tenant_and_grants
Revises: 001_initial_vault
"""
from alembic import op
import sqlalchemy as sa

revision = "002_vault_tenant_and_grants"
down_revision = "001_initial_vault"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Add installation_id to enterprise_identity_vault
    with op.batch_alter_table("enterprise_identity_vault") as batch_op:
        batch_op.add_column(
            sa.Column(
                "installation_id",
                sa.String(100),
                nullable=False,
                server_default="toroka-default-installation",
            )
        )
        batch_op.create_index("ix_vault_installation_id", ["installation_id"])

    # 2. Create enterprise_vault_consumed_grants
    op.create_table(
        "enterprise_vault_consumed_grants",
        sa.Column("installation_id", sa.String(100), primary_key=True),
        sa.Column("grant_id", sa.String(100), primary_key=True),
        sa.Column("case_id", sa.String(100), nullable=False, index=True),
        sa.Column("requester_subject", sa.String(255), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("enterprise_vault_consumed_grants")
    with op.batch_alter_table("enterprise_identity_vault") as batch_op:
        batch_op.drop_index("ix_vault_installation_id")
        batch_op.drop_column("installation_id")
