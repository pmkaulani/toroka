"""Phase 14.2: Federated Mule Directory & Hash-Linked Interbank Blacklist.

Revision ID: 018_phase14_2_federated_mules
Revises: 017_phase14_1_telecom_scam_signals
"""
from alembic import op
import sqlalchemy as sa

revision = "018_phase14_2_federated_mules"
down_revision = "017_phase14_1_telecom_scam_signals"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "enterprise_federated_mule_directory",
        sa.Column("entry_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("entity_type", sa.String(50), nullable=False, server_default=sa.text("'BANK_ACCOUNT'")),
        sa.Column("blinded_token", sa.String(64), nullable=False, index=True),
        sa.Column("cleartext_preview", sa.String(100), nullable=False),
        sa.Column("severity_tier", sa.String(50), nullable=False, server_default=sa.text("'CORROBORATED_MULE'")),
        sa.Column("originating_bank_bic", sa.String(50), nullable=False, server_default=sa.text("''")),
        sa.Column("reason_code", sa.String(100), nullable=False, server_default=sa.text("'SUSPICIOUS_MULE_ACTIVITY'")),
        sa.Column("dossier_reference", sa.String(100), nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default=sa.text("'ACTIVE'"), index=True),
        sa.Column("registered_by", sa.String(255), nullable=True),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("enterprise_federated_mule_directory")
