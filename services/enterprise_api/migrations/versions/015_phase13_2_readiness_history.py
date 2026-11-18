"""Phase 13.2: Preserve readiness attestation history safely.

Revision ID: 015_phase13_2_readiness_history
Revises: 014_phase13_1_dossier_and_iso20022
"""
from alembic import op
import sqlalchemy as sa

revision = "015_phase13_2_readiness_history"
down_revision = "014_phase13_1_dossier_and_iso20022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The former unconditional unique constraint prevented a new attestation
    # from being inserted after an older row had been marked inactive.
    with op.batch_alter_table("enterprise_readiness_attestations") as batch_op:
        batch_op.drop_constraint("uq_readiness_attestation", type_="unique")
    # Keep the history append-only, but prevent concurrent writers from
    # creating two active attestations for the same release and gate.
    op.create_index(
        "uq_readiness_attestation_active",
        "enterprise_readiness_attestations",
        ["installation_id", "release_version", "gate_name"],
        unique=True,
        sqlite_where=sa.text("is_active = 1"),
        postgresql_where=sa.text("is_active IS TRUE"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_readiness_attestation_active",
        table_name="enterprise_readiness_attestations",
    )
    # Downgrade may fail if history contains multiple rows for a release/gate.
    with op.batch_alter_table("enterprise_readiness_attestations") as batch_op:
        batch_op.create_unique_constraint(
            "uq_readiness_attestation",
            ["installation_id", "release_version", "gate_name"],
        )
