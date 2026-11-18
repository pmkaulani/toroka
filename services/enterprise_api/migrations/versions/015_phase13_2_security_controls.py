"""Phase 13.2: Security controls, readiness attestation history, signer trust registry, and AI provider governance.

Revision ID: 015_phase13_2_security_controls
Revises: 014_phase13_1_dossier_and_iso20022
"""
from alembic import op
import sqlalchemy as sa

revision = "015_phase13_2_security_controls"
down_revision = "014_phase13_1_dossier_and_iso20022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Readiness attestations: drop table-level constraint and create partial unique index on active row
    with op.batch_alter_table("enterprise_readiness_attestations") as batch_op:
        batch_op.drop_constraint("uq_readiness_attestation", type_="unique")

    op.create_index(
        "uq_readiness_attestation_active",
        "enterprise_readiness_attestations",
        ["installation_id", "release_version", "gate_name"],
        unique=True,
        sqlite_where=sa.text("is_active = 1"),
        postgresql_where=sa.text("is_active IS TRUE"),
    )

    # 2. Institutional Signer Trust Registry table
    op.create_table(
        "enterprise_signer_trust_registry",
        sa.Column("key_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("public_key_pem", sa.Text(), nullable=False),
        sa.Column("algorithm", sa.String(50), nullable=False),
        sa.Column("purpose", sa.String(50), nullable=False, index=True),
        sa.Column("security_level", sa.String(50), nullable=False, server_default=sa.text("'BANK_MANAGED_HSM'")),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("revocation_reason", sa.Text(), nullable=True),
        sa.Column("registered_by", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 3. Validation runs: add execution provenance columns
    with op.batch_alter_table("enterprise_validation_runs") as batch_op:
        batch_op.add_column(sa.Column("execution_provenance_digest", sa.String(64), nullable=True))
        batch_op.add_column(sa.Column("executor_id", sa.String(100), nullable=True))
        batch_op.add_column(sa.Column("is_trusted_execution", sa.Boolean(), nullable=False, server_default=sa.text("0")))

    # 4. In-flight evaluations: add integration_mode
    with op.batch_alter_table("enterprise_inflight_payment_evaluations") as batch_op:
        batch_op.add_column(sa.Column("integration_mode", sa.String(32), nullable=False, server_default=sa.text("'SHADOW'")))

    # 5. AI provider records: add independent review columns
    with op.batch_alter_table("enterprise_ai_provider_records") as batch_op:
        batch_op.add_column(sa.Column("registered_by", sa.String(255), nullable=True))
        batch_op.add_column(sa.Column("approved_by", sa.String(255), nullable=True))
        batch_op.add_column(sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("review_status", sa.String(50), nullable=False, server_default=sa.text("'PENDING_INDEPENDENT_REVIEW'")))
        batch_op.add_column(sa.Column("review_notes", sa.Text(), nullable=True))


def downgrade() -> None:
    # 5. AI provider records
    with op.batch_alter_table("enterprise_ai_provider_records") as batch_op:
        batch_op.drop_column("review_notes")
        batch_op.drop_column("review_status")
        batch_op.drop_column("approved_at")
        batch_op.drop_column("approved_by")
        batch_op.drop_column("registered_by")

    # 4. In-flight evaluations
    with op.batch_alter_table("enterprise_inflight_payment_evaluations") as batch_op:
        batch_op.drop_column("integration_mode")

    # 3. Validation runs
    with op.batch_alter_table("enterprise_validation_runs") as batch_op:
        batch_op.drop_column("is_trusted_execution")
        batch_op.drop_column("executor_id")
        batch_op.drop_column("execution_provenance_digest")

    # 2. Institutional Signer Trust Registry
    op.drop_table("enterprise_signer_trust_registry")

    # 1. Readiness attestations
    op.drop_index(
        "uq_readiness_attestation_active",
        table_name="enterprise_readiness_attestations",
    )
    with op.batch_alter_table("enterprise_readiness_attestations") as batch_op:
        batch_op.create_unique_constraint(
            "uq_readiness_attestation",
            ["installation_id", "release_version", "gate_name"],
        )
