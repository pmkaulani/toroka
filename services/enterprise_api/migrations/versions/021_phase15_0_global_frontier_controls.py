"""Phase 15: Global Frontier Hardening Migration.

Creates persistence tables for:
- Singapore MAS Money Lock Vault Partitioning (enterprise_money_lock_accounts)
- Brazil BCB 72-Hour Precautionary Block (enterprise_precautionary_holds)
- India NPCI Cryptographic SIM & Hardware Binding (enterprise_sim_bindings)
- Extends enterprise_inflight_payment_evaluations with BioCatch RAT & Coercion Telemetry.

Revision ID: 021_phase15_0_global_frontier_controls
Revises: 020_phase14_4_sic5_parallel
"""
from alembic import op
import sqlalchemy as sa

revision = "021_phase15_0_global_frontier_controls"
down_revision = "020_phase14_4_sic5_parallel"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Singapore MAS Money Lock Accounts
    op.create_table(
        "enterprise_money_lock_accounts",
        sa.Column("account_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("currency", sa.String(10), nullable=False, server_default=sa.text("'KES'")),
        sa.Column("total_balance", sa.Numeric(18, 4), nullable=False, server_default=sa.text("0.0")),
        sa.Column("locked_vault_balance", sa.Numeric(18, 4), nullable=False, server_default=sa.text("0.0")),
        sa.Column("available_balance", sa.Numeric(18, 4), nullable=False, server_default=sa.text("0.0")),
        sa.Column("status", sa.String(50), nullable=False, server_default=sa.text("'UNLOCKED'"), index=True),
        sa.Column("last_locked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_unlocked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("unlock_channel", sa.String(50), nullable=True),
        sa.Column("unlock_officer_id", sa.String(100), nullable=True),
        sa.Column("unlock_station_id", sa.String(100), nullable=True),
        sa.Column("dual_authorizer_id", sa.String(100), nullable=True),
        sa.Column("audit_trail", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. Brazil BCB Bloqueio Cautelar Precautionary Holds
    op.create_table(
        "enterprise_precautionary_holds",
        sa.Column("hold_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("tx_id", sa.String(100), nullable=False, index=True),
        sa.Column("amount", sa.Numeric(18, 4), nullable=False),
        sa.Column("currency", sa.String(10), nullable=False, server_default=sa.text("'KES'")),
        sa.Column("debtor_account", sa.String(100), nullable=False, index=True),
        sa.Column("creditor_account", sa.String(100), nullable=False, index=True),
        sa.Column("state", sa.String(50), nullable=False, server_default=sa.text("'ACTIVE_HOLD_72H'"), index=True),
        sa.Column("placed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("statutory_basis", sa.String(100), nullable=False, server_default=sa.text("'RESOLUCAO_BCB_493_2025_ART_39'")),
        sa.Column("decision_officer_id", sa.String(100), nullable=True),
        sa.Column("resolution_notes", sa.Text(), nullable=True),
        sa.Column("camt056_xml", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 3. India NPCI SIM & Hardware Bindings
    op.create_table(
        "enterprise_sim_bindings",
        sa.Column("account_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("bound_device_imei_hash", sa.String(64), nullable=False),
        sa.Column("bound_sim_iccid_hash", sa.String(64), nullable=False),
        sa.Column("carrier_name", sa.String(50), nullable=False, server_default=sa.text("'Safaricom'")),
        sa.Column("status", sa.String(50), nullable=False, server_default=sa.text("'BOUND_TRUSTED'"), index=True),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_verified_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 4. Inflight Payment Evaluations extension
    with op.batch_alter_table("enterprise_inflight_payment_evaluations") as batch_op:
        batch_op.add_column(sa.Column("biometrics_verdict", sa.String(50), nullable=True))
        batch_op.add_column(sa.Column("biometrics_risk_score", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("is_rat_detected", sa.Boolean(), nullable=False, server_default=sa.text("0")))
        batch_op.add_column(sa.Column("sim_binding_status", sa.String(50), nullable=True))
        batch_op.add_column(sa.Column("is_nighttime_breach", sa.Boolean(), nullable=False, server_default=sa.text("0")))


def downgrade() -> None:
    with op.batch_alter_table("enterprise_inflight_payment_evaluations") as batch_op:
        batch_op.drop_column("is_nighttime_breach")
        batch_op.drop_column("sim_binding_status")
        batch_op.drop_column("is_rat_detected")
        batch_op.drop_column("biometrics_risk_score")
        batch_op.drop_column("biometrics_verdict")

    op.drop_table("enterprise_sim_bindings")
    op.drop_table("enterprise_precautionary_holds")
    op.drop_table("enterprise_money_lock_accounts")
