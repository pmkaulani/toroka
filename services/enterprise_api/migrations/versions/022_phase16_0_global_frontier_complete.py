"""Phase 16: Global Frontier Defenses Complete Migration.

Creates persistence tables for:
- Singapore MAS 24/7 Customer Emergency Kill Switch (enterprise_customer_kill_switches)
- South Korea FSS Designated Safe Accounts (enterprise_designated_safe_accounts)
- South Korea FSS Delayed ATM Cash-Out (enterprise_atm_delayed_withdrawals)
- Brazil BCB Limit Increase Cooling-Off (enterprise_limit_increase_requests)
- Brazil BCB Pix MED 2.0 5-Layer Cascading Clawback Traces (enterprise_med2_clawback_traces)
- India I4C Helpline 1930 Golden Hour Emergency Intake (enterprise_golden_hour_reports)
- Hong Kong HKMA FPS Scameter Statutory Liability Shield Waivers (enterprise_scameter_waivers)

Revision ID: 022_phase16_0_global_frontier_complete
Revises: 021_phase15_0_global_frontier_controls
"""
from alembic import op
import sqlalchemy as sa

revision = "022_phase16_0_global_frontier_complete"
down_revision = "021_phase15_0_global_frontier_controls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Singapore MAS 24/7 Customer Kill Switch
    op.create_table(
        "enterprise_customer_kill_switches",
        sa.Column("account_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("customer_id", sa.String(100), nullable=False, index=True),
        sa.Column("status", sa.String(50), nullable=False, server_default=sa.text("'ACTIVE'"), index=True),
        sa.Column("channel_initiated", sa.String(50), nullable=False, server_default=sa.text("'MOBILE_PANIC_BUTTON'")),
        sa.Column("activation_reason", sa.Text(), nullable=False),
        sa.Column("revoked_sessions_count", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deactivation_maker_officer", sa.String(100), nullable=True),
        sa.Column("deactivation_checker_officer", sa.String(100), nullable=True),
        sa.Column("deactivation_branch_code", sa.String(50), nullable=True),
        sa.Column("deactivation_notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. South Korea FSS Designated Safe Accounts
    op.create_table(
        "enterprise_designated_safe_accounts",
        sa.Column("registration_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("account_id", sa.String(100), nullable=False, index=True),
        sa.Column("payee_account", sa.String(100), nullable=False, index=True),
        sa.Column("payee_institution", sa.String(100), nullable=False, server_default=sa.text("'Safaricom'")),
        sa.Column("label", sa.String(100), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 3. South Korea FSS Delayed ATM Cash-Out
    op.create_table(
        "enterprise_atm_delayed_withdrawals",
        sa.Column("hold_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("account_id", sa.String(100), nullable=False, index=True),
        sa.Column("inbound_amount", sa.Numeric(18, 4), nullable=False),
        sa.Column("inbound_reference", sa.String(100), nullable=False),
        sa.Column("credit_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hold_expiry_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, server_default=sa.text("'ACTIVE_HOLD'"), index=True),
    )

    # 4. Brazil BCB Limit Increase Cooling-off
    op.create_table(
        "enterprise_limit_increase_requests",
        sa.Column("request_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("account_id", sa.String(100), nullable=False, index=True),
        sa.Column("limit_type", sa.String(50), nullable=False, server_default=sa.text("'DAILY_P2P'")),
        sa.Column("current_limit", sa.Numeric(18, 4), nullable=False),
        sa.Column("requested_limit", sa.Numeric(18, 4), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("is_cancelled", sa.Boolean(), nullable=False, server_default=sa.text("0")),
    )

    # 5. Brazil BCB Pix MED 2.0 5-Layer Cascading Clawback Traces
    op.create_table(
        "enterprise_med2_clawback_traces",
        sa.Column("contestation_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("original_tx_id", sa.String(100), nullable=False, index=True),
        sa.Column("victim_account", sa.String(100), nullable=False, index=True),
        sa.Column("total_stolen_amount", sa.Numeric(18, 4), nullable=False),
        sa.Column("total_clawback_holds_placed", sa.Numeric(18, 4), nullable=False),
        sa.Column("recovery_rate_pct", sa.Float(), nullable=False, server_default=sa.text("0.0")),
        sa.Column("reported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hops_payload", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("status", sa.String(50), nullable=False, server_default=sa.text("'RESOLVED'")),
    )

    # 6. India I4C Helpline 1930 Golden Hour Emergency Intake
    op.create_table(
        "enterprise_golden_hour_reports",
        sa.Column("report_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("victim_account_id", sa.String(100), nullable=False, index=True),
        sa.Column("victim_phone", sa.String(50), nullable=False, index=True),
        sa.Column("scam_category", sa.String(100), nullable=False),
        sa.Column("incident_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reported_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("elapsed_minutes", sa.Float(), nullable=False),
        sa.Column("is_golden_hour", sa.Boolean(), nullable=False),
        sa.Column("total_amount_lost", sa.Numeric(18, 4), nullable=False),
        sa.Column("transaction_references", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("switch_freeze_broadcast_id", sa.String(100), nullable=True),
        sa.Column("switch_status", sa.String(50), nullable=False, server_default=sa.text("'BROADCAST_DISPATCHED'")),
    )

    # 7. Hong Kong HKMA FPS Scameter Statutory Liability Shield Waivers
    op.create_table(
        "enterprise_scameter_waivers",
        sa.Column("waiver_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("account_id", sa.String(100), nullable=False, index=True),
        sa.Column("customer_id", sa.String(100), nullable=False, index=True),
        sa.Column("proxy_id", sa.String(100), nullable=False, index=True),
        sa.Column("risk_level", sa.String(50), nullable=False),
        sa.Column("transfer_amount", sa.Numeric(18, 4), nullable=False),
        sa.Column("signed_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("waiver_hash", sa.String(64), nullable=False),
        sa.Column("is_institution_shielded", sa.Boolean(), nullable=False, server_default=sa.text("1")),
    )


def downgrade() -> None:
    op.drop_table("enterprise_scameter_waivers")
    op.drop_table("enterprise_golden_hour_reports")
    op.drop_table("enterprise_med2_clawback_traces")
    op.drop_table("enterprise_limit_increase_requests")
    op.drop_table("enterprise_atm_delayed_withdrawals")
    op.drop_table("enterprise_designated_safe_accounts")
    op.drop_table("enterprise_customer_kill_switches")
