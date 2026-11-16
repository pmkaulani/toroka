"""Counterfactual investigation simulator, strategies, outcomes, runs, and dual approvals.

Revision ID: 007_counterfactual_simulator
Revises: 006_attack_reconstruction
"""
from alembic import op
import sqlalchemy as sa

revision = "007_counterfactual_simulator"
down_revision = "006_attack_reconstruction"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. enterprise_simulation_strategies
    op.create_table(
        "enterprise_simulation_strategies",
        sa.Column("strategy_id", sa.String(100), primary_key=True),
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("rules_enabled", sa.JSON(), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("min_severity", sa.String(30), nullable=False, server_default="medium"),
        sa.Column("min_confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("status", sa.String(30), nullable=False, server_default="draft", index=True),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. enterprise_simulation_case_outcomes
    op.create_table(
        "enterprise_simulation_case_outcomes",
        sa.Column("case_id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("label", sa.String(32), nullable=False, index=True),
        sa.Column("first_fraud_event_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("adjudicated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("adjudicated_by", sa.String(255), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
    )

    # 3. enterprise_simulation_runs
    op.create_table(
        "enterprise_simulation_runs",
        sa.Column("simulation_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("strategy_id", sa.String(100), nullable=False, index=True),
        sa.Column("strategy_version", sa.Integer(), nullable=False),
        sa.Column("baseline_strategy_id", sa.String(100), nullable=True),
        sa.Column("baseline_strategy_version", sa.Integer(), nullable=True),
        sa.Column("executed_by", sa.String(255), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("simulation_cutoff", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column("baseline_metrics", sa.JSON(), nullable=True),
        sa.Column("delta", sa.JSON(), nullable=True),
        sa.Column("total_events_replayed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("delayed_events_filtered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("case_detections", sa.JSON(), nullable=False),
    )

    # 4. enterprise_simulation_approvals
    op.create_table(
        "enterprise_simulation_approvals",
        sa.Column("approval_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("strategy_id", sa.String(100), nullable=False, index=True),
        sa.Column("strategy_version", sa.Integer(), nullable=False),
        sa.Column("requester_subject", sa.String(255), nullable=False),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_rationale", sa.Text(), nullable=False),
        sa.Column("simulation_run_id", sa.String(100), nullable=True),
        sa.Column("status", sa.String(30), nullable=False, server_default="pending", index=True),
        sa.Column("reviewer_subject", sa.String(255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_decision", sa.String(30), nullable=True),
        sa.Column("review_notes", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("enterprise_simulation_approvals")
    op.drop_table("enterprise_simulation_runs")
    op.drop_table("enterprise_simulation_case_outcomes")
    op.drop_table("enterprise_simulation_strategies")
