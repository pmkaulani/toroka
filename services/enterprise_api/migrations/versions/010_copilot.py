"""Phase 11: Toroka AI Investigation Copilot tables for threads, messages, report drafts, and feedback.

Revision ID: 010_copilot
Revises: 009_network_intelligence
"""
from alembic import op
import sqlalchemy as sa

revision = "010_copilot"
down_revision = "009_network_intelligence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. enterprise_copilot_threads
    op.create_table(
        "enterprise_copilot_threads",
        sa.Column("thread_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("case_id", sa.String(36), nullable=False, index=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("is_archived", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. enterprise_copilot_messages
    op.create_table(
        "enterprise_copilot_messages",
        sa.Column("message_id", sa.String(100), primary_key=True),
        sa.Column("thread_id", sa.String(100), nullable=False, index=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("case_id", sa.String(36), nullable=False, index=True),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("task_type", sa.String(50), nullable=True),
        sa.Column("claims", sa.JSON(), nullable=False),
        sa.Column("citations", sa.JSON(), nullable=False),
        sa.Column("tool_calls", sa.JSON(), nullable=False),
        sa.Column("grounding_report", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 3. enterprise_copilot_report_drafts
    op.create_table(
        "enterprise_copilot_report_drafts",
        sa.Column("draft_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("case_id", sa.String(36), nullable=False, index=True),
        sa.Column("thread_id", sa.String(100), nullable=True, index=True),
        sa.Column("report_type", sa.String(50), nullable=False, index=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("content_markdown", sa.Text(), nullable=False),
        sa.Column("investigator_edits_markdown", sa.Text(), nullable=True),
        sa.Column("status", sa.String(30), nullable=False, server_default="DRAFT", index=True),
        sa.Column("evidence_context_hash", sa.String(64), nullable=False),
        sa.Column("citations", sa.JSON(), nullable=False),
        sa.Column("model_info", sa.JSON(), nullable=False),
        sa.Column("review_notes", sa.Text(), nullable=True),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 4. enterprise_copilot_feedbacks
    op.create_table(
        "enterprise_copilot_feedbacks",
        sa.Column("feedback_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("case_id", sa.String(36), nullable=False, index=True),
        sa.Column("message_id", sa.String(100), nullable=False, index=True),
        sa.Column("rating", sa.Integer(), nullable=False),
        sa.Column("feedback_text", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("enterprise_copilot_feedbacks")
    op.drop_table("enterprise_copilot_report_drafts")
    op.drop_table("enterprise_copilot_messages")
    op.drop_table("enterprise_copilot_threads")
