"""Integration gateway persistence tables.

Revision ID: 003_integrations
Revises: 002_case_closure_proposals
"""
from alembic import op
import sqlalchemy as sa

revision = "003_integrations"
down_revision = "002_case_closure_proposals"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. enterprise_integration_records
    op.create_table(
        "enterprise_integration_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("connector_id", sa.String(100), nullable=False, index=True),
        sa.Column("record_id", sa.String(255), nullable=False, index=True),
        sa.Column("record_type", sa.String(50), nullable=False, index=True),
        sa.Column("source_system", sa.String(50), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False, index=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="ingested"),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("source_event_timestamp", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("ingested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "installation_id", "connector_id", "record_id", "version",
            name="uq_integration_record_version",
        ),
    )

    # 2. enterprise_integration_cursors
    op.create_table(
        "enterprise_integration_cursors",
        sa.Column("installation_id", sa.String(100), primary_key=True),
        sa.Column("connector_id", sa.String(100), primary_key=True),
        sa.Column("cursor", sa.String(500), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error_message", sa.Text(), nullable=True),
        sa.Column("records_ingested_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_duplicates_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_corrected_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 3. enterprise_integration_jobs
    op.create_table(
        "enterprise_integration_jobs",
        sa.Column("job_id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("connector_id", sa.String(100), nullable=False, index=True),
        sa.Column("job_type", sa.String(50), nullable=False),
        sa.Column("triggered_by", sa.String(255), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cursor_before", sa.String(500), nullable=True),
        sa.Column("cursor_after", sa.String(500), nullable=True),
        sa.Column("records_received", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_accepted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_rejected", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_duplicates", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("records_corrected", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("correlation_id", sa.String(128), nullable=False, index=True),
    )

    # 4. enterprise_integration_events_inbox
    op.create_table(
        "enterprise_integration_events_inbox",
        sa.Column("event_id", sa.String(255), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True),
        sa.Column("connector_id", sa.String(100), primary_key=True),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False, server_default="received"),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
    )

    # 5. enterprise_integration_rejected_records
    op.create_table(
        "enterprise_integration_rejected_records",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("connector_id", sa.String(100), nullable=False, index=True),
        sa.Column("job_id", sa.String(36), nullable=True, index=True),
        sa.Column("source_record_id", sa.String(255), nullable=True),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("reason_message", sa.Text(), nullable=False),
        sa.Column("raw_payload", sa.JSON(), nullable=True),
        sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("enterprise_integration_rejected_records")
    op.drop_table("enterprise_integration_events_inbox")
    op.drop_table("enterprise_integration_jobs")
    op.drop_table("enterprise_integration_cursors")
    op.drop_table("enterprise_integration_records")
