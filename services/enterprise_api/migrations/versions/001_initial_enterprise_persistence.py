"""Initial Toroka Enterprise persistence schema.

Revision ID: 001_initial_enterprise
Revises: 
"""
from alembic import op
import sqlalchemy as sa

revision = "001_initial_enterprise"
down_revision = None
branch_labels = None
depends_on = None

GENESIS_HASH = "0" * 64


def upgrade() -> None:
    # 1. enterprise_cases
    op.create_table(
        "enterprise_cases",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("dedupe_key", sa.String(64), nullable=True),
        sa.Column("label", sa.String(64), nullable=False),
        sa.Column("focus", sa.String(300), nullable=False),
        sa.Column("snapshot", sa.JSON(), nullable=False),
        sa.Column("snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("manifest_id", sa.String(64), nullable=True, index=True),
        sa.Column("status", sa.String(24), nullable=False, server_default="open"),
        sa.Column("disposition", sa.String(64), nullable=True),
        sa.Column("closing_note", sa.Text(), nullable=True),
        sa.Column("alternatives_considered", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint("installation_id", "dedupe_key", name="uq_case_installation_dedupe"),
    )
    op.create_index("ix_case_status_created", "enterprise_cases", ["status", "created_at"])

    # 2. enterprise_case_assignments
    op.create_table(
        "enterprise_case_assignments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "case_id",
            sa.String(36),
            sa.ForeignKey("enterprise_cases.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("assigned_subject", sa.String(255), nullable=False, index=True),
        sa.Column("assignment_role", sa.String(40), nullable=False, server_default="investigator"),
        sa.Column("assigned_by", sa.String(255), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="active"),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_assignment_subject_status",
        "enterprise_case_assignments",
        ["assigned_subject", "status"],
    )

    # 3. enterprise_case_notes
    op.create_table(
        "enterprise_case_notes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "case_id",
            sa.String(36),
            sa.ForeignKey("enterprise_cases.id", ondelete="RESTRICT"),
            nullable=False,
            index=True,
        ),
        sa.Column("author_subject", sa.String(255), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 4. enterprise_reveal_requests
    op.create_table(
        "enterprise_reveal_requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "case_id",
            sa.String(36),
            sa.ForeignKey("enterprise_cases.id", ondelete="RESTRICT"),
            nullable=False,
            index=True,
        ),
        sa.Column("pseudonym", sa.String(255), nullable=False),
        sa.Column("requested_by", sa.String(255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="pending"),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('pending','approved','rejected','expired','used')",
            name="ck_reveal_status",
        ),
    )

    # 5. enterprise_audit_heads
    op.create_table(
        "enterprise_audit_heads",
        sa.Column("installation_id", sa.String(100), primary_key=True),
        sa.Column("last_sequence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_hash", sa.String(64), nullable=False),
    )

    # 6. enterprise_audit_records
    op.create_table(
        "enterprise_audit_records",
        sa.Column("sequence", sa.Integer(), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("event_id", sa.String(36), unique=True, nullable=False),
        sa.Column("actor_subject", sa.String(255), nullable=False),
        sa.Column("actor_role", sa.String(40), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("target_type", sa.String(64), nullable=False),
        sa.Column("target_id", sa.String(100), nullable=True),
        sa.Column("safe_metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False, unique=True),
    )

    # 7. enterprise_runs
    op.create_table(
        "enterprise_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("manifest_id", sa.String(64), unique=True, nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("result_digest", sa.String(64), nullable=True),
        sa.Column("status", sa.String(24), nullable=False, server_default="completed"),
        sa.Column("created_by", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # Initialise default audit head row with Genesis Hash
    op.execute(
        sa.text(
            "INSERT INTO enterprise_audit_heads (installation_id, last_sequence, last_hash) "
            f"VALUES ('toroka-default-installation', 0, '{GENESIS_HASH}')"
        )
    )


def downgrade() -> None:
    op.drop_table("enterprise_runs")
    op.drop_table("enterprise_audit_records")
    op.drop_table("enterprise_audit_heads")
    op.drop_table("enterprise_reveal_requests")
    op.drop_table("enterprise_case_notes")
    op.drop_table("enterprise_case_assignments")
    op.drop_table("enterprise_cases")
