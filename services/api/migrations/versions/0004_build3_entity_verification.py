"""Build 3: NEA snapshots and reviewed BRS entity associations.

Revision ID: 0004
Revises: 0003
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "nea_registry_snapshots",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("source_url", sa.String(length=300), nullable=False),
        sa.Column("data_as_of", sa.String(length=10), nullable=False),
        sa.Column("retrieved_at", sa.String(length=32), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("record_count", sa.Integer(), nullable=False),
        sa.Column("invalid_rows", sa.Integer(), nullable=False),
        sa.Column("imported_by", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.ForeignKeyConstraint(["imported_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "nea_registry_entries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("snapshot_id", sa.String(length=36), nullable=False),
        sa.Column("registration_number", sa.String(length=40), nullable=False),
        sa.Column("agency_name", sa.String(length=180), nullable=False),
        sa.Column("normalized_name", sa.String(length=180), nullable=False),
        sa.Column("service_type", sa.String(length=100), nullable=False),
        sa.Column("email_domains", sa.JSON(), nullable=False),
        sa.Column("website_domains", sa.JSON(), nullable=False),
        sa.Column("licence_status", sa.String(length=16), nullable=False),
        sa.Column("valid_from", sa.String(length=10), nullable=True),
        sa.Column("expires_on", sa.String(length=10), nullable=True),
        sa.Column("row_sha256", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["snapshot_id"], ["nea_registry_snapshots.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("snapshot_id", "registration_number"),
    )
    with op.batch_alter_table("nea_registry_entries") as batch_op:
        batch_op.create_index("ix_nea_registry_entries_snapshot_id", ["snapshot_id"], unique=False)
        batch_op.create_index("ix_nea_registry_entries_registration_number", ["registration_number"], unique=False)
        batch_op.create_index("ix_nea_registry_entries_normalized_name", ["normalized_name"], unique=False)

    op.create_table(
        "brs_business_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("registration_type", sa.String(length=24), nullable=False),
        sa.Column("registration_hmac", sa.String(length=64), nullable=False),
        sa.Column("registration_masked", sa.String(length=48), nullable=False),
        sa.Column("registered_name", sa.String(length=180), nullable=False),
        sa.Column("normalized_name", sa.String(length=180), nullable=False),
        sa.Column("source_url", sa.String(length=300), nullable=False),
        sa.Column("evidence_sha256", sa.String(length=64), nullable=False),
        sa.Column("checked_at", sa.String(length=10), nullable=False),
        sa.Column("review_due", sa.String(length=10), nullable=False),
        sa.Column("reviewer_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(["reviewer_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("registration_type", "registration_hmac"),
    )
    with op.batch_alter_table("brs_business_records") as batch_op:
        batch_op.create_index("ix_brs_business_records_registration_hmac", ["registration_hmac"], unique=False)
        batch_op.create_index("ix_brs_business_records_normalized_name", ["normalized_name"], unique=False)

    op.create_table(
        "brs_business_associations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("business_record_id", sa.String(length=36), nullable=False),
        sa.Column("association_type", sa.String(length=24), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("normalized_value", sa.String(length=255), nullable=False),
        sa.Column("source_url", sa.String(length=500), nullable=False),
        sa.Column("evidence_sha256", sa.String(length=64), nullable=False),
        sa.Column("reviewed_at", sa.String(length=10), nullable=False),
        sa.Column("review_due", sa.String(length=10), nullable=False),
        sa.Column("reviewer_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(["business_record_id"], ["brs_business_records.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["reviewer_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("business_record_id", "association_type", "normalized_value"),
    )
    with op.batch_alter_table("brs_business_associations") as batch_op:
        batch_op.create_index("ix_brs_business_associations_business_record_id", ["business_record_id"], unique=False)
        batch_op.create_index("ix_brs_business_associations_normalized_value", ["normalized_value"], unique=False)


def downgrade() -> None:
    op.drop_table("brs_business_associations")
    op.drop_table("brs_business_records")
    op.drop_table("nea_registry_entries")
    op.drop_table("nea_registry_snapshots")
