"""Phase 9: Fraud DNA & Institutional Memory Engine models, fingerprints, patterns, reviews, and matches.

Revision ID: 008_institutional_memory
Revises: 007_counterfactual_simulator
"""
from alembic import op
import sqlalchemy as sa

revision = "008_institutional_memory"
down_revision = "007_counterfactual_simulator"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. enterprise_case_fingerprints
    op.create_table(
        "enterprise_case_fingerprints",
        sa.Column("case_id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("extractor_version", sa.String(50), nullable=False, server_default="v1"),
        sa.Column("features", sa.JSON(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("source_systems", sa.JSON(), nullable=False),
        sa.Column("source_coverage", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("total_events", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("first_event_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_event_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("control_weaknesses", sa.JSON(), nullable=False),
        sa.Column("adjudicated_label", sa.String(32), nullable=True, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )

    # 2. enterprise_case_memory_features
    op.create_table(
        "enterprise_case_memory_features",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("case_id", sa.String(36), nullable=False, index=True),
        sa.Column("dimension", sa.String(100), nullable=False, index=True),
        sa.Column("feature_value", sa.String(255), nullable=False),
        sa.Column("event_ids", sa.JSON(), nullable=False),
        sa.Column("source_systems", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 3. enterprise_institutional_patterns
    op.create_table(
        "enterprise_institutional_patterns",
        sa.Column("pattern_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("feature_signature", sa.JSON(), nullable=False),
        sa.Column("extractor_version", sa.String(50), nullable=False, server_default="v1"),
        sa.Column("status", sa.String(30), nullable=False, server_default="candidate", index=True),
        sa.Column("curator_subject", sa.String(255), nullable=False),
        sa.Column("reviewer_subject", sa.String(255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("validation_rationale", sa.Text(), nullable=True),
        sa.Column("limitations", sa.JSON(), nullable=False),
        sa.Column("control_weaknesses", sa.JSON(), nullable=False),
        sa.Column("independent_source_systems", sa.JSON(), nullable=False),
        sa.Column("supporting_event_ids", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )

    # 4. enterprise_pattern_case_links
    op.create_table(
        "enterprise_pattern_case_links",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("pattern_id", sa.String(100), nullable=False, index=True),
        sa.Column("case_id", sa.String(36), nullable=False, index=True),
        sa.Column("case_role", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 5. enterprise_pattern_reviews
    op.create_table(
        "enterprise_pattern_reviews",
        sa.Column("review_id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("pattern_id", sa.String(100), nullable=False, index=True),
        sa.Column("pattern_version", sa.Integer(), nullable=False),
        sa.Column("reviewer_subject", sa.String(255), nullable=False),
        sa.Column("action", sa.String(30), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("evaluation_metrics", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 6. enterprise_pattern_versions
    op.create_table(
        "enterprise_pattern_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("pattern_id", sa.String(100), nullable=False, index=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("feature_signature", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("changed_by", sa.String(255), nullable=False),
        sa.Column("change_summary", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 7. enterprise_memory_match_results
    op.create_table(
        "enterprise_memory_match_results",
        sa.Column("match_id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("query_case_id", sa.String(36), nullable=False, index=True),
        sa.Column("matched_type", sa.String(30), nullable=False),
        sa.Column("target_id", sa.String(100), nullable=False, index=True),
        sa.Column("similarity_index", sa.Float(), nullable=True),
        sa.Column("comparison_coverage", sa.Float(), nullable=False),
        sa.Column("matched_features", sa.JSON(), nullable=False),
        sa.Column("different_features", sa.JSON(), nullable=False),
        sa.Column("target_outcome", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 8. enterprise_memory_audit_events
    op.create_table(
        "enterprise_memory_audit_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("actor_subject", sa.String(255), nullable=False),
        sa.Column("actor_role", sa.String(50), nullable=False),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("target_type", sa.String(50), nullable=False),
        sa.Column("target_id", sa.String(255), nullable=True),
        sa.Column("safe_metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("enterprise_memory_audit_events")
    op.drop_table("enterprise_memory_match_results")
    op.drop_table("enterprise_pattern_versions")
    op.drop_table("enterprise_pattern_reviews")
    op.drop_table("enterprise_pattern_case_links")
    op.drop_table("enterprise_institutional_patterns")
    op.drop_table("enterprise_case_memory_features")
    op.drop_table("enterprise_case_fingerprints")
