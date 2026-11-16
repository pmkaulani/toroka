"""Phase 10: Network Intelligence & Collaborative Fraud Graphs models, nodes, edges, candidates, reviews, findings, snapshots, and runs.

Revision ID: 009_network_intelligence
Revises: 008_institutional_memory
"""
from alembic import op
import sqlalchemy as sa

revision = "009_network_intelligence"
down_revision = "008_institutional_memory"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. enterprise_network_nodes
    op.create_table(
        "enterprise_network_nodes",
        sa.Column("node_key", sa.String(255), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("entity_type", sa.String(50), nullable=False, index=True),
        sa.Column("pseudonymous_label", sa.String(255), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 2. enterprise_network_edges
    op.create_table(
        "enterprise_network_edges",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("source_key", sa.String(255), nullable=False, index=True),
        sa.Column("target_key", sa.String(255), nullable=False, index=True),
        sa.Column("relationship_type", sa.String(100), nullable=False, index=True),
        sa.Column("evidence_basis", sa.String(50), nullable=False, index=True),
        sa.Column("event_ids", sa.JSON(), nullable=False),
        sa.Column("source_record_ids", sa.JSON(), nullable=False),
        sa.Column("source_systems", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("directed", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "installation_id", "source_key", "target_key", "relationship_type", "evidence_basis",
            name="uq_network_edge_record",
        ),
    )

    # 3. enterprise_entity_link_candidates
    op.create_table(
        "enterprise_entity_link_candidates",
        sa.Column("candidate_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("source_entity_key", sa.String(255), nullable=False, index=True),
        sa.Column("target_entity_key", sa.String(255), nullable=False, index=True),
        sa.Column("attribute_type", sa.String(50), nullable=False, index=True),
        sa.Column("attribute_value", sa.String(255), nullable=False),
        sa.Column("match_type", sa.String(30), nullable=False),
        sa.Column("status", sa.String(40), nullable=False, server_default="SHARED_ATTRIBUTE_ONLY", index=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("supporting_evidence", sa.JSON(), nullable=False),
        sa.Column("contradicting_evidence", sa.JSON(), nullable=False),
        sa.Column("source_systems", sa.JSON(), nullable=False),
        sa.Column("first_observed", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_observed", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_by", sa.String(255), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_rationale", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 4. enterprise_entity_link_reviews
    op.create_table(
        "enterprise_entity_link_reviews",
        sa.Column("review_id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("candidate_id", sa.String(100), nullable=False, index=True),
        sa.Column("reviewer_subject", sa.String(255), nullable=False),
        sa.Column("decision", sa.String(40), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column("previous_status", sa.String(40), nullable=False),
        sa.Column("new_status", sa.String(40), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 5. enterprise_network_findings
    op.create_table(
        "enterprise_network_findings",
        sa.Column("finding_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("case_id", sa.String(36), nullable=True, index=True),
        sa.Column("pattern_type", sa.String(50), nullable=False, index=True),
        sa.Column("anchor_entity", sa.String(255), nullable=False, index=True),
        sa.Column("related_entities", sa.JSON(), nullable=False),
        sa.Column("event_ids", sa.JSON(), nullable=False),
        sa.Column("start_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("detection_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("evidence_limitations", sa.JSON(), nullable=False),
        sa.Column("alternative_legitimate_explanations", sa.JSON(), nullable=False),
        sa.Column("supporting_source_systems", sa.JSON(), nullable=False),
        sa.Column("transaction_ids", sa.JSON(), nullable=False),
        sa.Column("monetary_total", sa.String(50), nullable=True),
        sa.Column("currency", sa.String(10), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("pattern_version", sa.String(50), nullable=False, server_default="v1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 6. enterprise_network_finding_evidence
    op.create_table(
        "enterprise_network_finding_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("installation_id", sa.String(100), nullable=False, index=True),
        sa.Column("finding_id", sa.String(100), nullable=False, index=True),
        sa.Column("subgraph_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 7. enterprise_network_snapshots
    op.create_table(
        "enterprise_network_snapshots",
        sa.Column("snapshot_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("as_of", sa.DateTime(timezone=True), nullable=False),
        sa.Column("node_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("edge_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("nodes_digest", sa.String(64), nullable=False),
        sa.Column("edges_digest", sa.String(64), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # 8. enterprise_network_analysis_runs
    op.create_table(
        "enterprise_network_analysis_runs",
        sa.Column("run_id", sa.String(100), primary_key=True),
        sa.Column("installation_id", sa.String(100), primary_key=True, index=True),
        sa.Column("case_id", sa.String(36), nullable=True, index=True),
        sa.Column("executed_by", sa.String(255), nullable=False),
        sa.Column("seed_entities", sa.JSON(), nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("nodes_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("edges_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("truncated", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("result_digest", sa.String(64), nullable=False),
        sa.Column("result_json", sa.JSON(), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("enterprise_network_analysis_runs")
    op.drop_table("enterprise_network_snapshots")
    op.drop_table("enterprise_network_finding_evidence")
    op.drop_table("enterprise_network_findings")
    op.drop_table("enterprise_entity_link_reviews")
    op.drop_table("enterprise_entity_link_candidates")
    op.drop_table("enterprise_network_edges")
    op.drop_table("enterprise_network_nodes")
