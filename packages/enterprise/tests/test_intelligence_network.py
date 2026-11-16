"""Unit and domain tests for Phase 10: Network Intelligence & Collaborative Fraud Graphs."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
import pytest

from toroka_enterprise.intelligence.network import (
    ApprovedTypologyPackage,
    CollaborationMode,
    CollaborativeExchangeContract,
    CollaborativeIntelligenceGateway,
    EntityLinkCandidate,
    EntityLinkStatus,
    EntityResolutionEngine,
    EvidenceBasis,
    EvidenceNetwork,
    EvidenceSubgraph,
    FindingEvidenceSubgraph,
    NetworkAnalysisResult,
    NetworkAnalysisService,
    NetworkEdge,
    NetworkGraphDiff,
    NetworkNode,
    NetworkPatternFinding,
    TemporalNetworkManager,
    TransferObservation,
    detect_circular_movement,
    detect_common_beneficiaries,
    detect_fan_patterns,
    detect_multi_hop_movement,
    detect_rapid_pass_through,
    detect_shared_infrastructure,
    expand_neighborhood,
    extract_finding_subgraph,
    find_shortest_path,
)


def _dt(offset_mins: int = 0) -> datetime:
    base = datetime(2026, 11, 16, 10, 0, 0, tzinfo=timezone.utc)
    return base + timedelta(minutes=offset_mins)


# =============================================================================
# 1. Graph Construction & Invariants
# =============================================================================


def test_graph_node_and_edge_creation_and_installation_isolation():
    net = EvidenceNetwork("inst-alpha")
    node_a = NetworkNode(
        installation_id="inst-alpha",
        node_key="account:ACC_001",
        entity_type="account",
        pseudonymous_label="Account 001",
    )
    node_b = NetworkNode(
        installation_id="inst-alpha",
        node_key="account:ACC_002",
        entity_type="account",
        pseudonymous_label="Account 002",
    )
    net.add_node(node_a)
    net.add_node(node_b)

    # Edge creation with evidence requirement
    edge = NetworkEdge(
        installation_id="inst-alpha",
        source_key="account:ACC_001",
        target_key="account:ACC_002",
        relationship_type="transferred_funds_to",
        evidence_basis=EvidenceBasis.DIRECT_OBSERVATION,
        event_ids=("ev_101",),
        source_systems=("payment_switch",),
        confidence=1.0,
    )
    net.add_edge(edge)

    assert net.node_count == 2 if hasattr(net, "node_count") else len(net.nodes) == 2
    assert len(net.edges) == 1

    # Cross-installation node rejection
    foreign_node = NetworkNode(
        installation_id="inst-beta",
        node_key="account:ACC_003",
        entity_type="account",
        pseudonymous_label="Account 003",
    )
    with pytest.raises(ValueError, match="installation mismatch"):
        net.add_node(foreign_node)

    # Direct observation edge without evidence must be rejected
    with pytest.raises(ValueError, match="requires at least one event_id"):
        NetworkEdge(
            installation_id="inst-alpha",
            source_key="account:ACC_001",
            target_key="account:ACC_002",
            relationship_type="transferred_funds_to",
            evidence_basis=EvidenceBasis.DIRECT_OBSERVATION,
            event_ids=(),
            source_record_ids=(),
            source_systems=(),
        )


# =============================================================================
# 2. Neighborhood Expansion, Bounds & Exclusion of Weak Associations
# =============================================================================


def test_bounded_traversal_and_weak_association_exclusion():
    net = EvidenceNetwork("inst-alpha")
    for i in range(1, 6):
        net.add_node(
            NetworkNode(
                installation_id="inst-alpha",
                node_key=f"account:ACC_00{i}",
                entity_type="account",
                pseudonymous_label=f"Account 00{i}",
            )
        )

    # Direct transfer edges: 1 -> 2 -> 3
    net.add_edge(
        NetworkEdge(
            installation_id="inst-alpha",
            source_key="account:ACC_001",
            target_key="account:ACC_002",
            relationship_type="transferred_funds_to",
            evidence_basis=EvidenceBasis.DIRECT_OBSERVATION,
            event_ids=("ev_1",),
            source_systems=("core_banking",),
        )
    )
    net.add_edge(
        NetworkEdge(
            installation_id="inst-alpha",
            source_key="account:ACC_002",
            target_key="account:ACC_003",
            relationship_type="transferred_funds_to",
            evidence_basis=EvidenceBasis.DIRECT_OBSERVATION,
            event_ids=("ev_2",),
            source_systems=("core_banking",),
        )
    )
    # Weak association edge: 1 -> 4 via shared workstation
    net.add_edge(
        NetworkEdge(
            installation_id="inst-alpha",
            source_key="account:ACC_001",
            target_key="account:ACC_004",
            relationship_type="shared_workstation",
            evidence_basis=EvidenceBasis.SHARED_ATTRIBUTE,
            confidence=0.3,
        )
    )

    # Default expansion (include_shared_attributes=False)
    sub = expand_neighborhood(
        net,
        {"account:ACC_001"},
        max_depth=2,
        include_shared_attributes=False,
    )
    node_keys = {n.node_key for n in sub.nodes}
    assert "account:ACC_001" in node_keys
    assert "account:ACC_002" in node_keys
    assert "account:ACC_003" in node_keys
    assert "account:ACC_004" not in node_keys  # Weak association excluded!

    # When explicitly included, ACC_004 appears
    sub_with_weak = expand_neighborhood(
        net,
        {"account:ACC_001"},
        max_depth=2,
        include_shared_attributes=True,
        minimum_confidence=0.2,
    )
    assert "account:ACC_004" in {n.node_key for n in sub_with_weak.nodes}


def test_traversal_limits_and_truncation_flag():
    net = EvidenceNetwork("inst-alpha")
    for i in range(1, 15):
        net.add_node(
            NetworkNode(
                installation_id="inst-alpha",
                node_key=f"account:ACC_{i:03d}",
                entity_type="account",
                pseudonymous_label=f"Account {i:03d}",
            )
        )
    # Star graph: node 1 connected to 2..14
    for i in range(2, 15):
        net.add_edge(
            NetworkEdge(
                installation_id="inst-alpha",
                source_key="account:ACC_001",
                target_key=f"account:ACC_{i:03d}",
                relationship_type="transferred_funds_to",
                evidence_basis=EvidenceBasis.DIRECT_OBSERVATION,
                event_ids=(f"ev_{i}",),
                source_systems=("payment_switch",),
            )
        )

    # Restrict max_nodes to 5
    sub = expand_neighborhood(net, {"account:ACC_001"}, max_nodes=5)
    assert len(sub.nodes) == 5
    assert sub.truncated is True
    assert "max_nodes_reached" in (sub.truncation_reason or "")


def test_shortest_path_discovery():
    net = EvidenceNetwork("inst-alpha")
    for i in range(1, 5):
        net.add_node(
            NetworkNode(
                installation_id="inst-alpha",
                node_key=f"account:ACC_{i}",
                entity_type="account",
                pseudonymous_label=f"Account {i}",
            )
        )
    net.add_edge(
        NetworkEdge(
            installation_id="inst-alpha",
            source_key="account:ACC_1",
            target_key="account:ACC_2",
            relationship_type="transferred_funds_to",
            evidence_basis=EvidenceBasis.DIRECT_OBSERVATION,
            event_ids=("ev_12",),
            source_systems=("core_banking",),
        )
    )
    net.add_edge(
        NetworkEdge(
            installation_id="inst-alpha",
            source_key="account:ACC_2",
            target_key="account:ACC_3",
            relationship_type="transferred_funds_to",
            evidence_basis=EvidenceBasis.DIRECT_OBSERVATION,
            event_ids=("ev_23",),
            source_systems=("core_banking",),
        )
    )

    path = find_shortest_path(net, "account:ACC_1", "account:ACC_3")
    assert path is not None
    nodes, edges = path
    assert [n.node_key for n in nodes] == ["account:ACC_1", "account:ACC_2", "account:ACC_3"]
    assert len(edges) == 2


# =============================================================================
# 3. Transaction Network Motifs
# =============================================================================


def test_fan_in_and_fan_out_detection():
    # 4 distinct accounts transfer to ACC_TARGET (Fan-in)
    transfers = [
        TransferObservation(
            installation_id="inst-alpha",
            event_id=f"ev_in_{i}",
            source_account=f"account:SRC_{i}",
            target_account="account:TARGET",
            amount=Decimal("2500.00"),
            currency="USD",
            event_time=_dt(i * 10),
            available_at=_dt(i * 10),
        )
        for i in range(1, 5)
    ]
    # ACC_DISPERSE transfers to 4 distinct accounts (Fan-out)
    transfers.extend([
        TransferObservation(
            installation_id="inst-alpha",
            event_id=f"ev_out_{i}",
            source_account="account:DISPERSE",
            target_account=f"account:DEST_{i}",
            amount=Decimal("1200.00"),
            currency="USD",
            event_time=_dt(100 + i * 10),
            available_at=_dt(100 + i * 10),
        )
        for i in range(1, 5)
    ])

    findings = detect_fan_patterns(transfers, min_sources=3, min_targets=3)
    types = [f.pattern_type for f in findings]
    assert "fan_in" in types
    assert "fan_out" in types

    fan_in_f = next(f for f in findings if f.pattern_type == "fan_in")
    assert fan_in_f.anchor_entity == "account:TARGET"
    assert len(fan_in_f.related_entities) == 4
    assert fan_in_f.monetary_total == Decimal("10000.00")
    assert len(fan_in_f.alternative_legitimate_explanations) > 0


def test_rapid_pass_through_detection_and_temporal_invariants():
    t_in = TransferObservation(
        installation_id="inst-alpha",
        event_id="ev_in",
        source_account="account:ORIGIN",
        target_account="account:INTERMEDIARY",
        amount=Decimal("50000.00"),
        currency="USD",
        event_time=_dt(10),
        available_at=_dt(10),
    )
    t_out = TransferObservation(
        installation_id="inst-alpha",
        event_id="ev_out",
        source_account="account:INTERMEDIARY",
        target_account="account:BENEFICIARY",
        amount=Decimal("49500.00"),
        currency="USD",
        event_time=_dt(35),  # 25 minutes later
        available_at=_dt(35),
    )

    findings = detect_rapid_pass_through([t_in, t_out], max_retention=timedelta(hours=2))
    assert len(findings) == 1
    pt = findings[0]
    assert pt.pattern_type == "rapid_pass_through"
    assert pt.anchor_entity == "account:INTERMEDIARY"
    assert pt.related_entities == ("account:ORIGIN", "account:BENEFICIARY")
    # Limitations must explicitly declare no claim of tracing identical money
    assert any("does not claim to trace identical" in lim.lower() for lim in pt.evidence_limitations)

    # Replay test: if as_of is before t_out became available, finding must NOT exist
    replay_findings = detect_rapid_pass_through(
        [t_in, t_out],
        max_retention=timedelta(hours=2),
        as_of=_dt(20),  # Before t_out available
    )
    assert len(replay_findings) == 0


def test_circular_movement_detection():
    # A -> B -> C -> A cycle
    transfers = [
        TransferObservation(
            installation_id="inst-alpha",
            event_id="ev_ab",
            source_account="account:A",
            target_account="account:B",
            amount=Decimal("10000.00"),
            currency="EUR",
            event_time=_dt(10),
            available_at=_dt(10),
        ),
        TransferObservation(
            installation_id="inst-alpha",
            event_id="ev_bc",
            source_account="account:B",
            target_account="account:C",
            amount=Decimal("9800.00"),
            currency="EUR",
            event_time=_dt(20),
            available_at=_dt(20),
        ),
        TransferObservation(
            installation_id="inst-alpha",
            event_id="ev_ca",
            source_account="account:C",
            target_account="account:A",
            amount=Decimal("9500.00"),
            currency="EUR",
            event_time=_dt(30),
            available_at=_dt(30),
        ),
    ]

    findings = detect_circular_movement(transfers)
    assert len(findings) == 1
    assert findings[0].pattern_type == "circular_movement"
    assert findings[0].anchor_entity == "account:A"


def test_common_beneficiary_detection():
    transfers = [
        TransferObservation(
            installation_id="inst-alpha",
            event_id=f"ev_ben_{i}",
            source_account=f"account:PAYOR_{i}",
            target_account="account:MERCHANT_HUB",
            amount=Decimal("500.00"),
            currency="USD",
            event_time=_dt(i * 5),
            available_at=_dt(i * 5),
        )
        for i in range(1, 5)
    ]
    findings = detect_common_beneficiaries(transfers, min_accounts=3)
    assert len(findings) == 1
    assert findings[0].pattern_type == "common_beneficiary"
    assert findings[0].anchor_entity == "account:MERCHANT_HUB"


# =============================================================================
# 4. Entity Resolution & Governance Review
# =============================================================================


def test_entity_resolution_candidate_proposal_and_review():
    cand = EntityResolutionEngine.propose_candidate(
        installation_id="inst-alpha",
        source_key="customer:CUST_100",
        target_key="device:DEV_IPHONE_77",
        attribute_type="device_id",
        attribute_value="DEV_IPHONE_77",
        source_systems=["channel_telemetry"],
        supporting_evidence=[{"event_id": "ev_login_1"}],
    )

    # Initial state must be SHARED_ATTRIBUTE_ONLY with conservative confidence
    assert cand.status == EntityLinkStatus.SHARED_ATTRIBUTE_ONLY
    assert cand.confidence <= 0.50

    # Reviewer confirms relationship
    reviewed = EntityResolutionEngine.apply_human_review(
        cand,
        reviewer_subject="investigator.alice",
        decision=EntityLinkStatus.SAME_ENTITY_CONFIRMED,
        rationale="Customer verified device ownership during in-branch interview with government ID.",
    )
    assert reviewed.status == EntityLinkStatus.SAME_ENTITY_CONFIRMED
    assert reviewed.confidence == 1.0
    assert reviewed.reviewed_by == "investigator.alice"


# =============================================================================
# 5. Temporal Graph Snapshots & Diffing
# =============================================================================


def test_temporal_graph_as_of_filtering_and_diff():
    net = EvidenceNetwork("inst-alpha")
    node_1 = NetworkNode("inst-alpha", "account:1", "account", "Acc 1", first_seen=_dt(10))
    node_2 = NetworkNode("inst-alpha", "account:2", "account", "Acc 2", first_seen=_dt(50))
    net.add_node(node_1)
    net.add_node(node_2)

    net.add_edge(
        NetworkEdge(
            "inst-alpha",
            "account:1",
            "account:2",
            "associated_with",
            EvidenceBasis.DIRECT_OBSERVATION,
            event_ids=("ev_rel",),
            source_systems=("crm",),
            first_seen=_dt(50),
        )
    )

    # At t=20, only node_1 existed
    g_t20 = TemporalNetworkManager.filter_graph_as_of(net, _dt(20))
    assert "account:1" in g_t20.nodes
    assert "account:2" not in g_t20.nodes
    assert len(g_t20.edges) == 0

    # At t=60, both nodes and edge exist
    g_t60 = TemporalNetworkManager.filter_graph_as_of(net, _dt(60))
    assert len(g_t60.nodes) == 2
    assert len(g_t60.edges) == 1

    diff = TemporalNetworkManager.compare_points_in_time(g_t20, g_t60, _dt(20), _dt(60))
    assert diff.added_nodes == ("account:2",)
    assert len(diff.added_edges) == 1


# =============================================================================
# 6. Collaborative Intelligence Architecture Safety & Invariants
# =============================================================================


def test_collaborative_intelligence_gateway_defaults_and_zero_pii_guards():
    gateway = CollaborativeIntelligenceGateway()
    # Default must be strictly INTERNAL_ONLY
    assert gateway.is_sharing_permitted() is False
    assert gateway.mode == CollaborationMode.INTERNAL_ONLY

    # Export typology package
    pkg = gateway.export_typology_package(
        installation_id="inst-alpha",
        pattern_type="rapid_pass_through",
        heuristics={"max_window_hours": 4, "min_amount": 10000},
        explanations=["Corporate payroll settlement", "Escrow forwarding"],
    )
    assert isinstance(pkg, ApprovedTypologyPackage)
    assert pkg.pattern_type == "rapid_pass_through"

    # Invariant: Attempting to embed raw customer PII into typology must raise ValueError
    with pytest.raises(ValueError, match="Prohibited identifier"):
        ApprovedTypologyPackage(
            typology_id="typ_bad",
            originating_installation_id="inst-alpha",
            pattern_type="bad_pattern",
            abstract_structure={"account_number": "123456789"},  # Prohibited raw key!
            detection_heuristics={},
            alternative_explanations=(),
            governance_notes="Invalid",
            created_at=datetime.now(timezone.utc),
        )
