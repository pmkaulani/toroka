from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .graph import EvidenceBasis, EvidenceNetwork, NetworkEdge, NetworkNode


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class NetworkGraphSnapshot:
    snapshot_id: str
    installation_id: str
    as_of: datetime
    created_at: datetime
    node_count: int
    edge_count: int
    nodes_digest: str
    edges_digest: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "installation_id": self.installation_id,
            "as_of": self.as_of.isoformat(),
            "created_at": self.created_at.isoformat(),
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "nodes_digest": self.nodes_digest,
            "edges_digest": self.edges_digest,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class NetworkGraphDiff:
    installation_id: str
    from_time: datetime
    to_time: datetime
    added_nodes: tuple[str, ...]
    removed_nodes: tuple[str, ...]
    added_edges: tuple[str, ...]
    removed_edges: tuple[str, ...]
    changed_edges: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "installation_id": self.installation_id,
            "from_time": self.from_time.isoformat(),
            "to_time": self.to_time.isoformat(),
            "added_nodes": list(self.added_nodes),
            "removed_nodes": list(self.removed_nodes),
            "added_edges": list(self.added_edges),
            "removed_edges": list(self.removed_edges),
            "changed_edges": list(self.changed_edges),
        }


class TemporalNetworkManager:
    """Manages bitemporal point-in-time graph reconstruction and historical diffing."""

    @staticmethod
    def filter_graph_as_of(
        base_graph: EvidenceNetwork,
        as_of: datetime,
    ) -> EvidenceNetwork:
        """Construct point-in-time graph showing only entities and relationships known at as_of."""
        filtered = EvidenceNetwork(base_graph.installation_id)

        # Add nodes first seen on or before as_of
        for node in base_graph.nodes.values():
            if node.first_seen is None or _ensure_utc(node.first_seen) <= _ensure_utc(as_of):
                filtered.add_node(node)

        # Add edges first seen on or before as_of and whose endpoints are present
        for edge in base_graph.edges:
            if edge.first_seen is None or _ensure_utc(edge.first_seen) <= _ensure_utc(as_of):
                # If edge has expired/last_seen before as_of, it was historically present
                if edge.source_key in filtered.nodes and edge.target_key in filtered.nodes:
                    filtered.add_edge(edge)

        return filtered

    @staticmethod
    def compare_points_in_time(
        graph_t1: EvidenceNetwork,
        graph_t2: EvidenceNetwork,
        t1: datetime,
        t2: datetime,
    ) -> NetworkGraphDiff:
        """Compute structural differences between two historical graph states."""
        if graph_t1.installation_id != graph_t2.installation_id:
            raise ValueError("Cannot compare graphs from different installations")

        nodes1 = set(graph_t1.nodes.keys())
        nodes2 = set(graph_t2.nodes.keys())

        edges1 = {e.edge_id: e for e in graph_t1.edges}
        edges2 = {e.edge_id: e for e in graph_t2.edges}

        added_nodes = tuple(sorted(nodes2 - nodes1))
        removed_nodes = tuple(sorted(nodes1 - nodes2))

        added_edges = tuple(sorted(set(edges2.keys()) - set(edges1.keys())))
        removed_edges = tuple(sorted(set(edges1.keys()) - set(edges2.keys())))

        # Changed edges (same endpoints & type, but differing confidence or evidence)
        changed: list[str] = []
        for eid in set(edges1.keys()) & set(edges2.keys()):
            e1 = edges1[eid]
            e2 = edges2[eid]
            if e1.confidence != e2.confidence or e1.evidence_basis != e2.evidence_basis:
                changed.append(eid)

        return NetworkGraphDiff(
            installation_id=graph_t1.installation_id,
            from_time=t1,
            to_time=t2,
            added_nodes=added_nodes,
            removed_nodes=removed_nodes,
            added_edges=added_edges,
            removed_edges=removed_edges,
            changed_edges=tuple(sorted(changed)),
        )
