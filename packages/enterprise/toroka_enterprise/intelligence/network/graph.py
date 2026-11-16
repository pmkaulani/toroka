from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class EvidenceBasis(StrEnum):
    DIRECT_OBSERVATION = "direct_observation"
    DERIVED_RELATIONSHIP = "derived_relationship"
    SHARED_ATTRIBUTE = "shared_attribute"


@dataclass(frozen=True)
class NetworkNode:
    installation_id: str
    node_key: str
    entity_type: str
    pseudonymous_label: str
    attributes: dict[str, Any] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def __post_init__(self) -> None:
        if not self.installation_id or not self.installation_id.strip():
            raise ValueError("installation_id is required")
        if not self.node_key or not self.node_key.strip():
            raise ValueError("node_key is required")
        if not self.entity_type or not self.entity_type.strip():
            raise ValueError("entity_type is required")
        if not self.pseudonymous_label or not self.pseudonymous_label.strip():
            raise ValueError("pseudonymous_label is required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "installation_id": self.installation_id,
            "node_key": self.node_key,
            "entity_type": self.entity_type,
            "pseudonymous_label": self.pseudonymous_label,
            "attributes": dict(self.attributes),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


@dataclass(frozen=True)
class NetworkEdge:
    installation_id: str
    source_key: str
    target_key: str
    relationship_type: str
    evidence_basis: EvidenceBasis
    event_ids: tuple[str, ...] = ()
    source_record_ids: tuple[str, ...] = ()
    source_systems: tuple[str, ...] = ()
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    confidence: float = 1.0
    directed: bool = True
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.installation_id or not self.installation_id.strip():
            raise ValueError("installation_id is required")
        if not self.source_key or not self.source_key.strip():
            raise ValueError("source_key is required")
        if not self.target_key or not self.target_key.strip():
            raise ValueError("target_key is required")
        if not self.relationship_type or not self.relationship_type.strip():
            raise ValueError("relationship_type is required")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {self.confidence}")
        if self.evidence_basis in (EvidenceBasis.DIRECT_OBSERVATION, EvidenceBasis.DERIVED_RELATIONSHIP):
            if not self.event_ids and not self.source_record_ids and not self.source_systems:
                raise ValueError(
                    f"Evidence-backed edge ({self.evidence_basis}) requires at least one event_id, source_record_id, or source_system"
                )

    @property
    def edge_id(self) -> str:
        dir_marker = "->" if self.directed else "<->"
        return f"{self.source_key}{dir_marker}{self.target_key}:{self.relationship_type}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "installation_id": self.installation_id,
            "edge_id": self.edge_id,
            "source_key": self.source_key,
            "target_key": self.target_key,
            "relationship_type": self.relationship_type,
            "evidence_basis": self.evidence_basis.value,
            "event_ids": list(self.event_ids),
            "source_record_ids": list(self.source_record_ids),
            "source_systems": list(self.source_systems),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "confidence": self.confidence,
            "directed": self.directed,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class EvidenceSubgraph:
    installation_id: str
    seed_nodes: tuple[str, ...]
    nodes: tuple[NetworkNode, ...]
    edges: tuple[NetworkEdge, ...]
    truncated: bool = False
    truncation_reason: str | None = None
    max_depth_reached: int = 0
    limitations: tuple[str, ...] = ()

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def to_dict(self) -> dict[str, Any]:
        return {
            "installation_id": self.installation_id,
            "seed_nodes": list(self.seed_nodes),
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "truncated": self.truncated,
            "truncation_reason": self.truncation_reason,
            "max_depth_reached": self.max_depth_reached,
            "limitations": list(self.limitations),
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
        }


class EvidenceNetwork:
    """In-memory, bounded evidence-backed network graph scoped to an installation."""

    def __init__(self, installation_id: str) -> None:
        if not installation_id or not installation_id.strip():
            raise ValueError("installation_id is required")
        self.installation_id = installation_id
        self._nodes: dict[str, NetworkNode] = {}
        self._edges: list[NetworkEdge] = []
        self._outgoing: dict[str, list[NetworkEdge]] = {}
        self._incoming: dict[str, list[NetworkEdge]] = {}

    @property
    def nodes(self) -> dict[str, NetworkNode]:
        return dict(self._nodes)

    @property
    def edges(self) -> list[NetworkEdge]:
        return list(self._edges)

    def add_node(self, node: NetworkNode) -> None:
        if node.installation_id != self.installation_id:
            raise ValueError(
                f"Node installation mismatch: {node.installation_id} != {self.installation_id}"
            )
        self._nodes[node.node_key] = node
        if node.node_key not in self._outgoing:
            self._outgoing[node.node_key] = []
        if node.node_key not in self._incoming:
            self._incoming[node.node_key] = []

    def add_edge(self, edge: NetworkEdge) -> None:
        if edge.installation_id != self.installation_id:
            raise ValueError(
                f"Edge installation mismatch: {edge.installation_id} != {self.installation_id}"
            )
        if edge.source_key not in self._nodes:
            raise ValueError(f"Source node '{edge.source_key}' does not exist in graph")
        if edge.target_key not in self._nodes:
            raise ValueError(f"Target node '{edge.target_key}' does not exist in graph")

        self._edges.append(edge)
        self._outgoing[edge.source_key].append(edge)
        self._incoming[edge.target_key].append(edge)
        if not edge.directed:
            self._outgoing[edge.target_key].append(edge)
            self._incoming[edge.source_key].append(edge)

    def get_node(self, node_key: str) -> NetworkNode | None:
        return self._nodes.get(node_key)

    def get_adjacent_edges(
        self,
        node_key: str,
        direction: str = "both",
        include_shared_attributes: bool = False,
        min_confidence: float = 0.0,
    ) -> list[NetworkEdge]:
        if node_key not in self._nodes:
            return []

        candidates: list[NetworkEdge] = []
        if direction in ("out", "both"):
            candidates.extend(self._outgoing.get(node_key, []))
        if direction in ("in", "both"):
            candidates.extend(self._incoming.get(node_key, []))

        # Deduplicate while preserving deterministic order
        seen_keys: set[tuple[str, str, str, str]] = set()
        filtered: list[NetworkEdge] = []
        for e in sorted(candidates, key=lambda x: (x.source_key, x.target_key, x.relationship_type)):
            key = (e.source_key, e.target_key, e.relationship_type, e.evidence_basis.value)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            if not include_shared_attributes and e.evidence_basis == EvidenceBasis.SHARED_ATTRIBUTE:
                continue
            if e.confidence < min_confidence:
                continue
            filtered.append(e)

        return filtered

    def to_subgraph(self, seed_nodes: set[str] | None = None) -> EvidenceSubgraph:
        seeds = tuple(sorted(seed_nodes)) if seed_nodes else tuple(sorted(self._nodes.keys()))
        nodes_tuple = tuple(sorted(self._nodes.values(), key=lambda n: n.node_key))
        edges_tuple = tuple(sorted(self._edges, key=lambda e: (e.source_key, e.target_key, e.relationship_type)))
        return EvidenceSubgraph(
            installation_id=self.installation_id,
            seed_nodes=seeds,
            nodes=nodes_tuple,
            edges=edges_tuple,
            truncated=False,
            truncation_reason=None,
            max_depth_reached=0,
            limitations=(),
        )
