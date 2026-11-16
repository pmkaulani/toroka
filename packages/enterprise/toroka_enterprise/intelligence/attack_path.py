"""Evidence-backed attack path representation linking entities and events."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .entities import Relationship
    from .events import IntelligenceEvent


@dataclass(frozen=True)
class AttackPathNode:
    node_id: str
    node_type: str
    label: str


@dataclass(frozen=True)
class AttackPathEdge:
    source_id: str
    target_id: str
    relationship: str
    event_ids: tuple[str, ...]
    confidence: float


@dataclass
class AttackPath:
    path_id: str
    nodes: list[AttackPathNode] = field(default_factory=list)
    edges: list[AttackPathEdge] = field(default_factory=list)
    confidence: float = 0.0

    def add_node(
        self,
        node: AttackPathNode,
    ) -> None:
        if not any(existing.node_id == node.node_id for existing in self.nodes):
            self.nodes.append(node)

    def add_edge(
        self,
        edge: AttackPathEdge,
    ) -> None:
        self.edges.append(edge)


def build_attack_path_from_relationships(
    path_id: str,
    relationships: list[Relationship],
    events: list[IntelligenceEvent] | None = None,
) -> AttackPath:
    """Constructs an AttackPath graph from canonical entity relationships and supporting events."""
    path = AttackPath(path_id=path_id)

    # Collect event IDs mapped by entity pair if events provided
    evt_map: dict[tuple[str, str], list[str]] = {}
    if events:
        for evt in events:
            if evt.actor and evt.subject:
                pair = (evt.actor, evt.subject)
                evt_map.setdefault(pair, []).append(evt.event_id)

    for rel in relationships:
        src_node = AttackPathNode(
            node_id=rel.source.entity_id,
            node_type=rel.source.entity_type.value,
            label=rel.source.display_id or rel.source.entity_id,
        )
        tgt_node = AttackPathNode(
            node_id=rel.target.entity_id,
            node_type=rel.target.entity_type.value,
            label=rel.target.display_id or rel.target.entity_id,
        )
        path.add_node(src_node)
        path.add_node(tgt_node)

        supporting_evts = evt_map.get((rel.source.entity_id, rel.target.entity_id), ())
        edge = AttackPathEdge(
            source_id=rel.source.entity_id,
            target_id=rel.target.entity_id,
            relationship=rel.relationship_type,
            event_ids=tuple(supporting_evts),
            confidence=rel.confidence,
        )
        path.add_edge(edge)

    # Set overall path confidence as mean of edge confidences
    if path.edges:
        path.confidence = round(sum(e.confidence for e in path.edges) / len(path.edges), 2)
    else:
        path.confidence = 0.0

    return path
