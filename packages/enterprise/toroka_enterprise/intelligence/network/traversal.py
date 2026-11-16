from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from typing import Any

from .graph import (
    EvidenceBasis,
    EvidenceNetwork,
    EvidenceSubgraph,
    NetworkEdge,
    NetworkNode,
)


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def expand_neighborhood(
    graph: EvidenceNetwork,
    seed_nodes: set[str],
    *,
    max_depth: int = 2,
    max_nodes: int = 100,
    max_edges: int = 200,
    minimum_confidence: float = 0.5,
    include_shared_attributes: bool = False,
    direction: str = "both",
    as_of: datetime | None = None,
) -> EvidenceSubgraph:
    """Bounded neighborhood expansion with deterministic traversal and explicit truncation signaling."""
    if max_depth < 0:
        raise ValueError("max_depth cannot be negative")
    if max_nodes < 1 or max_edges < 1:
        raise ValueError("Graph limits must be positive")
    if not (0.0 <= minimum_confidence <= 1.0):
        raise ValueError("Invalid confidence threshold")
    if not seed_nodes:
        raise ValueError("At least one seed entity is required")
    if not seed_nodes.issubset(graph.nodes):
        raise ValueError("One or more seed entities are unknown")

    # Deterministic start ordering
    sorted_seeds = sorted(seed_nodes)

    collected_nodes: dict[str, NetworkNode] = {}
    collected_edges: dict[str, NetworkEdge] = {}
    node_depth: dict[str, int] = {}

    for s in sorted_seeds:
        if len(collected_nodes) < max_nodes:
            node = graph.get_node(s)
            if node:
                collected_nodes[s] = node
                node_depth[s] = 0

    queue: deque[tuple[str, int]] = deque([(s, 0) for s in sorted_seeds if s in collected_nodes])
    truncated = False
    truncation_reasons: list[str] = []
    max_depth_reached = 0

    while queue:
        current_key, depth = queue.popleft()
        if depth > max_depth_reached:
            max_depth_reached = depth

        if depth >= max_depth:
            # Check if there are unvisited adjacent nodes that would have been expanded
            adj = graph.get_adjacent_edges(
                current_key,
                direction=direction,
                include_shared_attributes=include_shared_attributes,
                min_confidence=minimum_confidence,
            )
            for edge in adj:
                neighbor_key = edge.target_key if edge.source_key == current_key else edge.source_key
                if neighbor_key not in collected_nodes:
                    truncated = True
                    if "max_depth_reached" not in truncation_reasons:
                        truncation_reasons.append("max_depth_reached")
                    break
            continue

        adj_edges = graph.get_adjacent_edges(
            current_key,
            direction=direction,
            include_shared_attributes=include_shared_attributes,
            min_confidence=minimum_confidence,
        )

        for edge in adj_edges:
            # Temporal filter: relationship must have been established on or before as_of
            if as_of and edge.first_seen and _ensure_utc(edge.first_seen) > _ensure_utc(as_of):
                continue

            neighbor_key = edge.target_key if edge.source_key == current_key else edge.source_key

            # Edge collection check
            if edge.edge_id not in collected_edges:
                if len(collected_edges) >= max_edges:
                    truncated = True
                    if "max_edges_reached" not in truncation_reasons:
                        truncation_reasons.append("max_edges_reached")
                    continue
                collected_edges[edge.edge_id] = edge

            # Node collection check
            if neighbor_key not in collected_nodes:
                if len(collected_nodes) >= max_nodes:
                    truncated = True
                    if "max_nodes_reached" not in truncation_reasons:
                        truncation_reasons.append("max_nodes_reached")
                    continue

                neighbor_node = graph.get_node(neighbor_key)
                if neighbor_node:
                    collected_nodes[neighbor_key] = neighbor_node
                    node_depth[neighbor_key] = depth + 1
                    queue.append((neighbor_key, depth + 1))

    limitations: list[str] = []
    if not include_shared_attributes:
        limitations.append("Weak shared-attribute associations were excluded from traversal.")
    if minimum_confidence > 0.0:
        limitations.append(f"Relationships below {minimum_confidence:.2f} confidence were excluded.")
    if truncated:
        limitations.append(f"Graph traversal was bounded: {', '.join(truncation_reasons)}.")

    sorted_nodes = tuple(sorted(collected_nodes.values(), key=lambda n: n.node_key))
    sorted_edges = tuple(sorted(collected_edges.values(), key=lambda e: (e.source_key, e.target_key, e.relationship_type)))

    return EvidenceSubgraph(
        installation_id=graph.installation_id,
        seed_nodes=tuple(sorted_seeds),
        nodes=sorted_nodes,
        edges=sorted_edges,
        truncated=truncated,
        truncation_reason="; ".join(truncation_reasons) if truncation_reasons else None,
        max_depth_reached=max_depth_reached,
        limitations=tuple(limitations),
    )


def find_shortest_path(
    graph: EvidenceNetwork,
    source_key: str,
    target_key: str,
    *,
    max_depth: int = 5,
    minimum_confidence: float = 0.5,
    include_shared_attributes: bool = False,
    direction: str = "both",
) -> tuple[tuple[NetworkNode, ...], tuple[NetworkEdge, ...]] | None:
    """Find the shortest evidence-backed path between two entities using BFS."""
    if source_key not in graph.nodes or target_key not in graph.nodes:
        return None
    if source_key == target_key:
        src = graph.get_node(source_key)
        return ((src,), ()) if src else None

    # Queue stores (current_node, list_of_nodes, list_of_edges)
    queue: deque[tuple[str, list[str], list[NetworkEdge]]] = deque([(source_key, [source_key], [])])
    visited: set[str] = {source_key}

    while queue:
        curr, path_nodes, path_edges = queue.popleft()
        if len(path_edges) >= max_depth:
            continue

        adj_edges = graph.get_adjacent_edges(
            curr,
            direction=direction,
            include_shared_attributes=include_shared_attributes,
            min_confidence=minimum_confidence,
        )

        for edge in adj_edges:
            neighbor = edge.target_key if edge.source_key == curr else edge.source_key
            if neighbor == target_key:
                final_node_keys = path_nodes + [target_key]
                final_edges = path_edges + [edge]
                nodes = tuple(graph.get_node(k) for k in final_node_keys if graph.get_node(k) is not None) # type: ignore
                return nodes, tuple(final_edges)

            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path_nodes + [neighbor], path_edges + [edge]))

    return None
