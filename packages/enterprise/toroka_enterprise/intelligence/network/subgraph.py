from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .graph import EvidenceBasis, EvidenceNetwork, EvidenceSubgraph, NetworkEdge, NetworkNode
from .motifs import NetworkPatternFinding


@dataclass(frozen=True)
class FindingEvidenceSubgraph:
    """Compact, explainable evidence subgraph tailored to an individual network finding."""
    finding_id: str
    installation_id: str
    pattern_type: str
    anchor_entity: str
    nodes: tuple[NetworkNode, ...]
    edges: tuple[NetworkEdge, ...]
    supporting_event_ids: tuple[str, ...]
    supporting_transaction_ids: tuple[str, ...]
    supporting_source_systems: tuple[str, ...]
    confidence: float
    explanation: str
    limitations: tuple[str, ...]
    alternative_explanations: tuple[str, ...]
    missing_information: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "installation_id": self.installation_id,
            "pattern_type": self.pattern_type,
            "anchor_entity": self.anchor_entity,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "supporting_event_ids": list(self.supporting_event_ids),
            "supporting_transaction_ids": list(self.supporting_transaction_ids),
            "supporting_source_systems": list(self.supporting_source_systems),
            "confidence": self.confidence,
            "explanation": self.explanation,
            "limitations": list(self.limitations),
            "alternative_explanations": list(self.alternative_explanations),
            "missing_information": list(self.missing_information),
        }


def extract_finding_subgraph(
    finding: NetworkPatternFinding,
    graph: EvidenceNetwork,
) -> FindingEvidenceSubgraph:
    """Extract the minimal evidence subgraph substantiating a specific network finding."""
    if finding.installation_id != graph.installation_id:
        raise ValueError("Finding and graph installation mismatch")

    involved_keys = {finding.anchor_entity} | set(finding.related_entities)
    nodes: list[NetworkNode] = []
    for k in sorted(involved_keys):
        n = graph.get_node(k)
        if n:
            nodes.append(n)

    # Collect edges connecting the involved nodes that share the finding's event_ids or relate to them
    finding_event_set = set(finding.event_ids)
    edges: list[NetworkEdge] = []
    seen_edge_ids: set[str] = set()

    for e in graph.edges:
        if e.source_key in involved_keys and e.target_key in involved_keys:
            # Check if this edge has supporting events matching the finding
            if set(e.event_ids) & finding_event_set or not finding_event_set:
                if e.edge_id not in seen_edge_ids:
                    seen_edge_ids.add(e.edge_id)
                    edges.append(e)

    missing_info: list[str] = []
    if not finding.supporting_source_systems or "core_banking" not in finding.supporting_source_systems:
        missing_info.append("Core banking account balance ledger corroboration")
    if "iam" not in finding.supporting_source_systems and "employee" in finding.anchor_entity:
        missing_info.append("IAM access control session telemetry")

    return FindingEvidenceSubgraph(
        finding_id=finding.pattern_id,
        installation_id=finding.installation_id,
        pattern_type=finding.pattern_type,
        anchor_entity=finding.anchor_entity,
        nodes=tuple(sorted(nodes, key=lambda x: x.node_key)),
        edges=tuple(sorted(edges, key=lambda x: (x.source_key, x.target_key, x.relationship_type))),
        supporting_event_ids=finding.event_ids,
        supporting_transaction_ids=finding.transaction_ids,
        supporting_source_systems=finding.supporting_source_systems,
        confidence=finding.confidence,
        explanation=finding.explanation,
        limitations=finding.evidence_limitations,
        alternative_explanations=finding.alternative_legitimate_explanations,
        missing_information=tuple(missing_info),
    )
