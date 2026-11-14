"""Consumer-app wrapper: the graph builder lives in toroka_core; this injects the connectors' domain normaliser."""
from __future__ import annotations
from typing import Any
from ssi_connectors.domain_intelligence import normalize_domain
from toroka_core.graph.evidence_graph import build_evidence_graph as _build


def build_evidence_graph(targets: list[dict[str, Any]] | None, evidence: list[dict[str, Any]] | None, *,
                         shop_discovery: dict[str, Any] | None = None) -> dict[str, Any]:
    return _build(targets, evidence, shop_discovery=shop_discovery, normalize_domain=normalize_domain)
