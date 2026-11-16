from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from .graph import EvidenceBasis, EvidenceNetwork, EvidenceSubgraph, NetworkEdge, NetworkNode
from .motifs import (
    NetworkPatternFinding,
    TransferObservation,
    detect_circular_movement,
    detect_common_beneficiaries,
    detect_fan_patterns,
    detect_multi_hop_movement,
    detect_rapid_pass_through,
    detect_shared_infrastructure,
)
from .resolution import EntityLinkCandidate, EntityLinkStatus, EntityResolutionEngine
from .subgraph import FindingEvidenceSubgraph, extract_finding_subgraph
from .traversal import expand_neighborhood, find_shortest_path


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class NetworkAnalysisResult:
    """Comprehensive, structured network intelligence analysis result."""
    analysis_id: str
    installation_id: str
    case_id: str | None
    anchor_entities: tuple[str, ...]
    subgraph: EvidenceSubgraph
    findings: tuple[NetworkPatternFinding, ...]
    entity_link_candidates: tuple[EntityLinkCandidate, ...]
    source_coverage: float
    source_systems: tuple[str, ...]
    alternative_explanations: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    institutional_pattern_matches: tuple[dict[str, Any], ...]
    executed_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "installation_id": self.installation_id,
            "case_id": self.case_id,
            "anchor_entities": list(self.anchor_entities),
            "subgraph": self.subgraph.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "entity_link_candidates": [c.to_dict() for c in self.entity_link_candidates],
            "source_coverage": self.source_coverage,
            "source_systems": list(self.source_systems),
            "alternative_explanations": list(self.alternative_explanations),
            "missing_evidence": list(self.missing_evidence),
            "institutional_pattern_matches": list(self.institutional_pattern_matches),
            "executed_at": self.executed_at.isoformat(),
        }


class NetworkAnalysisService:
    """Orchestrates multi-source graph assembly, traversal, motif mining, and explainable intelligence."""

    def __init__(self, installation_id: str) -> None:
        self.installation_id = installation_id

    def build_network_from_events(
        self,
        events: list[dict[str, Any]],
        relationships: list[dict[str, Any]] | None = None,
        as_of: datetime | None = None,
    ) -> tuple[EvidenceNetwork, list[TransferObservation], list[EntityLinkCandidate]]:
        """Construct an EvidenceNetwork and extracted TransferObservations from normalized events."""
        graph = EvidenceNetwork(self.installation_id)
        transfers: list[TransferObservation] = []
        candidates: list[EntityLinkCandidate] = []

        seen_nodes: set[str] = set()

        def ensure_node(k: str, etype: str, label: str, t: datetime | None = None) -> None:
            t_utc = _ensure_utc(t)
            if k not in graph.nodes:
                n = NetworkNode(
                    installation_id=self.installation_id,
                    node_key=k,
                    entity_type=etype,
                    pseudonymous_label=label,
                    first_seen=t_utc,
                    last_seen=t_utc,
                )
                graph.add_node(n)
            else:
                existing = graph.get_node(k)
                if existing and t_utc:
                    e_first = _ensure_utc(existing.first_seen)
                    e_last = _ensure_utc(existing.last_seen)
                    first_s = min(e_first, t_utc) if e_first else t_utc
                    last_s = max(e_last, t_utc) if e_last else t_utc
                    graph._nodes[k] = NetworkNode(
                        installation_id=self.installation_id,
                        node_key=k,
                        entity_type=existing.entity_type,
                        pseudonymous_label=existing.pseudonymous_label,
                        attributes=existing.attributes,
                        first_seen=first_s,
                        last_seen=last_s,
                    )

        # 1. Process relationships if provided
        for rel in relationships or []:
            if rel.get("installation_id") != self.installation_id:
                continue
            src = rel.get("source", {})
            tgt = rel.get("target", {})
            src_key = f"{src.get('entity_type', 'entity')}:{src.get('entity_id')}"
            tgt_key = f"{tgt.get('entity_type', 'entity')}:{tgt.get('entity_id')}"

            t_first = rel.get("first_seen")
            if isinstance(t_first, str):
                t_first = datetime.fromisoformat(t_first)
            if as_of and t_first and _ensure_utc(t_first) > _ensure_utc(as_of):
                continue

            ensure_node(src_key, src.get("entity_type", "entity"), src.get("display_id") or src_key, t_first)
            ensure_node(tgt_key, tgt.get("entity_type", "entity"), tgt.get("display_id") or tgt_key, t_first)

            edge = NetworkEdge(
                installation_id=self.installation_id,
                source_key=src_key,
                target_key=tgt_key,
                relationship_type=rel.get("relationship_type", "associated_with"),
                evidence_basis=EvidenceBasis.DIRECT_OBSERVATION,
                source_record_ids=(rel.get("source_record_id", ""),) if rel.get("source_record_id") else (),
                source_systems=(rel.get("source_system", "core_banking"),) if rel.get("source_system") else (),
                confidence=float(rel.get("confidence", 1.0)),
                first_seen=t_first,
            )
            graph.add_edge(edge)

        # 2. Process normalized events
        for ev in events:
            if ev.get("installation_id") != self.installation_id:
                continue

            ev_time = ev.get("event_time")
            if isinstance(ev_time, str):
                ev_time = datetime.fromisoformat(ev_time)
            avail_at = ev.get("available_at", ev_time)
            if isinstance(avail_at, str):
                avail_at = datetime.fromisoformat(avail_at)

            # Never use future evidence
            if as_of and avail_at and _ensure_utc(avail_at) > _ensure_utc(as_of):
                continue

            ev_id = str(ev.get("event_id", ""))
            ev_type = str(ev.get("event_type", ""))
            source_sys = str(ev.get("source_system", "unknown"))
            attrs = ev.get("attributes", {})

            # Transactions / transfers
            if "transfer" in ev_type or "payment" in ev_type or "transaction" in ev_type:
                src_acc = ev.get("actor") or attrs.get("source_account") or attrs.get("from_account")
                tgt_acc = ev.get("subject") or attrs.get("target_account") or attrs.get("to_account")
                raw_amt = attrs.get("amount", 0)
                curr = str(attrs.get("currency", "USD"))
                amt = Decimal(str(raw_amt)) if raw_amt else Decimal("0")

                if src_acc and tgt_acc:
                    src_k = f"account:{src_acc}"
                    tgt_k = f"account:{tgt_acc}"
                    ensure_node(src_k, "account", f"Account {src_acc}", ev_time)
                    ensure_node(tgt_k, "account", f"Account {tgt_acc}", ev_time)

                    # Add transfer edge
                    edge = NetworkEdge(
                        installation_id=self.installation_id,
                        source_key=src_k,
                        target_key=tgt_k,
                        relationship_type="transferred_funds_to",
                        evidence_basis=EvidenceBasis.DIRECT_OBSERVATION,
                        event_ids=(ev_id,) if ev_id else (),
                        source_record_ids=(str(ev.get("source_record_id", "")),) if ev.get("source_record_id") else (),
                        source_systems=(source_sys,),
                        first_seen=ev_time,
                        last_seen=ev_time,
                        confidence=1.0,
                        directed=True,
                        attributes={"amount": str(amt), "currency": curr},
                    )
                    graph.add_edge(edge)

                    # Create TransferObservation for motif detection
                    transfers.append(
                        TransferObservation(
                            installation_id=self.installation_id,
                            event_id=ev_id or str(uuid.uuid4()),
                            source_account=src_k,
                            target_account=tgt_k,
                            amount=amt,
                            currency=curr,
                            event_time=ev_time,
                            available_at=avail_at,
                            source_system=source_sys,
                            transaction_id=str(attrs.get("transaction_id", ev_id)),
                            attributes=attrs,
                        )
                    )

            # Access / IAM / Employee login / session
            elif "login" in ev_type or "session" in ev_type or "access" in ev_type:
                actor = ev.get("actor")
                dev = attrs.get("device_id") or attrs.get("ip_address")
                if actor and dev:
                    actor_k = f"employee:{actor}" if "emp" in actor.lower() else f"customer:{actor}"
                    dev_k = f"device:{dev}"
                    ensure_node(actor_k, "employee" if "emp" in actor.lower() else "customer", actor, ev_time)
                    ensure_node(dev_k, "device", f"Device {dev}", ev_time)

                    edge = NetworkEdge(
                        installation_id=self.installation_id,
                        source_key=actor_k,
                        target_key=dev_k,
                        relationship_type="accessed_via_device",
                        evidence_basis=EvidenceBasis.DIRECT_OBSERVATION,
                        event_ids=(ev_id,) if ev_id else (),
                        source_systems=(source_sys,),
                        first_seen=ev_time,
                        confidence=0.95,
                    )
                    graph.add_edge(edge)

            # Check for shared attributes to propose link candidates
            dev_id = attrs.get("device_id")
            phone = attrs.get("phone") or attrs.get("telephone")
            subject = ev.get("subject") or ev.get("actor")
            if subject:
                subj_k = f"entity:{subject}"
                if dev_id:
                    cand = EntityResolutionEngine.propose_candidate(
                        installation_id=self.installation_id,
                        source_key=subj_k,
                        target_key=f"device:{dev_id}",
                        attribute_type="device_id",
                        attribute_value=str(dev_id),
                        source_systems=[source_sys],
                        observed_time=ev_time,
                    )
                    candidates.append(cand)

        return graph, transfers, candidates

    def analyze(
        self,
        seed_entities: list[str],
        events: list[dict[str, Any]],
        relationships: list[dict[str, Any]] | None = None,
        *,
        case_id: str | None = None,
        max_depth: int = 2,
        max_nodes: int = 100,
        max_edges: int = 200,
        include_shared_attributes: bool = False,
        as_of: datetime | None = None,
    ) -> NetworkAnalysisResult:
        """Execute full network intelligence analysis for seed entities."""
        graph, transfers, candidates = self.build_network_from_events(events, relationships, as_of=as_of)

        # Expand neighborhood
        subgraph = expand_neighborhood(
            graph,
            set(seed_entities),
            max_depth=max_depth,
            max_nodes=max_nodes,
            max_edges=max_edges,
            include_shared_attributes=include_shared_attributes,
            as_of=as_of,
        )

        # Run motif detectors
        findings: list[NetworkPatternFinding] = []
        findings.extend(detect_fan_patterns(transfers, as_of=as_of))
        findings.extend(detect_rapid_pass_through(transfers, as_of=as_of))
        findings.extend(detect_multi_hop_movement(transfers, as_of=as_of))
        findings.extend(detect_circular_movement(transfers, as_of=as_of))
        findings.extend(detect_common_beneficiaries(transfers, as_of=as_of))
        findings.extend(detect_shared_infrastructure(events, self.installation_id, as_of=as_of))

        # Compute source coverage
        detected_sources = sorted({e.get("source_system", "unknown") for e in events})
        expected_sources = ["core_banking", "payment_switch", "iam", "siem", "channel_telemetry"]
        coverage = round(len(set(detected_sources) & set(expected_sources)) / len(expected_sources), 2)

        # Compile alternative explanations
        alt_explanations: list[str] = [
            "Normal commercial batch payroll or vendor invoice distributions.",
            "Authorized multi-account management by power of attorney or business administrator.",
            "Family shared devices or public shared kiosks in branch premises.",
            "Intercompany liquidity management across affiliated corporate accounts.",
        ]

        missing_evidence: list[str] = []
        if "iam" not in detected_sources:
            missing_evidence.append("IAM authentication and privileged session telemetry")
        if "channel_telemetry" not in detected_sources:
            missing_evidence.append("Device fingerprint and channel security context")

        # Mock / integration comparison against Phase 9 institutional patterns
        institutional_matches: list[dict[str, Any]] = []
        if findings:
            institutional_matches.append({
                "pattern_id": "typ_fan_in_pass_through_v1",
                "title": "Layered Pass-Through & Mule Dispersal",
                "similarity_score": 0.86,
                "control_weaknesses": ["delayed_outbound_velocity_alerting", "unmonitored_dormancy_reactivation"],
            })

        aid = f"netrun_{hashlib.sha256(f'{self.installation_id}:{case_id}:{uuid.uuid4().hex}'.encode()).hexdigest()[:16]}"

        return NetworkAnalysisResult(
            analysis_id=aid,
            installation_id=self.installation_id,
            case_id=case_id,
            anchor_entities=tuple(sorted(seed_entities)),
            subgraph=subgraph,
            findings=tuple(findings),
            entity_link_candidates=tuple(candidates[:20]),
            source_coverage=coverage,
            source_systems=tuple(detected_sources),
            alternative_explanations=tuple(alt_explanations),
            missing_evidence=tuple(missing_evidence),
            institutional_pattern_matches=tuple(institutional_matches),
            executed_at=datetime.now(timezone.utc),
        )
