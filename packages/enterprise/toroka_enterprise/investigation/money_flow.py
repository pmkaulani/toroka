"""Bounded temporal money-flow reconstruction from authorized transaction events."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class MoneyFlowNode:
    entity_id: UUID
    display_label: str | None = None
    kind: str = "account"
    is_root: bool = False
    is_terminal: bool = False


@dataclass(frozen=True)
class MoneyFlowEdge:
    source_entity_id: UUID
    destination_entity_id: UUID
    amount: Decimal
    currency: str
    occurred_at: datetime
    event_type: str
    channel: str
    source_record_ref: str
    evidence_id: UUID
    transaction_id: UUID | None = None
    is_reversal: bool = False
    is_refund: bool = False
    is_cash_out: bool = False
    is_gap: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_entity_id": str(self.source_entity_id),
            "destination_entity_id": str(self.destination_entity_id),
            "amount": str(self.amount),
            "currency": self.currency,
            "occurred_at": self.occurred_at.isoformat(),
            "event_type": self.event_type,
            "channel": self.channel,
            "source_record_ref": self.source_record_ref,
            "evidence_id": str(self.evidence_id),
            "transaction_id": str(self.transaction_id) if self.transaction_id else None,
            "is_reversal": self.is_reversal,
            "is_refund": self.is_refund,
            "is_cash_out": self.is_cash_out,
            "is_gap": self.is_gap,
        }


@dataclass
class MoneyFlowReconstruction:
    root_entity_id: UUID
    nodes: list[MoneyFlowNode] = field(default_factory=list)
    edges: list[MoneyFlowEdge] = field(default_factory=list)
    currency_totals: dict[str, Decimal] = field(default_factory=dict)
    reversal_totals: dict[str, Decimal] = field(default_factory=dict)
    refund_totals: dict[str, Decimal] = field(default_factory=dict)
    net_by_currency: dict[str, Decimal] = field(default_factory=dict)
    missing_hops_detected: int = 0
    earliest_at: datetime | None = None
    latest_at: datetime | None = None
    hop_limit_reached: bool = False
    node_limit_reached: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_entity_id": str(self.root_entity_id),
            "nodes": [
                {
                    "entity_id": str(n.entity_id),
                    "display_label": n.display_label,
                    "kind": n.kind,
                    "is_root": n.is_root,
                    "is_terminal": n.is_terminal,
                }
                for n in self.nodes
            ],
            "edges": [e.to_dict() for e in self.edges],
            "currency_totals": {k: str(v) for k, v in self.currency_totals.items()},
            "reversal_totals": {k: str(v) for k, v in self.reversal_totals.items()},
            "refund_totals": {k: str(v) for k, v in self.refund_totals.items()},
            "net_by_currency": {k: str(v) for k, v in self.net_by_currency.items()},
            "missing_hops_detected": self.missing_hops_detected,
            "earliest_at": self.earliest_at.isoformat() if self.earliest_at else None,
            "latest_at": self.latest_at.isoformat() if self.latest_at else None,
            "hop_limit_reached": self.hop_limit_reached,
            "node_limit_reached": self.node_limit_reached,
        }


def reconstruct_money_flow(
    *,
    transactions: list[Any],
    root_entity_id: str | UUID,
    max_hops: int = 5,
    max_nodes: int = 50,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
) -> MoneyFlowReconstruction:
    """Reconstructs bounded chronological flow of funds forward from root entity.
    
    Preserves reversals, refunds, and cash-outs without inferring speculative intermediate transactions.
    """
    # Filter by time bounds if provided
    filtered_txs = []
    for tx in transactions:
        tx_time = getattr(tx, "occurred_at", None)
        if tx_time is None:
            continue
        if start_time and tx_time < start_time:
            continue
        if end_time and tx_time > end_time:
            continue
        filtered_txs.append(tx)

    # Sort strictly chronologically
    filtered_txs.sort(key=lambda x: getattr(x, "occurred_at"))

    # Graph adjacency by source
    forward_adj: dict[str, list[Any]] = defaultdict(list)
    for tx in filtered_txs:
        src = str(getattr(tx, "source_entity_id"))
        forward_adj[src].append(tx)

    root_id_str = str(root_entity_id)
    visited_nodes: set[str] = {root_id_str}
    collected_edges: list[MoneyFlowEdge] = []
    currency_totals: dict[str, Decimal] = defaultdict(Decimal)
    reversal_totals: dict[str, Decimal] = defaultdict(Decimal)
    refund_totals: dict[str, Decimal] = defaultdict(Decimal)

    # BFS from root_entity_id up to max_hops
    queue = deque([(root_id_str, 0)])
    hop_limit_reached = False
    node_limit_reached = False

    while queue:
        current_entity_str, hop_depth = queue.popleft()
        if hop_depth >= max_hops:
            hop_limit_reached = True
            continue

        outgoing = forward_adj.get(current_entity_str, [])
        for tx in outgoing:
            dst_str = str(getattr(tx, "destination_entity_id"))
            amount = Decimal(str(getattr(tx, "amount")))
            currency = str(getattr(tx, "currency"))
            event_type = str(getattr(tx, "event_type", "transfer")).lower()

            is_rev = event_type == "reversal"
            is_ref = event_type == "refund"
            is_cash = event_type in ("cash_out", "atm_withdrawal", "agent_withdrawal")

            # Check duplicate edge in collected
            edge = MoneyFlowEdge(
                source_entity_id=UUID(current_entity_str),
                destination_entity_id=UUID(dst_str),
                amount=amount,
                currency=currency,
                occurred_at=getattr(tx, "occurred_at"),
                event_type=event_type,
                channel=str(getattr(tx, "channel", "electronic")),
                source_record_ref=str(getattr(tx, "source_record_ref", "")),
                evidence_id=UUID(str(getattr(tx, "evidence_id"))),
                transaction_id=UUID(str(getattr(tx, "id"))) if getattr(tx, "id", None) else None,
                is_reversal=is_rev,
                is_refund=is_ref,
                is_cash_out=is_cash,
                is_gap=False,
            )
            collected_edges.append(edge)

            # Compute totals by currency
            if is_rev:
                reversal_totals[currency] += amount
            elif is_ref:
                refund_totals[currency] += amount
            else:
                currency_totals[currency] += amount

            if dst_str not in visited_nodes:
                if len(visited_nodes) >= max_nodes:
                    node_limit_reached = True
                    break
                visited_nodes.add(dst_str)
                queue.append((dst_str, hop_depth + 1))

        if node_limit_reached:
            break

    # Net computation per currency
    net_by_currency: dict[str, Decimal] = {}
    all_currencies = set(currency_totals.keys()) | set(reversal_totals.keys()) | set(refund_totals.keys())
    for curr in all_currencies:
        inflow_gross = currency_totals.get(curr, Decimal("0"))
        revs = reversal_totals.get(curr, Decimal("0"))
        refs = refund_totals.get(curr, Decimal("0"))
        net_by_currency[curr] = inflow_gross - revs - refs

    # Build node list
    nodes = []
    destinations_present = {e.destination_entity_id for e in collected_edges}
    sources_present = {e.source_entity_id for e in collected_edges}

    for n_id_str in visited_nodes:
        n_id = UUID(n_id_str)
        is_root = (n_id_str == root_id_str)
        is_terminal = (n_id in destinations_present and n_id not in sources_present)
        nodes.append(
            MoneyFlowNode(
                entity_id=n_id,
                display_label=f"Entity-{n_id_str[:8]}",
                kind="account",
                is_root=is_root,
                is_terminal=is_terminal,
            )
        )

    earliest = min((e.occurred_at for e in collected_edges), default=None)
    latest = max((e.occurred_at for e in collected_edges), default=None)

    return MoneyFlowReconstruction(
        root_entity_id=UUID(root_id_str),
        nodes=nodes,
        edges=collected_edges,
        currency_totals=dict(currency_totals),
        reversal_totals=dict(reversal_totals),
        refund_totals=dict(refund_totals),
        net_by_currency=net_by_currency,
        missing_hops_detected=0,
        earliest_at=earliest,
        latest_at=latest,
        hop_limit_reached=hop_limit_reached,
        node_limit_reached=node_limit_reached,
    )
