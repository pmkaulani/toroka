"""Multi-Tiered Mule Tracing & Graph Cascade Engine (China PBOC / UK PSR Model).

Implements real-time downstream rapid-dispersion graph tracing and automated
interbank recall directives across 3 hops:
  - Tier 1: Direct Fraud Beneficiary (Immediate recipient of victim transfer)
  - Tier 2: Secondary Dispersion Mule (Layering nodes receiving split funds)
  - Tier 3: Cashout Gateway (ATM, POS, Crypto OTC, Agency banking, Telco Till)

Enforces strict causal temporality: outgoing transfers occurring prior to the
incoming fraudulent credit are excluded from the cascade trace.
Generates automated interbank directives:
  - Internal nodes: IMMEDIATE_FREEZE, INFLOW_ONLY_RESTRICTION, ESCROW_DELAY_HOLD_48H
  - External nodes: ISO 20022 camt.056.001.10 FIToFIPaymentCancellationRequest (FRAD)
"""
from __future__ import annotations

import uuid
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import IntEnum, StrEnum
from typing import Any


def _ensure_utc(dt: datetime | None) -> datetime:
    if dt is None:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class MuleCascadeTier(IntEnum):
    TIER_1_DIRECT_BENEFICIARY = 1
    TIER_2_SECONDARY_DISPERSION = 2
    TIER_3_CASHOUT_GATEWAY = 3


class CascadeHoldDirectiveType(StrEnum):
    IMMEDIATE_FREEZE = "IMMEDIATE_FREEZE"
    INFLOW_ONLY_RESTRICTION = "INFLOW_ONLY_RESTRICTION"
    ESCROW_DELAY_HOLD_48H = "ESCROW_DELAY_HOLD_48H"
    INTERBANK_CAMT056_DISPATCH = "INTERBANK_CAMT056_DISPATCH"
    MONITOR_AND_ALERT = "MONITOR_AND_ALERT"


@dataclass(frozen=True)
class MuleCascadeNode:
    node_key: str  # Account number or MSISDN
    tier_level: MuleCascadeTier
    bank_bic: str
    account_name: str | None = None
    total_inflow: Decimal = Decimal("0.0")
    total_outflow: Decimal = Decimal("0.0")
    retained_balance_estimate: Decimal = Decimal("0.0")
    velocity_minutes: float = 0.0  # Inflow-to-outflow dispersion delay in minutes
    dispersion_ratio: float = 0.0  # total_outflow / total_inflow
    risk_score: float = 0.0        # 0.0 to 1.0
    recommended_directive: CascadeHoldDirectiveType = CascadeHoldDirectiveType.MONITOR_AND_ALERT
    directive_status: str = "PENDING"  # PENDING, EXECUTED, REJECTED
    first_inflow_time: datetime | None = None
    last_outflow_time: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_key": self.node_key,
            "tier_level": int(self.tier_level),
            "tier_name": self.tier_level.name,
            "bank_bic": self.bank_bic,
            "account_name": self.account_name,
            "total_inflow": str(self.total_inflow),
            "total_outflow": str(self.total_outflow),
            "retained_balance_estimate": str(self.retained_balance_estimate),
            "velocity_minutes": round(self.velocity_minutes, 2),
            "dispersion_ratio": round(self.dispersion_ratio, 4),
            "risk_score": round(self.risk_score, 4),
            "recommended_directive": self.recommended_directive.value,
            "directive_status": self.directive_status,
            "first_inflow_time": self.first_inflow_time.isoformat() if self.first_inflow_time else None,
            "last_outflow_time": self.last_outflow_time.isoformat() if self.last_outflow_time else None,
        }


@dataclass(frozen=True)
class MuleCascadeEdge:
    edge_id: str
    source_node: str
    target_node: str
    amount: Decimal
    currency: str
    timestamp: datetime
    payment_rail: str  # PESALINK, MPESA, RTGS, SWIFT, INTERNAL
    transaction_id: str
    hop_number: int    # 1, 2, 3
    transfer_delay_minutes: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_node": self.source_node,
            "target_node": self.target_node,
            "amount": str(self.amount),
            "currency": self.currency,
            "timestamp": self.timestamp.isoformat(),
            "payment_rail": self.payment_rail,
            "transaction_id": self.transaction_id,
            "hop_number": self.hop_number,
            "transfer_delay_minutes": round(self.transfer_delay_minutes, 2),
        }


@dataclass
class MuleCascadeTraceResult:
    trace_id: str
    installation_id: str
    root_account: str
    root_transaction_id: str | None
    root_fraud_amount: Decimal
    currency: str
    max_depth_reached: int
    nodes: list[MuleCascadeNode]
    edges: list[MuleCascadeEdge]
    total_nodes_identified: int
    total_frozen_or_held_amount: Decimal
    recovery_potential_ratio: float  # held / root_fraud_amount
    created_at: datetime
    directives_generated: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "installation_id": self.installation_id,
            "root_account": self.root_account,
            "root_transaction_id": self.root_transaction_id,
            "root_fraud_amount": str(self.root_fraud_amount),
            "currency": self.currency,
            "max_depth_reached": self.max_depth_reached,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "total_nodes_identified": self.total_nodes_identified,
            "total_frozen_or_held_amount": str(self.total_frozen_or_held_amount),
            "recovery_potential_ratio": round(self.recovery_potential_ratio, 4),
            "created_at": self.created_at.isoformat(),
            "directives_generated": self.directives_generated,
        }


class MuleCascadeTracerEngine:
    """Graph traversal and rapid-freezing directive generator."""

    def __init__(self, local_bank_bic: str = "KCBKKENA"):
        self.local_bank_bic = local_bank_bic.upper().strip()

    def trace_cascade(
        self,
        *,
        installation_id: str,
        root_account: str,
        root_fraud_amount: Decimal,
        currency: str = "KES",
        root_transaction_id: str | None = None,
        anchor_time: datetime | None = None,
        transfers: list[dict[str, Any]],
        max_hops: int = 3,
        time_window_hours: int = 72,
        account_metadata: dict[str, dict[str, Any]] | None = None,
    ) -> MuleCascadeTraceResult:
        """Traces the downstream mule dispersion cascade starting from root_account.

        Each transfer in transfers must have:
          - source_account: str
          - target_account: str
          - amount: Decimal or float/str
          - timestamp: datetime or ISO string
          - transaction_id: str
          - payment_rail: str (optional, defaults to "PESALINK")
          - source_bic: str (optional)
          - target_bic: str (optional)
        """
        trace_id = f"casc_{uuid.uuid4().hex[:16]}"
        anchor_dt = _ensure_utc(anchor_time)
        window_end = anchor_dt + timedelta(hours=time_window_hours)
        metadata = account_metadata or {}

        # Normalize transfers
        parsed_transfers: list[dict[str, Any]] = []
        for t in transfers:
            src = str(t.get("source_account", "")).strip()
            tgt = str(t.get("target_account", "")).strip()
            if not src or not tgt:
                continue
            amt = Decimal(str(t.get("amount", "0.0")))
            if amt <= Decimal("0.0"):
                continue

            raw_ts = t.get("timestamp")
            if isinstance(raw_ts, str):
                ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            elif isinstance(raw_ts, datetime):
                ts = raw_ts
            else:
                ts = anchor_dt
            ts = _ensure_utc(ts)

            parsed_transfers.append({
                "source_account": src,
                "target_account": tgt,
                "amount": amt,
                "currency": str(t.get("currency", currency)).upper(),
                "timestamp": ts,
                "transaction_id": str(t.get("transaction_id", f"tx_{uuid.uuid4().hex[:8]}")),
                "payment_rail": str(t.get("payment_rail", "PESALINK")).upper(),
                "source_bic": str(t.get("source_bic", self.local_bank_bic)).upper(),
                "target_bic": str(t.get("target_bic", self.local_bank_bic)).upper(),
            })

        # BFS Traversal
        # Queue item: (account, current_hop, arrival_time, incoming_amount)
        queue: deque[tuple[str, int, datetime, Decimal]] = deque()
        queue.append((root_account, 1, anchor_dt, root_fraud_amount))

        visited_nodes: dict[str, dict[str, Any]] = {}
        recorded_edges: list[MuleCascadeEdge] = []
        max_depth = 1

        # Root node setup (Tier 1 Direct Beneficiary)
        root_bic = metadata.get(root_account, {}).get("bank_bic", self.local_bank_bic)
        visited_nodes[root_account] = {
            "tier": MuleCascadeTier.TIER_1_DIRECT_BENEFICIARY,
            "bank_bic": root_bic,
            "account_name": metadata.get(root_account, {}).get("account_name", f"Account {root_account}"),
            "inflow": root_fraud_amount,
            "outflow": Decimal("0.0"),
            "first_inflow": anchor_dt,
            "last_outflow": None,
            "first_outflow": None,
        }

        while queue:
            curr_acc, curr_hop, curr_arrival_ts, curr_funds = queue.popleft()
            if curr_hop > max_hops:
                continue

            # Find valid downstream outgoing transfers from curr_acc
            # Causal check: transfer timestamp >= curr_arrival_ts and within window
            outgoing = [
                tx for tx in parsed_transfers
                if tx["source_account"] == curr_acc
                and curr_arrival_ts <= tx["timestamp"] <= window_end
            ]
            outgoing.sort(key=lambda x: x["timestamp"])

            for tx in outgoing:
                target_acc = tx["target_account"]
                amt = tx["amount"]
                tx_ts = tx["timestamp"]

                delay_mins = max(0.0, (tx_ts - curr_arrival_ts).total_seconds() / 60.0)

                # Record edge
                edge_id = f"edge_{uuid.uuid4().hex[:12]}"
                edge = MuleCascadeEdge(
                    edge_id=edge_id,
                    source_node=curr_acc,
                    target_node=target_acc,
                    amount=amt,
                    currency=tx["currency"],
                    timestamp=tx_ts,
                    payment_rail=tx["payment_rail"],
                    transaction_id=tx["transaction_id"],
                    hop_number=curr_hop,
                    transfer_delay_minutes=delay_mins,
                )
                recorded_edges.append(edge)

                # Update current node outflow and velocity
                node_data = visited_nodes[curr_acc]
                node_data["outflow"] += amt
                if node_data["first_outflow"] is None or tx_ts < node_data["first_outflow"]:
                    node_data["first_outflow"] = tx_ts
                if node_data["last_outflow"] is None or tx_ts > node_data["last_outflow"]:
                    node_data["last_outflow"] = tx_ts

                # Target node setup
                next_hop = curr_hop + 1
                if next_hop > max_depth:
                    max_depth = next_hop

                target_tier = MuleCascadeTier(min(next_hop, int(MuleCascadeTier.TIER_3_CASHOUT_GATEWAY)))
                target_bic = tx.get("target_bic") or metadata.get(target_acc, {}).get("bank_bic", self.local_bank_bic)

                if target_acc not in visited_nodes:
                    visited_nodes[target_acc] = {
                        "tier": target_tier,
                        "bank_bic": target_bic,
                        "account_name": metadata.get(target_acc, {}).get("account_name", f"Account {target_acc}"),
                        "inflow": amt,
                        "outflow": Decimal("0.0"),
                        "first_inflow": tx_ts,
                        "last_outflow": None,
                        "first_outflow": None,
                    }
                    if next_hop <= max_hops:
                        queue.append((target_acc, next_hop, tx_ts, amt))
                else:
                    visited_nodes[target_acc]["inflow"] += amt
                    if tx_ts < visited_nodes[target_acc]["first_inflow"]:
                        visited_nodes[target_acc]["first_inflow"] = tx_ts

        # Build final node objects and directives
        final_nodes: list[MuleCascadeNode] = []
        directives: list[dict[str, Any]] = []
        total_held = Decimal("0.0")

        for acc, data in visited_nodes.items():
            inflow = data["inflow"]
            outflow = data["outflow"]
            retained = max(Decimal("0.0"), inflow - outflow)

            # Dispersion velocity: minutes between first inflow and first outflow
            velocity_mins = 0.0
            if data["first_inflow"] and data["first_outflow"]:
                velocity_mins = max(0.0, (data["first_outflow"] - data["first_inflow"]).total_seconds() / 60.0)

            ratio = float(outflow / inflow) if inflow > Decimal("0.0") else 0.0
            ratio = min(1.0, max(0.0, ratio))

            # Risk scoring: rapid velocity (<15m) + high dispersion (>80%) = very high risk
            tier_base_score = {
                MuleCascadeTier.TIER_1_DIRECT_BENEFICIARY: 0.95,
                MuleCascadeTier.TIER_2_SECONDARY_DISPERSION: 0.85,
                MuleCascadeTier.TIER_3_CASHOUT_GATEWAY: 0.75,
            }[data["tier"]]

            velocity_factor = 0.05 if velocity_mins > 0 and velocity_mins < 15.0 else 0.0
            dispersion_factor = 0.05 if ratio > 0.80 else 0.0
            node_risk = min(1.0, tier_base_score + velocity_factor + dispersion_factor)

            # Determine directive based on BIC locality and Tier
            is_internal = data["bank_bic"].upper() == self.local_bank_bic
            if is_internal:
                if data["tier"] == MuleCascadeTier.TIER_1_DIRECT_BENEFICIARY:
                    directive = CascadeHoldDirectiveType.IMMEDIATE_FREEZE
                elif data["tier"] == MuleCascadeTier.TIER_2_SECONDARY_DISPERSION:
                    directive = CascadeHoldDirectiveType.INFLOW_ONLY_RESTRICTION
                else:
                    directive = CascadeHoldDirectiveType.ESCROW_DELAY_HOLD_48H
                # Internal holds preserve the retained balance
                total_held += retained
            else:
                directive = CascadeHoldDirectiveType.INTERBANK_CAMT056_DISPATCH
                # Assume interbank recall could recover up to retained balance if acted upon within SLA
                total_held += (retained * Decimal("0.50"))

            node_obj = MuleCascadeNode(
                node_key=acc,
                tier_level=data["tier"],
                bank_bic=data["bank_bic"],
                account_name=data["account_name"],
                total_inflow=inflow,
                total_outflow=outflow,
                retained_balance_estimate=retained,
                velocity_minutes=velocity_mins,
                dispersion_ratio=ratio,
                risk_score=node_risk,
                recommended_directive=directive,
                directive_status="PENDING",
                first_inflow_time=data["first_inflow"],
                last_outflow_time=data["last_outflow"],
            )
            final_nodes.append(node_obj)

            # Directive record
            dir_id = f"dir_{uuid.uuid4().hex[:12]}"
            directives.append({
                "directive_id": dir_id,
                "node_key": acc,
                "tier_level": int(data["tier"]),
                "bank_bic": data["bank_bic"],
                "is_internal": is_internal,
                "directive_type": directive.value,
                "target_amount": str(retained if is_internal else inflow),
                "currency": currency,
                "status": "PENDING",
                "recommended_action": (
                    f"Immediately execute {directive.value} on local account {acc} (retained KES {retained})"
                    if is_internal
                    else f"Dispatch ISO 20022 camt.056.001.10 recall to external bank BIC {data['bank_bic']} for KES {inflow}"
                ),
            })

        rec_ratio = float(total_held / root_fraud_amount) if root_fraud_amount > Decimal("0.0") else 0.0

        return MuleCascadeTraceResult(
            trace_id=trace_id,
            installation_id=installation_id,
            root_account=root_account,
            root_transaction_id=root_transaction_id,
            root_fraud_amount=root_fraud_amount,
            currency=currency,
            max_depth_reached=max_depth,
            nodes=final_nodes,
            edges=recorded_edges,
            total_nodes_identified=len(final_nodes),
            total_frozen_or_held_amount=total_held,
            recovery_potential_ratio=min(1.0, rec_ratio),
            created_at=datetime.now(timezone.utc),
            directives_generated=directives,
        )

    def generate_camt056_xml(
        self,
        *,
        trace_id: str,
        original_txn_id: str,
        instructed_amount: Decimal,
        currency: str,
        counterparty_bic: str,
        mule_account: str,
        cancellation_reason_code: str = "FRAD",
    ) -> str:
        """Generates a valid ISO 20022 camt.056.001.10 FIToFIPaymentCancellationRequest message."""
        msg_id = f"CAMT056-{uuid.uuid4().hex[:12].upper()}"
        cre_dt_tm = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        root = ET.Element("Document", {
            "xmlns": "urn:iso:std:iso:20022:tech:xsd:camt.056.001.10",
            "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
        })
        cxl_req = ET.SubElement(root, "FIToFIPmtCxlReq")

        # Group Header
        grp_hdr = ET.SubElement(cxl_req, "GrpHdr")
        msg_id_elem = ET.SubElement(grp_hdr, "MsgId")
        msg_id_elem.text = msg_id
        cre_dt_elem = ET.SubElement(grp_hdr, "CreDtTm")
        cre_dt_elem.text = cre_dt_tm

        # Instructing Agent (Local Bank)
        instg_agt = ET.SubElement(grp_hdr, "InstgAgt")
        fin_instn_id = ET.SubElement(instg_agt, "FinInstnId")
        bic_elem = ET.SubElement(fin_instn_id, "BICFI")
        bic_elem.text = self.local_bank_bic

        # Instructed Agent (Counterparty / Mule Bank)
        instd_agt = ET.SubElement(grp_hdr, "InstdAgt")
        fin_instn_id_tgt = ET.SubElement(instd_agt, "FinInstnId")
        bic_elem_tgt = ET.SubElement(fin_instn_id_tgt, "BICFI")
        bic_elem_tgt.text = counterparty_bic

        # Underlying Transaction Details
        undrlyg = ET.SubElement(cxl_req, "Undrlyg")
        tx_inf = ET.SubElement(undrlyg, "TxInf")

        cxl_id = ET.SubElement(tx_inf, "CxlId")
        cxl_id.text = f"CXL-{trace_id[:8]}"

        orig_grp_inf = ET.SubElement(tx_inf, "OrgnlGrpInf")
        orig_msg_id = ET.SubElement(orig_grp_inf, "OrgnlMsgId")
        orig_msg_id.text = original_txn_id

        orig_tx_id = ET.SubElement(tx_inf, "OrgnlTxId")
        orig_tx_id.text = original_txn_id

        orig_instd_amt = ET.SubElement(tx_inf, "OrgnlInstdAmt", {"Ccy": currency})
        orig_instd_amt.text = f"{instructed_amount:.2f}"

        # Cancellation Reason: FRAD (Fraudulent Origin)
        cxl_rsn_inf = ET.SubElement(tx_inf, "CxlRsnInf")
        rsn = ET.SubElement(cxl_rsn_inf, "Rsn")
        cd = ET.SubElement(rsn, "Cd")
        cd.text = cancellation_reason_code

        addtl_inf = ET.SubElement(cxl_rsn_inf, "AddtlInf")
        addtl_inf.text = f"Mule Cascade Trace {trace_id} — Creditor Account: {mule_account}"

        return ET.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8")
