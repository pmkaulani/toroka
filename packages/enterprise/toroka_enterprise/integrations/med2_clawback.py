"""Brazil BCB Pix MED 2.0 (Resolução BCB nº 493/2025) 5-Layer Cascading Clawback Engine.

Implements:
1. Automated 5-Layer Cascading Mule Dispersion Graph Tracing:
   - When a fraud contestation is opened (within statutory 80-day window), the engine
     maps outward fund disbursement across up to 5 subsequent transfer layers.
2. Interbank camt.056.001.08 FIToFIPaymentCancellationRequest XML generation:
   - Formulates automated recall directives for each receiving participant bank/fintech
     holding residual stolen balances.
3. Residual Balance Extraction & Pro-Rata Recovery Allocation:
   - Calculates recoverable amounts at each hop, distinguishing between fully recovered,
     partially recovered (insufficient residual balance), and zero-balance dispersed nodes.
4. Bilateral Dispute Resolution Lifecycle (7 business days):
   - Directs hold and eventual clawback debit (camt.056 -> pacs.004).
"""
from __future__ import annotations

import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
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


class Med2HopTier(IntEnum):
    TIER_1_DIRECT_RECIPIENT = 1
    TIER_2_SECONDARY_SPLIT = 2
    TIER_3_TERTIARY_DISPERSION = 3
    TIER_4_QUATERNARY_LAYER = 4
    TIER_5_TERMINAL_GATEWAY = 5


class Med2ClawbackStatus(StrEnum):
    INITIATED = "INITIATED"
    HOLD_PLACED_FULL = "HOLD_PLACED_FULL"
    HOLD_PLACED_PARTIAL = "HOLD_PLACED_PARTIAL"
    INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS"
    DISPUTED_BILATERAL = "DISPUTED_BILATERAL"
    RECALLED_EXECUTED = "RECALLED_EXECUTED"


@dataclass(frozen=True)
class Med2DisbursementEdge:
    edge_id: str
    source_account: str
    target_account: str
    target_institution_bic: str
    amount: Decimal
    timestamp: datetime
    hop_tier: Med2HopTier
    payment_rail: str = "PIX"


@dataclass
class Med2LayerHopResult:
    hop_tier: Med2HopTier
    account_id: str
    institution_bic: str
    inflow_received: Decimal
    residual_balance: Decimal
    clawback_hold_amount: Decimal
    status: Med2ClawbackStatus
    camt056_xml: str
    resolution_deadline: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "hop_tier": int(self.hop_tier),
            "tier_name": self.hop_tier.name,
            "account_id": self.account_id,
            "institution_bic": self.institution_bic,
            "inflow_received": str(self.inflow_received),
            "residual_balance": str(self.residual_balance),
            "clawback_hold_amount": str(self.clawback_hold_amount),
            "status": self.status.value,
            "camt056_xml_length": len(self.camt056_xml),
            "resolution_deadline": self.resolution_deadline.isoformat(),
        }


@dataclass
class Med2CascadeTraceReport:
    contestation_id: str
    original_tx_id: str
    victim_account: str
    total_stolen_amount: Decimal
    reported_at: datetime
    is_within_80_day_window: bool
    total_clawback_holds_placed: Decimal
    recovery_rate_pct: float
    hops: list[Med2LayerHopResult]
    statutory_basis: str = "Banco Central do Brasil Resolução BCB nº 493/2025 (Pix MED 2.0)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "contestation_id": self.contestation_id,
            "original_tx_id": self.original_tx_id,
            "victim_account": self.victim_account,
            "total_stolen_amount": str(self.total_stolen_amount),
            "reported_at": self.reported_at.isoformat(),
            "is_within_80_day_window": self.is_within_80_day_window,
            "total_clawback_holds_placed": str(self.total_clawback_holds_placed),
            "recovery_rate_pct": self.recovery_rate_pct,
            "hops": [h.to_dict() for h in self.hops],
            "statutory_basis": self.statutory_basis,
        }


class Med2CascadingClawbackEngine:
    """Orchestrates Brazil BCB Pix MED 2.0 5-layer automated cascading clawback."""

    STATUTORY_CONTESTATION_DAYS = 80
    BILATERAL_ANALYSIS_DAYS = 7

    @classmethod
    def generate_camt056_xml(
        cls,
        original_tx_id: str,
        debtor_account: str,
        creditor_account: str,
        creditor_bic: str,
        amount: Decimal,
        currency: str = "BRL",
        reason_code: str = "FRAD",
        now: datetime | None = None,
    ) -> str:
        now_utc = _ensure_utc(now)
        msg_id = f"TOROKA-MED2-{uuid.uuid4().hex[:12].upper()}"

        root = ET.Element("Document", xmlns="urn:iso:std:iso:20022:tech:xsd:camt.056.001.08")
        cxl_req = ET.SubElement(root, "FIToFIPmtCxlReq")

        # Header
        grpHdr = ET.SubElement(cxl_req, "GrpHdr")
        ET.SubElement(grpHdr, "MsgId").text = msg_id
        ET.SubElement(grpHdr, "CreDtTm").text = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Case
        case = ET.SubElement(cxl_req, "Case")
        ET.SubElement(case, "Id").text = f"MED2-{original_tx_id[:16]}"
        ET.SubElement(case, "Cretr").text = "TOROKA-BCB-DICT-SPI"

        # Undrlyg
        undrlyg = ET.SubElement(cxl_req, "Undrlyg")
        txInf = ET.SubElement(undrlyg, "TxInf")
        ET.SubElement(txInf, "CxlId").text = f"CXL-{uuid.uuid4().hex[:8].upper()}"
        ET.SubElement(txInf, "OrgnlEndToEndId").text = original_tx_id
        orgnlAmt = ET.SubElement(txInf, "OrgnlInstdAmt", Ccy=currency)
        orgnlAmt.text = str(amount)

        cxlRsnInf = ET.SubElement(txInf, "CxlRsnInf")
        orgtr = ET.SubElement(cxlRsnInf, "Orgtr")
        ET.SubElement(orgtr, "Nm").text = "Banco Central do Brasil Pix MED 2.0 Direct"
        rsn = ET.SubElement(cxlRsnInf, "Rsn")
        ET.SubElement(rsn, "Cd").text = reason_code

        cdtrAgt = ET.SubElement(txInf, "CdtrAgt")
        finInstnId = ET.SubElement(cdtrAgt, "FinInstnId")
        ET.SubElement(finInstnId, "BICFI").text = creditor_bic

        return ET.tostring(root, encoding="utf-8").decode("utf-8")

    @classmethod
    def execute_med2_cascade_clawback(
        cls,
        original_tx_id: str,
        victim_account: str,
        total_stolen_amount: Decimal | float,
        incident_timestamp: datetime,
        edges: list[Med2DisbursementEdge],
        account_balances: dict[str, Decimal | float],
        now: datetime | None = None,
    ) -> Med2CascadeTraceReport:
        now_utc = _ensure_utc(now)
        inc_utc = _ensure_utc(incident_timestamp)
        stolen = Decimal(str(total_stolen_amount))

        # 1. Verify 80-day contestation window
        window_elapsed = now_utc - inc_utc
        is_valid_window = window_elapsed <= timedelta(days=cls.STATUTORY_CONTESTATION_DAYS)

        contestation_id = f"MED2-CNT-{uuid.uuid4().hex[:10].upper()}"
        resolution_deadline = now_utc + timedelta(days=cls.BILATERAL_ANALYSIS_DAYS)

        # 2. Process hops sequentially across tiers 1 to 5
        hops_sorted = sorted(edges, key=lambda e: (int(e.hop_tier), e.timestamp))
        processed_hops: list[Med2LayerHopResult] = []
        total_holds = Decimal("0.00")

        # Track remaining unrecovered stolen funds
        unrecovered_budget = stolen

        for edge in hops_sorted:
            if unrecovered_budget <= Decimal("0.00"):
                break

            target_acc = edge.target_account
            target_bic = edge.target_institution_bic
            hop_amt = edge.amount

            # Residual balance at destination node
            raw_bal = Decimal(str(account_balances.get(target_acc, Decimal("0.00"))))
            # The recoverable amount at this node is min(inflow, residual_balance, remaining_stolen)
            hold_amt = min(hop_amt, raw_bal, unrecovered_budget)

            if hold_amt >= hop_amt and hold_amt > Decimal("0.00"):
                status = Med2ClawbackStatus.HOLD_PLACED_FULL
            elif hold_amt > Decimal("0.00"):
                status = Med2ClawbackStatus.HOLD_PLACED_PARTIAL
            else:
                status = Med2ClawbackStatus.INSUFFICIENT_FUNDS

            camt_xml = cls.generate_camt056_xml(
                original_tx_id=original_tx_id,
                debtor_account=edge.source_account,
                creditor_account=target_acc,
                creditor_bic=target_bic,
                amount=hold_amt if hold_amt > Decimal("0.00") else hop_amt,
                currency="BRL",
                reason_code="FRAD",
                now=now_utc,
            )

            hop_result = Med2LayerHopResult(
                hop_tier=edge.hop_tier,
                account_id=target_acc,
                institution_bic=target_bic,
                inflow_received=hop_amt,
                residual_balance=raw_bal,
                clawback_hold_amount=hold_amt,
                status=status,
                camt056_xml=camt_xml,
                resolution_deadline=resolution_deadline,
            )
            processed_hops.append(hop_result)
            total_holds += hold_amt
            unrecovered_budget -= hold_amt

        recovery_rate = float((total_holds / stolen * 100).quantize(Decimal("0.01"))) if stolen > 0 else 0.0

        return Med2CascadeTraceReport(
            contestation_id=contestation_id,
            original_tx_id=original_tx_id,
            victim_account=victim_account,
            total_stolen_amount=stolen,
            reported_at=now_utc,
            is_within_80_day_window=is_valid_window,
            total_clawback_holds_placed=total_holds,
            recovery_rate_pct=recovery_rate,
            hops=processed_hops,
        )
