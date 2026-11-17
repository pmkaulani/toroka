"""ISO 20022 Financial Messaging Engine & Real-Time Kenya Payment Clearing.

Provides parsing, serialization, canonical event mapping, and sub-100ms in-flight
risk evaluation for ISO 20022 financial messages:
  - pacs.008.001.10: Financial Institution Customer Credit Transfer
  - pacs.002.001.12: Payment Status Report (Fraud / Reversal / Rejection)
  - camt.053.001.10: Bank-to-Customer End-of-Day Statement
Supported Clearing Rails:
  - PESALINK (IPSL Kenya Real-Time P2P/P2B)
  - KEPSS (Central Bank of Kenya RTGS)
  - MPESA_B2C / MPESA_B2B / MPESA_C2B (Safaricom Daraja Settlement)
  - SWIFT (Cross-Border Wire)
"""
from __future__ import annotations

import re
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class ClearingRail(StrEnum):
    PESALINK = "PESALINK"
    KEPSS_RTGS = "KEPSS_RTGS"
    MPESA_B2C = "MPESA_B2C"
    MPESA_B2B = "MPESA_B2B"
    MPESA_C2B = "MPESA_C2B"
    SWIFT = "SWIFT"
    INTERNAL_BOOK = "INTERNAL_BOOK"


class PaymentDecision(StrEnum):
    ALLOW = "ALLOW"
    STEP_UP_AUTH = "STEP_UP_AUTH"
    QUARANTINE_HOLD = "QUARANTINE_HOLD"
    BLOCK = "BLOCK"


class RiskTier(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class PartyIdentification:
    name: str
    account_number: str
    agent_bic: str
    national_id: str | None = None
    msisdn: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "account_number": self.account_number,
            "agent_bic": self.agent_bic,
            "national_id": self.national_id,
            "msisdn": self.msisdn,
        }


@dataclass(frozen=True)
class Pacs008CreditTransfer:
    """ISO 20022 pacs.008.001.10 Customer Credit Transfer."""
    msg_id: str
    end_to_end_id: str
    tx_id: str
    amount: float
    currency: str
    debtor: PartyIdentification
    creditor: PartyIdentification
    clearing_rail: ClearingRail
    charge_bearer: str = "SLEV"
    remittance_narrative: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "msg_id": self.msg_id,
            "end_to_end_id": self.end_to_end_id,
            "tx_id": self.tx_id,
            "amount": self.amount,
            "currency": self.currency,
            "debtor": self.debtor.to_dict(),
            "creditor": self.creditor.to_dict(),
            "clearing_rail": self.clearing_rail.value,
            "charge_bearer": self.charge_bearer,
            "remittance_narrative": self.remittance_narrative,
            "created_at": self.created_at.isoformat(),
        }

    def to_canonical_event(self, installation_id: str) -> dict[str, Any]:
        """Maps ISO 20022 pacs.008 transfer into a Toroka canonical intelligence event."""
        return {
            "event_id": f"ev:pacs008:{self.end_to_end_id}",
            "installation_id": installation_id,
            "event_type": "core_banking_transfer",
            "source_system": f"ISO20022_{self.clearing_rail.value}",
            "source_record_id": self.tx_id,
            "occurred_at": self.created_at.isoformat(),
            "payload": {
                "msg_id": self.msg_id,
                "end_to_end_id": self.end_to_end_id,
                "amount": self.amount,
                "currency": self.currency,
                "clearing_rail": self.clearing_rail.value,
                "debtor_name": self.debtor.name,
                "debtor_account": self.debtor.account_number,
                "debtor_bic": self.debtor.agent_bic,
                "debtor_msisdn": self.debtor.msisdn,
                "debtor_national_id": self.debtor.national_id,
                "creditor_name": self.creditor.name,
                "creditor_account": self.creditor.account_number,
                "creditor_bic": self.creditor.agent_bic,
                "creditor_msisdn": self.creditor.msisdn,
                "creditor_national_id": self.creditor.national_id,
                "remittance_narrative": self.remittance_narrative,
            },
        }


@dataclass(frozen=True)
class Pacs002PaymentStatusReport:
    """ISO 20022 pacs.002.001.12 Payment Status Report."""
    msg_id: str
    original_msg_id: str
    original_end_to_end_id: str
    tx_status: str  # ACCP, RJCT, PDNG
    reason_code: str | None = None  # e.g. FRAD, AC04, AM04
    additional_info: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "msg_id": self.msg_id,
            "original_msg_id": self.original_msg_id,
            "original_end_to_end_id": self.original_end_to_end_id,
            "tx_status": self.tx_status,
            "reason_code": self.reason_code,
            "additional_info": self.additional_info,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class InflightRiskEvaluation:
    """Sub-100ms real-time advisory evaluation before clearing execution."""
    end_to_end_id: str
    decision: PaymentDecision
    risk_score: float
    risk_tier: RiskTier
    triggered_rules: tuple[str, ...]
    recommended_action: str
    latency_ms: float
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "end_to_end_id": self.end_to_end_id,
            "decision": self.decision.value,
            "risk_score": round(self.risk_score, 4),
            "risk_tier": self.risk_tier.value,
            "triggered_rules": list(self.triggered_rules),
            "recommended_action": self.recommended_action,
            "latency_ms": round(self.latency_ms, 3),
            "evaluated_at": self.evaluated_at.isoformat(),
        }


class ISO20022Engine:
    """Parser, serializer, and in-flight risk decision engine for ISO 20022 messages."""

    # High-risk remittance keywords indicative of social engineering or mule laundering
    SUSPICIOUS_NARRATIVE_PATTERNS = [
        re.compile(r"\b(crypto|bitcoin|usdt|binance)\b", re.IGNORECASE),
        re.compile(r"\b(activation|unlock|clearance)\s+fee\b", re.IGNORECASE),
        re.compile(r"\b(agent\s+float|commission|reversal)\b", re.IGNORECASE),
        re.compile(r"\b(mpesa\s+pin|otp|authorization\s+code)\b", re.IGNORECASE),
        re.compile(r"\b(urgent\s+release|tender\s+deposit)\b", re.IGNORECASE),
    ]

    @classmethod
    def parse_pacs008_dict(cls, data: dict[str, Any]) -> Pacs008CreditTransfer:
        """Parses a pacs.008 transfer from JSON/dictionary."""
        debtor_d = data.get("debtor", {})
        creditor_d = data.get("creditor", {})

        clearing_str = data.get("clearing_rail", ClearingRail.PESALINK.value)
        clearing_rail = (
            ClearingRail(clearing_str)
            if clearing_str in ClearingRail.__members__.values()
            else ClearingRail.PESALINK
        )

        debtor = PartyIdentification(
            name=str(debtor_d.get("name", "Unknown Debtor")),
            account_number=str(debtor_d.get("account_number", "")),
            agent_bic=str(debtor_d.get("agent_bic", "")),
            national_id=debtor_d.get("national_id"),
            msisdn=debtor_d.get("msisdn"),
        )
        creditor = PartyIdentification(
            name=str(creditor_d.get("name", "Unknown Creditor")),
            account_number=str(creditor_d.get("account_number", "")),
            agent_bic=str(creditor_d.get("agent_bic", "")),
            national_id=creditor_d.get("national_id"),
            msisdn=creditor_d.get("msisdn"),
        )

        created_str = data.get("created_at")
        created_at = (
            datetime.fromisoformat(created_str)
            if created_str
            else datetime.now(timezone.utc)
        )

        return Pacs008CreditTransfer(
            msg_id=str(data.get("msg_id", f"MSG-{uuid.uuid4().hex[:12]}")),
            end_to_end_id=str(data.get("end_to_end_id", f"E2E-{uuid.uuid4().hex[:12]}")),
            tx_id=str(data.get("tx_id", f"TX-{uuid.uuid4().hex[:12]}")),
            amount=float(data.get("amount", 0.0)),
            currency=str(data.get("currency", "KES")),
            debtor=debtor,
            creditor=creditor,
            clearing_rail=clearing_rail,
            charge_bearer=str(data.get("charge_bearer", "SLEV")),
            remittance_narrative=str(data.get("remittance_narrative", "")),
            created_at=created_at,
        )

    @classmethod
    def parse_pacs008_xml(cls, xml_text: str) -> Pacs008CreditTransfer:
        """Parses standard ISO 20022 pacs.008 XML format."""
        # Strip default XML namespace for clean XPath
        xml_clean = re.sub(r'\sxmlns="[^"]+"', "", xml_text, count=1)
        root = ET.fromstring(xml_clean)

        msg_id_elem = root.find(".//GrpHdr/MsgId")
        msg_id = msg_id_elem.text if msg_id_elem is not None and msg_id_elem.text else f"MSG-{uuid.uuid4().hex[:12]}"

        tx_info = root.find(".//CdtTrfTxInf")
        if tx_info is None:
            raise ValueError("Invalid pacs.008 XML: missing CdtTrfTxInf element")

        e2e_elem = tx_info.find(".//PmtId/EndToEndId")
        end_to_end_id = e2e_elem.text if e2e_elem is not None and e2e_elem.text else f"E2E-{uuid.uuid4().hex[:12]}"

        tx_elem = tx_info.find(".//PmtId/TxId")
        tx_id = tx_elem.text if tx_elem is not None and tx_elem.text else end_to_end_id

        amt_elem = tx_info.find(".//IntrBkSttlmAmt")
        amount = float(amt_elem.text) if amt_elem is not None and amt_elem.text else 0.0
        currency = amt_elem.get("Ccy", "KES") if amt_elem is not None else "KES"

        # Debtor
        dbtr_name = tx_info.findtext(".//Dbtr/Nm") or "Unknown Debtor"
        dbtr_acct = tx_info.findtext(".//DbtrAcct/Id/Othr/Id") or tx_info.findtext(".//DbtrAcct/Id/IBAN") or ""
        dbtr_bic = tx_info.findtext(".//DbtrAgt/FinInstnId/BICFI") or ""
        dbtr_msisdn = tx_info.findtext(".//Dbtr/CtctDtls/MobNb")
        dbtr_nat_id = tx_info.findtext(".//Dbtr/Id/OrgId/Othr/Id") or tx_info.findtext(".//Dbtr/Id/PrvtId/Othr/Id")

        # Creditor
        cdtr_name = tx_info.findtext(".//Cdtr/Nm") or "Unknown Creditor"
        cdtr_acct = tx_info.findtext(".//CdtrAcct/Id/Othr/Id") or tx_info.findtext(".//CdtrAcct/Id/IBAN") or ""
        cdtr_bic = tx_info.findtext(".//CdtrAgt/FinInstnId/BICFI") or ""
        cdtr_msisdn = tx_info.findtext(".//Cdtr/CtctDtls/MobNb")
        cdtr_nat_id = tx_info.findtext(".//Cdtr/Id/OrgId/Othr/Id") or tx_info.findtext(".//Cdtr/Id/PrvtId/Othr/Id")

        # Narrative
        narrative = tx_info.findtext(".//RmtInf/Ustrd") or ""

        # Rail inference from clearing system proprietary code
        clr_sys = tx_info.findtext(".//ClrSysPrtry") or ""
        if "PESALINK" in clr_sys.upper():
            rail = ClearingRail.PESALINK
        elif "KEPSS" in clr_sys.upper() or "RTGS" in clr_sys.upper():
            rail = ClearingRail.KEPSS_RTGS
        elif "MPESA" in clr_sys.upper():
            rail = ClearingRail.MPESA_B2C
        else:
            rail = ClearingRail.PESALINK

        debtor = PartyIdentification(
            name=dbtr_name,
            account_number=dbtr_acct,
            agent_bic=dbtr_bic,
            national_id=dbtr_nat_id,
            msisdn=dbtr_msisdn,
        )
        creditor = PartyIdentification(
            name=cdtr_name,
            account_number=cdtr_acct,
            agent_bic=cdtr_bic,
            national_id=cdtr_nat_id,
            msisdn=cdtr_msisdn,
        )

        return Pacs008CreditTransfer(
            msg_id=msg_id,
            end_to_end_id=end_to_end_id,
            tx_id=tx_id,
            amount=amount,
            currency=currency,
            debtor=debtor,
            creditor=creditor,
            clearing_rail=rail,
            remittance_narrative=narrative,
        )

    @classmethod
    def evaluate_inflight_payment(
        cls,
        transfer: Pacs008CreditTransfer,
        known_mule_accounts: set[str] | None = None,
        account_prior_transfers_count: int = 10,
    ) -> InflightRiskEvaluation:
        """Evaluates an in-flight payment against instant risk rules in <100ms."""
        t0 = time.perf_counter()
        triggered_rules: list[str] = []
        risk_score = 0.05  # Base background baseline risk

        mules = known_mule_accounts or set()

        # Rule 1: Known Mule Counterparty Match
        if transfer.creditor.account_number in mules:
            triggered_rules.append("RULE_MULE_ACCOUNT_MATCH: Creditor account is a corroborated mule")
            risk_score += 0.85

        # Rule 2: Large Round Amount Layering
        is_round = transfer.amount > 50_000 and (transfer.amount % 10_000 == 0 or transfer.amount % 5_000 == 0)
        if is_round and transfer.amount >= 250_000:
            triggered_rules.append("RULE_LARGE_ROUND_SUM: High-value round-denomination transfer")
            risk_score += 0.25

        # Rule 3: High-Risk Remittance Narrative
        narrative = transfer.remittance_narrative
        for pat in cls.SUSPICIOUS_NARRATIVE_PATTERNS:
            if pat.search(narrative):
                triggered_rules.append(f"RULE_SUSPICIOUS_NARRATIVE: Matched '{pat.pattern}' in transfer narrative")
                risk_score += 0.35
                break

        # Rule 4: New Uncorroborated First-Time Beneficiary on Fast Rail
        if account_prior_transfers_count == 0 and transfer.clearing_rail in (ClearingRail.PESALINK, ClearingRail.MPESA_B2C):
            triggered_rules.append("RULE_NEW_FAST_BENEFICIARY: First-time counterparty on instant settlement rail")
            risk_score += 0.20

        # Cap risk score at 1.0
        risk_score = min(risk_score, 1.0)

        # Decision Matrix
        if risk_score >= 0.80:
            decision = PaymentDecision.BLOCK
            tier = RiskTier.CRITICAL
            recommended_action = "IMMEDIATE_BLOCK: Terminate clearing, notify AML officer, return pacs.002 with reason FRAD"
        elif risk_score >= 0.50:
            decision = PaymentDecision.QUARANTINE_HOLD
            tier = RiskTier.HIGH
            recommended_action = "QUARANTINE_30M: Suspend clearing settlement for 30 minutes to enable automated fraud triage"
        elif risk_score >= 0.30:
            decision = PaymentDecision.STEP_UP_AUTH
            tier = RiskTier.MEDIUM
            recommended_action = "STEP_UP_AUTH: Prompt sender for hardware token / biometric confirmation before clearing"
        else:
            decision = PaymentDecision.ALLOW
            tier = RiskTier.LOW
            recommended_action = "ALLOW: Release to clearing rail immediately"

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return InflightRiskEvaluation(
            end_to_end_id=transfer.end_to_end_id,
            decision=decision,
            risk_score=risk_score,
            risk_tier=tier,
            triggered_rules=tuple(triggered_rules),
            recommended_action=recommended_action,
            latency_ms=elapsed_ms,
        )

    @classmethod
    def generate_pacs002_reversal(
        cls,
        transfer: Pacs008CreditTransfer,
        reason_code: str = "FRAD",
        additional_info: str = "Suspected fraudulent unauthorized transaction",
    ) -> Pacs002PaymentStatusReport:
        """Generates an ISO 20022 pacs.002 rejection/reversal message."""
        return Pacs002PaymentStatusReport(
            msg_id=f"STS-{uuid.uuid4().hex[:12]}",
            original_msg_id=transfer.msg_id,
            original_end_to_end_id=transfer.end_to_end_id,
            tx_status="RJCT",
            reason_code=reason_code,
            additional_info=additional_info,
        )
