"""ISO 20022 Financial Messaging Engine & Real-Time Kenya Payment Clearing.

Provides parsing, serialization, canonical event mapping, and in-flight
advisory risk evaluation for ISO 20022 financial messages:
  - pacs.008.001.10: Financial Institution Customer Credit Transfer
  - pacs.002.001.12: Payment Status Report (Fraud / Reversal / Rejection)
  - camt.053.001.10: Bank-to-Customer End-of-Day Statement
Supported Clearing Rails:
  - PESALINK (IPSL Kenya Real-Time P2P/P2B)
  - KEPSS_RTGS (Central Bank of Kenya RTGS)
  - MPESA_B2C / MPESA_B2B / MPESA_C2B (Safaricom Daraja Settlement)
  - SWIFT (Cross-Border Wire)
  - INTERNAL_BOOK (Internal Bank Transfer)
"""
from __future__ import annotations

import re
import time
import uuid
import xml.etree.ElementTree as ET

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring as _safe_fromstring
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import StrEnum
from typing import Any


class ClearingIntegrationMode(StrEnum):
    SIMULATION = "SIMULATION"
    SHADOW = "SHADOW"
    CONNECTED_READ_ONLY = "CONNECTED_READ_ONLY"
    CONTROL_ENABLED = "CONTROL_ENABLED"


SUPPORTED_PAYMENT_CURRENCIES = {"KES", "USD", "EUR", "GBP", "TZS", "UGX"}


def validate_payment_amount(amount: Decimal | float | str | int, currency: str) -> Decimal:
    """Validates payment amount and currency strictly."""
    try:
        dec = Decimal(str(amount)) if not isinstance(amount, Decimal) else amount
    except Exception as exc:
        raise ValueError(f"Invalid decimal amount: {amount}") from exc

    if dec.is_nan() or dec.is_infinite():
        raise ValueError(f"Invalid non-finite payment amount: {dec}")
    if dec <= Decimal("0.0"):
        raise ValueError(f"Payment amount must be strictly positive: {dec}")
    if currency.upper() not in SUPPORTED_PAYMENT_CURRENCIES:
        raise ValueError(f"Unsupported payment currency '{currency}'; supported: {sorted(SUPPORTED_PAYMENT_CURRENCIES)}")
    if dec.as_tuple().exponent < -4:
        raise ValueError(f"Excess precision: payment amount cannot exceed 4 decimal places ({dec})")
    return dec



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
    # Phase 14.0 Graduated Interventions (China PBOC / PayPal / UK PSR style)
    DELAY_SETTLEMENT_15M = "DELAY_SETTLEMENT_15M"
    INFLOW_ONLY = "INFLOW_ONLY"
    RESTRICT_NON_COUNTER = "RESTRICT_NON_COUNTER"


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
    amount: Decimal | float
    currency: str
    debtor: PartyIdentification
    creditor: PartyIdentification
    clearing_rail: ClearingRail
    charge_bearer: str = "SLEV"
    remittance_narrative: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if not isinstance(self.amount, Decimal):
            object.__setattr__(self, "amount", Decimal(str(self.amount)))
        validate_payment_amount(self.amount, self.currency)

    def to_dict(self) -> dict[str, Any]:
        return {
            "msg_id": self.msg_id,
            "end_to_end_id": self.end_to_end_id,
            "tx_id": self.tx_id,
            "amount": str(self.amount),
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
                "amount": float(self.amount),
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
    cop_status: str | None = None
    cop_match_score: float | None = None
    telecom_call_status: str | None = None
    telecom_coercion_score: float | None = None
    is_telecom_coerced: bool = False
    is_federated_mule: bool = False
    federated_mule_tier: str | None = None
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
            "cop_status": self.cop_status,
            "cop_match_score": round(self.cop_match_score, 4) if self.cop_match_score is not None else None,
            "telecom_call_status": self.telecom_call_status,
            "telecom_coercion_score": round(self.telecom_coercion_score, 4) if self.telecom_coercion_score is not None else None,
            "is_telecom_coerced": self.is_telecom_coerced,
            "is_federated_mule": self.is_federated_mule,
            "federated_mule_tier": self.federated_mule_tier,
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
        # Never reinterpret an invalid clearing rail as PesaLink: it changes
        # routing context and can conceal incompatible/malformed payloads.
        clearing_rail = ClearingRail(clearing_str)

        raw_amount = data.get("amount")
        if raw_amount is None:
            raise ValueError("Payment amount is required")
        amount = Decimal(str(raw_amount))
        currency = str(data.get("currency", "KES"))
        validate_payment_amount(amount, currency)

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
            amount=amount,
            currency=currency,
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
        try:
            raw_root = _safe_fromstring(xml_text)
        except (ET.ParseError, DefusedXmlException) as exc:
            raise ValueError(f"Malformed or unsafe pacs.008 XML payload: {exc}") from exc

        tag_name = raw_root.tag.split("}")[-1] if "}" in raw_root.tag else raw_root.tag
        if tag_name not in ("Document", "pacs.008.001.10", "FIToFICstmrCdtTrf"):
            raise ValueError(f"Unsupported XML root element '{raw_root.tag}': expected ISO 20022 Document")

        # Strip default XML namespace for clean XPath
        xml_clean = re.sub(r'\sxmlns="[^"]+"', "", xml_text, count=1)
        root = _safe_fromstring(xml_clean)

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
        if amt_elem is None or not amt_elem.text:
            raise ValueError("Invalid pacs.008 XML: missing IntrBkSttlmAmt element")
        amount = Decimal(str(amt_elem.text.strip()))
        currency = amt_elem.get("Ccy", "KES") if amt_elem is not None else "KES"
        validate_payment_amount(amount, currency)

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
        account_prior_transfers_count: int | None = None,
        cop_status: str | None = None,
        cop_match_score: float | None = None,
        beneficiary_inflow_restriction: bool = False,
        debtor_channel_anomaly: bool = False,
        enable_graduated_controls: bool = True,
        telecom_call_status: str | None = None,
        telecom_coercion_score: float | None = None,
        federated_mule_match: Any = None,
    ) -> InflightRiskEvaluation:
        """Evaluates an in-flight payment against instant risk rules in advisory mode."""
        t0 = time.perf_counter()
        triggered_rules: list[str] = []
        risk_score = 0.05  # Base background baseline risk

        mules = known_mule_accounts or set()

        # Rule 1: Known Mule Counterparty Match (Local Corpus & Federated Directory)
        is_federated_mule = False
        federated_mule_tier = None
        if transfer.creditor.account_number in mules:
            triggered_rules.append("RULE_MULE_ACCOUNT_MATCH: Creditor account is a corroborated mule")
            risk_score += 0.85

        if federated_mule_match:
            fed_is_match = (
                getattr(federated_mule_match, "is_match", False)
                if hasattr(federated_mule_match, "is_match")
                else (federated_mule_match.get("is_match") if isinstance(federated_mule_match, dict) else bool(federated_mule_match))
            )
            if fed_is_match:
                fed_tier = getattr(federated_mule_match, "severity_tier", None)
                tier_str = str(fed_tier.value if hasattr(fed_tier, "value") else (fed_tier or "CORROBORATED_MULE"))
                is_federated_mule = True
                federated_mule_tier = tier_str
                triggered_rules.append(f"RULE_FEDERATED_MULE_MATCH: Creditor listed on cross-bank blacklist ({tier_str})")
                if "SYNDICATE" in tier_str.upper():
                    risk_score += 0.95
                elif "CORROBORATED" in tier_str.upper():
                    risk_score += 0.85
                else:
                    risk_score += 0.50

        # Rule 2: Large Round Amount Layering
        dec_amount = Decimal(str(transfer.amount))
        is_round = dec_amount > Decimal("50000") and (dec_amount % Decimal("10000") == Decimal("0") or dec_amount % Decimal("5000") == Decimal("0"))
        if is_round and dec_amount >= Decimal("250000"):
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
        if account_prior_transfers_count is not None and account_prior_transfers_count == 0 and transfer.clearing_rail in (ClearingRail.PESALINK, ClearingRail.MPESA_B2C):
            triggered_rules.append("RULE_NEW_FAST_BENEFICIARY: First-time counterparty on instant settlement rail")
            risk_score += 0.20

        # Rule 5: Confirmation of Payee (CoP) Discrepancy (UK PSR & CBK Alignment)
        if cop_status:
            c_stat = str(cop_status).upper()
            if c_stat == "NO_MATCH":
                triggered_rules.append("RULE_COP_NO_MATCH: Creditor name does not match registered account holder (High Impersonation Risk)")
                risk_score += 0.45
            elif c_stat == "CLOSE_MATCH":
                triggered_rules.append("RULE_COP_CLOSE_MATCH: Creditor name is a close variant; advise user confirmation")
                risk_score += 0.10
            elif c_stat == "MATCH":
                risk_score = max(0.0, risk_score - 0.05)

        # Rule 6: Beneficiary Inflow Restriction Flag (PBOC Article 18 Alignment)
        if beneficiary_inflow_restriction:
            triggered_rules.append("RULE_BENEFICIARY_INFLOW_RESTRICTION: Creditor account flagged for inbound-only hold (PBOC Art. 18)")
            risk_score = max(risk_score, 0.75)

        # Rule 7: Debtor Channel Anomaly / Non-Counter Restriction Flag (PBOC Article 18 Alignment)
        if debtor_channel_anomaly:
            triggered_rules.append("RULE_NON_COUNTER_RESTRICTION: Channel anomaly / ATO indicator; non-counter restriction (PBOC Art. 18)")
            risk_score = max(risk_score, 0.70)

        # Rule 8: Telecom Live Call / Coercion Telemetry (GSMA Scam Signal & Safaricom/Airtel Open Gateway)
        is_telecom_coerced = False
        if telecom_call_status:
            t_stat = str(telecom_call_status).strip().upper()
            if t_stat == "CALL_IN_PROGRESS":
                c_score_str = f"{telecom_coercion_score:.2f}" if telecom_coercion_score is not None else "0.55"
                triggered_rules.append(f"RULE_TELECOM_ACTIVE_CALL: Debtor is currently on an active voice call (coaching indicator; score={c_score_str})")
                risk_score += 0.45
                is_telecom_coerced = True
            elif t_stat == "RECENT_CALL":
                triggered_rules.append("RULE_TELECOM_RECENT_CALL: Recent call termination within 10 minutes (potential coaching window)")
                risk_score += 0.15

        if telecom_coercion_score is not None and telecom_coercion_score >= 0.50:
            if not is_telecom_coerced:
                triggered_rules.append(f"RULE_TELECOM_COERCION_RISK: High carrier-telemetry coercion risk score ({telecom_coercion_score:.2f})")
                risk_score = max(risk_score, 0.65)
                is_telecom_coerced = True
            else:
                risk_score = max(risk_score, 0.65)

        # Cap risk score at 1.0
        risk_score = min(risk_score, 1.0)

        # Decision Matrix
        if risk_score >= 0.80:
            decision = PaymentDecision.BLOCK
            tier = RiskTier.CRITICAL
            recommended_action = "RECOMMEND_BLOCK: Advisory risk result only; Toroka sends no clearing instruction"
        elif beneficiary_inflow_restriction:
            decision = PaymentDecision.INFLOW_ONLY
            tier = RiskTier.HIGH
            recommended_action = "RECOMMEND_INFLOW_ONLY: Beneficiary account marked for outbound hold; capture incoming deposit while blocking outbound cashout or mule dispersal."
        elif debtor_channel_anomaly:
            decision = PaymentDecision.RESTRICT_NON_COUNTER
            tier = RiskTier.HIGH
            recommended_action = "RECOMMEND_RESTRICT_NON_COUNTER: Advisory suspension of mobile/USSD channels; require physical branch verification with national biometric ID."
        elif enable_graduated_controls and 0.50 <= risk_score < 0.80 and transfer.clearing_rail in (ClearingRail.PESALINK, ClearingRail.MPESA_B2C, ClearingRail.MPESA_B2B):
            decision = PaymentDecision.DELAY_SETTLEMENT_15M
            tier = RiskTier.HIGH
            recommended_action = "RECOMMEND_DELAY_SETTLEMENT_15M: Advisory 15-minute escrow hold on instant settlement to provide an active victim revocation window."
        elif risk_score >= 0.50:
            decision = PaymentDecision.QUARANTINE_HOLD
            tier = RiskTier.HIGH
            recommended_action = "RECOMMEND_MANUAL_REVIEW: Advisory only; the bank's authorised control owner decides"
        elif risk_score >= 0.30:
            decision = PaymentDecision.STEP_UP_AUTH
            tier = RiskTier.MEDIUM
            recommended_action = "RECOMMEND_STEP_UP_AUTH: Advisory only; Toroka issues no authentication challenge"
        else:
            decision = PaymentDecision.ALLOW
            tier = RiskTier.LOW
            recommended_action = "NO_RULE_TRIGGERED: Advisory only; Toroka does not release or clear the payment"

        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        return InflightRiskEvaluation(
            end_to_end_id=transfer.end_to_end_id,
            decision=decision,
            risk_score=risk_score,
            risk_tier=tier,
            triggered_rules=tuple(triggered_rules),
            recommended_action=recommended_action,
            latency_ms=elapsed_ms,
            cop_status=cop_status,
            cop_match_score=cop_match_score,
            telecom_call_status=telecom_call_status,
            telecom_coercion_score=telecom_coercion_score,
            is_telecom_coerced=is_telecom_coerced,
            is_federated_mule=is_federated_mule,
            federated_mule_tier=federated_mule_tier,
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
