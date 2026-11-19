"""Precautionary Clearing Block (Bloqueio Cautelar) & Statutory Nighttime Limits Module.

Implements statutory holding powers and temporal clearing friction based on:
1. Brazil Banco Central do Brasil (BCB) Resolução BCB nº 493/2025 (Bloqueio Cautelar
   72-Hour Precautionary Inbound Hold for receiving institutions).
2. Brazil BCB Statutory Nighttime Transfer Limits (Limite Noturno 20:00 - 06:00).
3. South Korea Financial Supervisory Service (FSS) Delayed Transfer Service (지연이체서비스)
   with 3-Hour Settlement Delay and 30-Minute Guaranteed Recall Window.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from enum import Enum
from typing import Any
import uuid


class PrecautionaryHoldState(str, Enum):
    """Lifecycle state of an inbound or inflight precautionary block."""
    ACTIVE_HOLD_72H = "ACTIVE_HOLD_72H"
    RELEASED_CLEARED = "RELEASED_CLEARED"
    ESCALATED_CLAWBACK_CAMT056 = "ESCALATED_CLAWBACK_CAMT056"
    RECALLED_BY_SENDER = "RECALLED_BY_SENDER"


@dataclass
class PrecautionaryHoldDirective:
    """Statutory hold directive quarantining incoming or inflight funds."""
    hold_id: str
    installation_id: str
    tx_id: str
    amount: Decimal
    currency: str
    debtor_account: str
    creditor_account: str
    state: PrecautionaryHoldState
    placed_at: datetime
    expires_at: datetime
    reason: str
    statutory_basis: str = "RESOLUCAO_BCB_493_2025_ART_39"
    decision_officer_id: str | None = None
    resolution_notes: str | None = None
    camt056_xml: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        """Whether the 72-hour holding window has elapsed without escalation."""
        return datetime.now(timezone.utc) >= self.expires_at


@dataclass
class NighttimeWindowPolicy:
    """Statutory nighttime payment bounds (Brazil BCB Limite Noturno)."""
    night_start_hour: int = 20  # 20:00 (8 PM)
    night_end_hour: int = 6    # 06:00 (6 AM)
    max_nighttime_amount: Decimal = Decimal("20000.00")  # KES 20,000 (~$150 USD)

    def is_nighttime(self, check_time: datetime | None = None) -> bool:
        """Returns True if the specified or current time falls within nighttime bounds."""
        t = check_time or datetime.now(timezone.utc)
        hour = t.hour
        if self.night_start_hour > self.night_end_hour:
            return hour >= self.night_start_hour or hour < self.night_end_hour
        return self.night_start_hour <= hour < self.night_end_hour

    def evaluate_nighttime_ceiling(
        self,
        amount: Decimal,
        check_time: datetime | None = None,
    ) -> dict[str, Any]:
        """Evaluates whether an outbound transfer breaches the statutory nighttime ceiling."""
        in_night = self.is_nighttime(check_time)
        if in_night and amount > self.max_nighttime_amount:
            return {
                "is_breach": True,
                "nighttime_active": True,
                "amount": float(amount),
                "ceiling": float(self.max_nighttime_amount),
                "recommended_action": "DELAY_UNTIL_DAYLIGHT_CLEARING",
                "reason": (
                    f"Outbound transfer of {amount} exceeds statutory nighttime limit "
                    f"({self.max_nighttime_amount}) between {self.night_start_hour:02d}:00 "
                    f"and {self.night_end_hour:02d}:00 (Brazil BCB Limite Noturno Standard)."
                ),
            }
        return {
            "is_breach": False,
            "nighttime_active": in_night,
            "amount": float(amount),
            "ceiling": float(self.max_nighttime_amount),
            "recommended_action": "PROCEED",
            "reason": "WITHIN_PERMITTED_TEMPORAL_LIMITS",
        }


@dataclass
class DelayedTransferRecallPolicy:
    """South Korea FSS Delayed Transfer and Recall Window Policy."""
    delay_duration_hours: int = 3
    recall_cutoff_minutes: int = 30

    def evaluate_recall(
        self,
        initiated_at: datetime,
        recall_requested_at: datetime | None = None,
    ) -> tuple[bool, str]:
        """Evaluates if a sender can recall an inflight delayed transfer.
        
        Permitted up to 30 minutes before the scheduled clearing execution.
        """
        now = recall_requested_at or datetime.now(timezone.utc)
        scheduled_execution = initiated_at + timedelta(hours=self.delay_duration_hours)
        cutoff_time = scheduled_execution - timedelta(minutes=self.recall_cutoff_minutes)

        if now > scheduled_execution:
            return False, "Transfer has already executed and cleared into destination account."

        if now > cutoff_time:
            return (
                False,
                f"Recall rejected: within final {self.recall_cutoff_minutes}-minute clearing "
                f"commitment window (cutoff was {cutoff_time.isoformat()}).",
            )

        return (
            True,
            f"Transfer recall accepted: requested {int((cutoff_time - now).total_seconds() / 60)} "
            f"minutes before cutoff window.",
        )


class PrecautionaryHoldEngine:
    """Engine executing Bloqueio Cautelar 72-hour holds and dispute lifecycle."""

    @staticmethod
    def create_precautionary_hold(
        installation_id: str,
        tx_id: str,
        amount: Decimal,
        debtor_account: str,
        creditor_account: str,
        reason: str,
        currency: str = "KES",
        duration_hours: int = 72,
    ) -> PrecautionaryHoldDirective:
        """Place an inbound or inflight payment into 72-hour Bloqueio Cautelar hold."""
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=duration_hours)
        hold_id = f"HOLD-{uuid.uuid4().hex[:12].upper()}"

        return PrecautionaryHoldDirective(
            hold_id=hold_id,
            installation_id=installation_id,
            tx_id=tx_id,
            amount=amount,
            currency=currency,
            debtor_account=debtor_account,
            creditor_account=creditor_account,
            state=PrecautionaryHoldState.ACTIVE_HOLD_72H,
            placed_at=now,
            expires_at=expires,
            reason=reason,
            statutory_basis="RESOLUCAO_BCB_493_2025_ART_39",
        )

    @staticmethod
    def release_hold(
        directive: PrecautionaryHoldDirective,
        officer_id: str,
        notes: str,
    ) -> PrecautionaryHoldDirective:
        """Release quarantined funds into the recipient's available balance upon clearance."""
        if directive.state != PrecautionaryHoldState.ACTIVE_HOLD_72H:
            raise ValueError(f"Cannot release hold in state {directive.state}")

        directive.state = PrecautionaryHoldState.RELEASED_CLEARED
        directive.decision_officer_id = officer_id
        directive.resolution_notes = notes
        return directive

    @staticmethod
    def escalate_to_camt056_clawback(
        directive: PrecautionaryHoldDirective,
        officer_id: str,
        notes: str,
    ) -> PrecautionaryHoldDirective:
        """Confirm fraud and escalate hold to an ISO 20022 camt.056 payment cancellation."""
        if directive.state != PrecautionaryHoldState.ACTIVE_HOLD_72H:
            raise ValueError(f"Cannot escalate hold in state {directive.state}")

        directive.state = PrecautionaryHoldState.ESCALATED_CLAWBACK_CAMT056
        directive.decision_officer_id = officer_id
        directive.resolution_notes = notes

        # Generate ISO 20022 camt.056.001.10 XML
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        directive.camt056_xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.056.001.10">\n'
            f"  <FIToFIPmtCxlReq>\n"
            f"    <GrpHdr>\n"
            f"      <MsgId>CAMT056-BCB-{directive.hold_id}</MsgId>\n"
            f"      <CreDtTm>{now_iso}</CreDtTm>\n"
            f"      <NbOfTxs>1</NbOfTxs>\n"
            f"    </GrpHdr>\n"
            f"    <Undrlyg>\n"
            f"      <TxInf>\n"
            f"        <CxlId>CXL-{directive.hold_id}</CxlId>\n"
            f"        <OrgnlTxId>{directive.tx_id}</OrgnlTxId>\n"
            f"        <OrgnlIntrBkSttlmAmt Ccy=\"{directive.currency}\">{directive.amount:.2f}</OrgnlIntrBkSttlmAmt>\n"
            f"        <CxlRsnInf>\n"
            f"          <Rsn><Cd>FRAD</Cd></Rsn>\n"
            f"          <AddtlInf>BCB_BLOQUEIO_CAUTELAR_CONFIRMED_FRAUD: {notes}</AddtlInf>\n"
            f"        </CxlRsnInf>\n"
            f"      </TxInf>\n"
            f"    </Undrlyg>\n"
            f"  </FIToFIPmtCxlReq>\n"
            f"</Document>"
        )
        return directive
