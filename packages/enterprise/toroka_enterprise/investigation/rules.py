"""Explainable investigation rule engine for Toroka Enterprise.

Generates evidence-backed leads and hypotheses for human investigator review.
Does not generate criminal accusations, guilt determinations, or automated sanctions.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

from toroka_enterprise.investigation.contracts import EvidenceState, FindingIn


@dataclass(frozen=True)
class InstitutionPolicyProfile:
    """Configurable, versioned threshold profile approved by the institution."""
    profile_version: str = "institution-policy-2026-v1"
    fan_out_window: timedelta = timedelta(hours=2)
    fan_out_min_destinations: int = 3
    fan_out_min_total_amount: Decimal = Decimal("100000.00")
    fan_in_window: timedelta = timedelta(hours=2)
    fan_in_min_sources: int = 3
    fan_in_min_total_amount: Decimal = Decimal("100000.00")
    refund_ratio_anomaly_threshold: Decimal = Decimal("0.35")
    bec_instruction_window: timedelta = timedelta(days=3)
    insider_privileged_window: timedelta = timedelta(hours=24)


class InvestigationRuleEngine:
    """Evaluates case evidence and transaction events to surface explainable leads."""

    def __init__(self, policy: InstitutionPolicyProfile | None = None) -> None:
        self.policy = policy or InstitutionPolicyProfile()

    def evaluate_case(
        self,
        *,
        transactions: list[Any],
        relationships: list[Any],
        evidence_items: list[Any],
    ) -> list[FindingIn]:
        findings: list[FindingIn] = []

        findings.extend(self._evaluate_fan_out(transactions))
        findings.extend(self._evaluate_fan_in(transactions))
        findings.extend(self._evaluate_reused_infrastructure(relationships))
        findings.extend(self._evaluate_refund_anomalies(transactions))
        findings.extend(self._evaluate_bec_indicators(relationships, transactions, evidence_items))
        findings.extend(self._evaluate_insider_actions(evidence_items, transactions))

        return findings

    def _evaluate_fan_out(self, transactions: list[Any]) -> list[FindingIn]:
        """Detects rapid dispersion of funds from one source to multiple distinct destinations."""
        by_source: dict[UUID, list[Any]] = defaultdict(list)
        for tx in transactions:
            if getattr(tx, "event_type", "transfer").lower() in ("transfer", "payout"):
                by_source[getattr(tx, "source_entity_id")].append(tx)

        findings: list[FindingIn] = []
        for src_id, rows in by_source.items():
            rows.sort(key=lambda r: getattr(r, "occurred_at"))
            for i, first in enumerate(rows):
                w_start = getattr(first, "occurred_at")
                w_end = w_start + self.policy.fan_out_window
                window_txs = [
                    r for r in rows[i:]
                    if w_start <= getattr(r, "occurred_at") <= w_end
                    and getattr(r, "currency") == getattr(first, "currency")
                ]
                distinct_destinations = {getattr(r, "destination_entity_id") for r in window_txs}
                total_amt = sum((Decimal(str(getattr(r, "amount"))) for r in window_txs), Decimal("0"))

                if (
                    len(distinct_destinations) >= self.policy.fan_out_min_destinations
                    and total_amt >= self.policy.fan_out_min_total_amount
                ):
                    ev_ids = [getattr(r, "evidence_id") for r in window_txs if getattr(r, "evidence_id", None)]
                    findings.append(
                        FindingIn(
                            rule_id="transaction.rapid_fan_out",
                            rule_version=self.policy.profile_version,
                            title=f"Rapid fund dispersion: {len(distinct_destinations)} distinct destinations",
                            explanation=(
                                f"Observed outward transfers of {total_amt} {getattr(first, 'currency')} "
                                f"to {len(distinct_destinations)} distinct accounts within "
                                f"{int(self.policy.fan_out_window.total_seconds() / 60)} minutes. "
                                "This velocity indicator warrants human review but does NOT prove "
                                "money laundering, mule recruitment, or syndicate control."
                            ),
                            state=EvidenceState.HYPOTHESIS,
                            evidence_ids=list(dict.fromkeys(ev_ids)) or [getattr(first, "evidence_id")],
                            counter_evidence_ids=[],
                            unresolved_questions=[
                                "Were these recipients registered beneficiaries prior to this window?",
                                "Was an institutional payroll or vendor batch schedule operating at this time?",
                            ],
                            recommended_human_action=(
                                "Review counterparty relationship history and confirm customer authorization."
                            ),
                        )
                    )
                    break  # One lead per source entity per session
        return findings

    def _evaluate_fan_in(self, transactions: list[Any]) -> list[FindingIn]:
        """Detects rapid pooling of funds from multiple distinct sources into one recipient."""
        by_dest: dict[UUID, list[Any]] = defaultdict(list)
        for tx in transactions:
            if getattr(tx, "event_type", "transfer").lower() in ("transfer", "deposit"):
                by_dest[getattr(tx, "destination_entity_id")].append(tx)

        findings: list[FindingIn] = []
        for dst_id, rows in by_dest.items():
            rows.sort(key=lambda r: getattr(r, "occurred_at"))
            for i, first in enumerate(rows):
                w_start = getattr(first, "occurred_at")
                w_end = w_start + self.policy.fan_in_window
                window_txs = [
                    r for r in rows[i:]
                    if w_start <= getattr(r, "occurred_at") <= w_end
                    and getattr(r, "currency") == getattr(first, "currency")
                ]
                distinct_sources = {getattr(r, "source_entity_id") for r in window_txs}
                total_amt = sum((Decimal(str(getattr(r, "amount"))) for r in window_txs), Decimal("0"))

                if (
                    len(distinct_sources) >= self.policy.fan_in_min_sources
                    and total_amt >= self.policy.fan_in_min_total_amount
                ):
                    ev_ids = [getattr(r, "evidence_id") for r in window_txs if getattr(r, "evidence_id", None)]
                    findings.append(
                        FindingIn(
                            rule_id="transaction.rapid_fan_in",
                            rule_version=self.policy.profile_version,
                            title=f"Rapid fund concentration: {len(distinct_sources)} distinct sources",
                            explanation=(
                                f"Observed inward transfers of {total_amt} {getattr(first, 'currency')} "
                                f"from {len(distinct_sources)} distinct sources within "
                                f"{int(self.policy.fan_in_window.total_seconds() / 60)} minutes. "
                                "This pooling pattern warrants investigation but does NOT determine "
                                "illegal collection or fraudulent fundraising."
                            ),
                            state=EvidenceState.HYPOTHESIS,
                            evidence_ids=list(dict.fromkeys(ev_ids)) or [getattr(first, "evidence_id")],
                            counter_evidence_ids=[],
                            unresolved_questions=[
                                "Does the account hold an approved merchant, fundraising, or aggregator profile?",
                                "Are the source senders reporting transaction disputes or unauthorized debits?",
                            ],
                            recommended_human_action=(
                                "Verify source funds legitimacy with originator institutions."
                            ),
                        )
                    )
                    break
        return findings

    def _evaluate_reused_infrastructure(self, relationships: list[Any]) -> list[FindingIn]:
        """Identifies entities sharing an infrastructure indicator (device, phone, IP)."""
        findings: list[FindingIn] = []
        for rel in relationships:
            rel_type = getattr(rel, "relationship_type", "").lower()
            if rel_type in ("shares_device", "shares_phone", "shares_ip", "shares_email"):
                ev_ids = getattr(rel, "evidence_ids", [])
                if not ev_ids:
                    continue
                findings.append(
                    FindingIn(
                        rule_id="identity.reused_infrastructure",
                        rule_version=self.policy.profile_version,
                        title=f"Shared infrastructure indicator: {rel_type.replace('_', ' ')}",
                        explanation=(
                            f"Entities are linked via common {rel_type.replace('shares_', '')}. "
                            "A shared device, phone, or IP indicator is an investigative lead, NOT "
                            "proof of common identity, conspiracy, or coordinated syndicate fraud."
                        ),
                        state=EvidenceState.HYPOTHESIS,
                        evidence_ids=ev_ids,
                        counter_evidence_ids=[],
                        unresolved_questions=[
                            "Is this indicator a shared family, cybercafe, institutional proxy, or NAT gateway?",
                            "Did the entities perform activities at overlapping or divergent timestamps?",
                        ],
                        recommended_human_action=(
                            "Examine network carrier metadata and avoid auto-merging entity profiles."
                        ),
                    )
                )
        return findings

    def _evaluate_refund_anomalies(self, transactions: list[Any]) -> list[FindingIn]:
        """Detects abnormal ratios of refunds/reversals compared to gross settlement volume."""
        by_merchant: dict[UUID, list[Any]] = defaultdict(list)
        for tx in transactions:
            by_merchant[getattr(tx, "source_entity_id")].append(tx)

        findings: list[FindingIn] = []
        for merch_id, rows in by_merchant.items():
            gross_volume = Decimal("0")
            refund_volume = Decimal("0")
            ev_ids = []

            for r in rows:
                amt = Decimal(str(getattr(r, "amount")))
                etype = getattr(r, "event_type", "transfer").lower()
                if etype in ("refund", "reversal"):
                    refund_volume += amt
                    if getattr(r, "evidence_id", None):
                        ev_ids.append(getattr(r, "evidence_id"))
                else:
                    gross_volume += amt

            if gross_volume > Decimal("50000.00") and (refund_volume / gross_volume) >= self.policy.refund_ratio_anomaly_threshold:
                ratio_pct = int((refund_volume / gross_volume) * Decimal("100"))
                findings.append(
                    FindingIn(
                        rule_id="merchant.abnormal_refund_activity",
                        rule_version=self.policy.profile_version,
                        title=f"Unusual refund volume: {ratio_pct}% of gross turnover",
                        explanation=(
                            f"Refund volume ({refund_volume}) represents {ratio_pct}% of gross transactions "
                            f"({gross_volume}), exceeding the {int(self.policy.refund_ratio_anomaly_threshold * 100)}% threshold. "
                            "This pattern warrants commercial review but does NOT prove synthetic billing or laundering."
                        ),
                        state=EvidenceState.HYPOTHESIS,
                        evidence_ids=list(dict.fromkeys(ev_ids)) or [getattr(rows[0], "evidence_id")],
                        counter_evidence_ids=[],
                        unresolved_questions=[
                            "Did a vendor supply chain cancellation or service outage cause bulk customer refunds?",
                            "Are the refunds returning to original payment instruments or alternate accounts?",
                        ],
                        recommended_human_action=(
                            "Request merchant reconciliation ledgers and order cancellation documentation."
                        ),
                    )
                )
        return findings

    def _evaluate_bec_indicators(
        self,
        relationships: list[Any],
        transactions: list[Any],
        evidence_items: list[Any],
    ) -> list[FindingIn]:
        """Identifies rapid payment after vendor instruction / banking detail updates."""
        findings: list[FindingIn] = []
        for rel in relationships:
            rel_type = getattr(rel, "relationship_type", "").lower()
            if rel_type in ("vendor_bank_change", "payment_instruction_updated"):
                ev_ids = getattr(rel, "evidence_ids", [])
                if not ev_ids:
                    continue
                findings.append(
                    FindingIn(
                        rule_id="bec.vendor_instruction_change",
                        rule_version=self.policy.profile_version,
                        title="Vendor payment instruction change prior to transaction",
                        explanation=(
                            "Vendor payment instructions were modified recently prior to fund execution. "
                            "BEC syndicates frequently impersonate vendors to redirect invoice payouts. "
                            "This finding highlights the timing proximity; it does NOT accuse vendor personnel."
                        ),
                        state=EvidenceState.HYPOTHESIS,
                        evidence_ids=ev_ids,
                        counter_evidence_ids=[],
                        unresolved_questions=[
                            "Was out-of-band secondary verification (voice/verified number) completed with vendor CFO?",
                            "Did the request originate from the vendor's genuine domain or a lookalike typo-squat?",
                        ],
                        recommended_human_action=(
                            "Place outbound transfer on administrative review and execute secondary vendor callback."
                        ),
                    )
                )
        return findings

    def _evaluate_insider_actions(
        self,
        evidence_items: list[Any],
        transactions: list[Any],
    ) -> list[FindingIn]:
        """Correlates privileged system overrides occurring immediately adjacent to high-value transfers."""
        findings: list[FindingIn] = []
        override_evs = [
            e for e in evidence_items
            if getattr(e, "source_type", None) == "authenticated_system_log"
            and "override" in getattr(e, "source_record_ref", "").lower()
        ]
        if override_evs and transactions:
            ev_ids = [getattr(e, "id") for e in override_evs if getattr(e, "id", None)]
            findings.append(
                FindingIn(
                    rule_id="audit.privileged_change_near_payment",
                    rule_version=self.policy.profile_version,
                    title="Privileged administrative override logged near payment execution",
                    explanation=(
                        "An administrative access override or profile change was executed in temporal proximity "
                        "to a significant payment event. This telemetry warrant internal audit verification; "
                        "it does NOT imply employee misconduct, criminal collusion, or intentional harm."
                    ),
                    state=EvidenceState.HYPOTHESIS,
                    evidence_ids=ev_ids or [getattr(transactions[0], "evidence_id")],
                    counter_evidence_ids=[],
                    unresolved_questions=[
                        "Was the change ticket referenced in institutional ITSM change management?",
                        "Did two distinct authorized managers sign off on the parameter change?",
                    ],
                    recommended_human_action=(
                        "Request dual-control IT audit ticket verification and review supervisor approval logs."
                    ),
                )
            )
        return findings
