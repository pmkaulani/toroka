from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any


def _ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class TransferObservation:
    installation_id: str
    event_id: str
    source_account: str
    target_account: str
    amount: Decimal
    currency: str
    event_time: datetime
    available_at: datetime
    source_system: str = "payment_switch"
    transaction_id: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.installation_id or not self.installation_id.strip():
            raise ValueError("installation_id is required")
        if not self.source_account or not self.source_account.strip():
            raise ValueError("source_account is required")
        if not self.target_account or not self.target_account.strip():
            raise ValueError("target_account is required")
        if self.amount < 0:
            raise ValueError("amount cannot be negative")
        if not self.currency or not self.currency.strip():
            raise ValueError("currency is required")


@dataclass(frozen=True)
class NetworkPatternFinding:
    pattern_id: str
    installation_id: str
    pattern_type: str
    anchor_entity: str
    related_entities: tuple[str, ...]
    event_ids: tuple[str, ...]
    start_time: datetime
    end_time: datetime
    detection_time: datetime
    explanation: str
    evidence_limitations: tuple[str, ...]
    alternative_legitimate_explanations: tuple[str, ...]
    supporting_source_systems: tuple[str, ...] = ()
    transaction_ids: tuple[str, ...] = ()
    monetary_total: Decimal | None = None
    currency: str | None = None
    confidence: float = 1.0
    pattern_version: str = "v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "installation_id": self.installation_id,
            "pattern_type": self.pattern_type,
            "anchor_entity": self.anchor_entity,
            "related_entities": list(self.related_entities),
            "event_ids": list(self.event_ids),
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat(),
            "detection_time": self.detection_time.isoformat(),
            "explanation": self.explanation,
            "evidence_limitations": list(self.evidence_limitations),
            "alternative_legitimate_explanations": list(self.alternative_legitimate_explanations),
            "supporting_source_systems": list(self.supporting_source_systems),
            "transaction_ids": list(self.transaction_ids),
            "monetary_total": str(self.monetary_total) if self.monetary_total is not None else None,
            "currency": self.currency,
            "confidence": self.confidence,
            "pattern_version": self.pattern_version,
        }


def _pattern_digest(installation_id: str, pattern_type: str, anchor: str, event_ids: tuple[str, ...]) -> str:
    seed = f"{installation_id}:{pattern_type}:{anchor}:{','.join(sorted(event_ids))}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:24]


def detect_fan_patterns(
    transfers: list[TransferObservation],
    *,
    min_sources: int = 3,
    min_targets: int = 3,
    window: timedelta = timedelta(hours=24),
    as_of: datetime | None = None,
    max_findings: int = 100,
) -> list[NetworkPatternFinding]:
    """Detect fan-in and fan-out transfer clusters within a temporal window."""
    # Filter observations available at as_of
    valid_transfers = [
        t for t in transfers
        if as_of is None or _ensure_utc(t.available_at) <= _ensure_utc(as_of)
    ]
    # Sort chronologically by event_time
    valid_transfers.sort(key=lambda t: t.event_time)

    now = datetime.now(timezone.utc)
    findings: list[NetworkPatternFinding] = []

    # 1. FAN-IN: multiple distinct sources -> single target account
    target_buckets: dict[tuple[str, str, str], list[TransferObservation]] = defaultdict(list)
    for t in valid_transfers:
        target_buckets[(t.installation_id, t.target_account, t.currency)].append(t)

    for (inst_id, target_acc, curr), tx_list in target_buckets.items():
        if len(findings) >= max_findings:
            break
        for i in range(len(tx_list)):
            start_t = tx_list[i].event_time
            end_t = start_t + window
            window_txs = [tx for tx in tx_list if start_t <= tx.event_time <= end_t]
            distinct_sources = sorted({tx.source_account for tx in window_txs})
            if len(distinct_sources) >= min_sources:
                ev_ids = tuple(sorted({tx.event_id for tx in window_txs}))
                tx_ids = tuple(sorted({tx.transaction_id for tx in window_txs if tx.transaction_id}))
                sources_sys = tuple(sorted({tx.source_system for tx in window_txs}))
                total_amt = sum((tx.amount for tx in window_txs), Decimal("0"))
                pid = f"pat_fan_in_{_pattern_digest(inst_id, 'fan_in', target_acc, ev_ids)}"

                if not any(f.pattern_id == pid for f in findings):
                    findings.append(
                        NetworkPatternFinding(
                            pattern_id=pid,
                            installation_id=inst_id,
                            pattern_type="fan_in",
                            anchor_entity=target_acc,
                            related_entities=tuple(distinct_sources),
                            event_ids=ev_ids,
                            start_time=window_txs[0].event_time,
                            end_time=window_txs[-1].event_time,
                            detection_time=now,
                            explanation=(
                                f"Fan-in pattern: {len(distinct_sources)} distinct source accounts transferred {curr} "
                                f"{total_amt} to target account {target_acc} within a {window.total_seconds() / 3600:.1f}h window."
                            ),
                            evidence_limitations=(
                                "Does not establish that source account owners are acting in coordination.",
                                "Does not prove the incoming funds originate from illicit sources.",
                                "Transactions are observed transfers without internal ledger context.",
                            ),
                            alternative_legitimate_explanations=(
                                "Merchant collections or e-commerce payment settlement.",
                                "Fundraising, charitable donations, or crowdfunded initiatives.",
                                "Group bill-splitting, family contributions, or social event collections.",
                                "Payroll expense reimbursements or commission distributions.",
                            ),
                            supporting_source_systems=sources_sys,
                            transaction_ids=tx_ids,
                            monetary_total=total_amt,
                            currency=curr,
                            confidence=0.85,
                        )
                    )

    # 2. FAN-OUT: single source account -> multiple distinct targets
    source_buckets: dict[tuple[str, str, str], list[TransferObservation]] = defaultdict(list)
    for t in valid_transfers:
        source_buckets[(t.installation_id, t.source_account, t.currency)].append(t)

    for (inst_id, source_acc, curr), tx_list in source_buckets.items():
        if len(findings) >= max_findings:
            break
        for i in range(len(tx_list)):
            start_t = tx_list[i].event_time
            end_t = start_t + window
            window_txs = [tx for tx in tx_list if start_t <= tx.event_time <= end_t]
            distinct_targets = sorted({tx.target_account for tx in window_txs})
            if len(distinct_targets) >= min_targets:
                ev_ids = tuple(sorted({tx.event_id for tx in window_txs}))
                tx_ids = tuple(sorted({tx.transaction_id for tx in window_txs if tx.transaction_id}))
                sources_sys = tuple(sorted({tx.source_system for tx in window_txs}))
                total_amt = sum((tx.amount for tx in window_txs), Decimal("0"))
                pid = f"pat_fan_out_{_pattern_digest(inst_id, 'fan_out', source_acc, ev_ids)}"

                if not any(f.pattern_id == pid for f in findings):
                    findings.append(
                        NetworkPatternFinding(
                            pattern_id=pid,
                            installation_id=inst_id,
                            pattern_type="fan_out",
                            anchor_entity=source_acc,
                            related_entities=tuple(distinct_targets),
                            event_ids=ev_ids,
                            start_time=window_txs[0].event_time,
                            end_time=window_txs[-1].event_time,
                            detection_time=now,
                            explanation=(
                                f"Fan-out pattern: source account {source_acc} distributed {curr} {total_amt} "
                                f"to {len(distinct_targets)} distinct recipient accounts within a {window.total_seconds() / 3600:.1f}h window."
                            ),
                            evidence_limitations=(
                                "Does not establish mule recruitment without corroborating communications or credential logs.",
                                "Batch dispatches are standard operational practice in many commercial organizations.",
                            ),
                            alternative_legitimate_explanations=(
                                "Corporate payroll disbursements or contractor stipends.",
                                "Supplier or vendor invoice batch settlement.",
                                "Dividend, rebate, or refund distribution to customers.",
                                "Family allowances or scheduled recurring outbound transfers.",
                            ),
                            supporting_source_systems=sources_sys,
                            transaction_ids=tx_ids,
                            monetary_total=total_amt,
                            currency=curr,
                            confidence=0.85,
                        )
                    )

    return findings[:max_findings]


def detect_rapid_pass_through(
    transfers: list[TransferObservation],
    *,
    max_retention: timedelta = timedelta(hours=4),
    as_of: datetime | None = None,
    max_findings: int = 100,
) -> list[NetworkPatternFinding]:
    """Detect rapid pass-through where incoming transfer is quickly followed by outgoing transfer."""
    valid_transfers = [
        t for t in transfers
        if as_of is None or _ensure_utc(t.available_at) <= _ensure_utc(as_of)
    ]
    valid_transfers.sort(key=lambda t: t.event_time)

    # Group incoming and outgoing per account
    incoming_by_acc: dict[str, list[TransferObservation]] = defaultdict(list)
    outgoing_by_acc: dict[str, list[TransferObservation]] = defaultdict(list)

    for t in valid_transfers:
        incoming_by_acc[t.target_account].append(t)
        outgoing_by_acc[t.source_account].append(t)

    findings: list[NetworkPatternFinding] = []
    now = datetime.now(timezone.utc)

    for acc, in_list in incoming_by_acc.items():
        out_list = outgoing_by_acc.get(acc, [])
        if not out_list:
            continue

        for in_tx in in_list:
            if len(findings) >= max_findings:
                break
            for out_tx in out_list:
                # Same currency required for direct comparison
                if in_tx.currency != out_tx.currency:
                    continue
                # Outgoing must happen after incoming within retention window
                if in_tx.event_time <= out_tx.event_time <= (in_tx.event_time + max_retention):
                    ev_ids = (in_tx.event_id, out_tx.event_id)
                    tx_ids = tuple(
                        sorted(
                            {x for x in (in_tx.transaction_id, out_tx.transaction_id) if x}
                        )
                    )
                    pid = f"pat_pass_through_{_pattern_digest(in_tx.installation_id, 'rapid_pass_through', acc, ev_ids)}"

                    if not any(f.pattern_id == pid for f in findings):
                        delta_mins = (out_tx.event_time - in_tx.event_time).total_seconds() / 60.0
                        findings.append(
                            NetworkPatternFinding(
                                pattern_id=pid,
                                installation_id=in_tx.installation_id,
                                pattern_type="rapid_pass_through",
                                anchor_entity=acc,
                                related_entities=(in_tx.source_account, out_tx.target_account),
                                event_ids=ev_ids,
                                start_time=in_tx.event_time,
                                end_time=out_tx.event_time,
                                detection_time=now,
                                explanation=(
                                    f"Rapid pass-through: account {acc} received {in_tx.currency} {in_tx.amount} "
                                    f"from {in_tx.source_account} and transferred {out_tx.currency} {out_tx.amount} "
                                    f"onward to {out_tx.target_account} within {delta_mins:.1f} minutes."
                                ),
                                evidence_limitations=(
                                    "Toroka does not claim to trace identical monetary units; funds flow is inferred from temporal sequence.",
                                    "Full verification requires balance reconciliation across source and intermediary ledgers.",
                                ),
                                alternative_legitimate_explanations=(
                                    "Immediate bill settlement or invoice clearance upon receipt of salary.",
                                    "Escrow account or trust account disbursement.",
                                    "Automated liquidity sweep into a higher-yield savings or investment account.",
                                    "Peer-to-peer forwarding on behalf of a family member.",
                                ),
                                supporting_source_systems=tuple(sorted({in_tx.source_system, out_tx.source_system})),
                                transaction_ids=tx_ids,
                                monetary_total=out_tx.amount,
                                currency=in_tx.currency,
                                confidence=0.80,
                            )
                        )

    return findings[:max_findings]


def detect_multi_hop_movement(
    transfers: list[TransferObservation],
    *,
    min_hops: int = 3,
    max_hop_delay: timedelta = timedelta(hours=12),
    as_of: datetime | None = None,
    max_findings: int = 50,
) -> list[NetworkPatternFinding]:
    """Detect sequential multi-hop transfers (e.g. A -> B -> C -> D) within a bounded temporal window."""
    valid_transfers = [
        t for t in transfers
        if as_of is None or _ensure_utc(t.available_at) <= _ensure_utc(as_of)
    ]
    valid_transfers.sort(key=lambda t: t.event_time)

    # Build adjacency list: source -> list of outgoing transfers
    outgoing: dict[str, list[TransferObservation]] = defaultdict(list)
    for t in valid_transfers:
        outgoing[t.source_account].append(t)

    findings: list[NetworkPatternFinding] = []
    now = datetime.now(timezone.utc)

    # DFS path exploration with depth limit min_hops..min_hops+2
    def dfs_paths(current_path: list[TransferObservation], depth: int) -> None:
        if len(findings) >= max_findings:
            return
        if len(current_path) >= min_hops:
            # Found a candidate multi-hop chain
            accounts = [current_path[0].source_account] + [tx.target_account for tx in current_path]
            # Must have distinct intermediate nodes
            if len(set(accounts)) == len(accounts):
                ev_ids = tuple(tx.event_id for tx in current_path)
                tx_ids = tuple(tx.transaction_id for tx in current_path if tx.transaction_id)
                curr = current_path[0].currency
                # Same currency check
                if all(tx.currency == curr for tx in current_path):
                    inst_id = current_path[0].installation_id
                    pid = f"pat_multi_hop_{_pattern_digest(inst_id, 'multi_hop_movement', accounts[0], ev_ids)}"
                    if not any(f.pattern_id == pid for f in findings):
                        findings.append(
                            NetworkPatternFinding(
                                pattern_id=pid,
                                installation_id=inst_id,
                                pattern_type="multi_hop_movement",
                                anchor_entity=accounts[0],
                                related_entities=tuple(accounts[1:]),
                                event_ids=ev_ids,
                                start_time=current_path[0].event_time,
                                end_time=current_path[-1].event_time,
                                detection_time=now,
                                explanation=(
                                    f"Multi-hop transfer movement across {len(accounts)} accounts ({' -> '.join(accounts)}) "
                                    f"completed within {(current_path[-1].event_time - current_path[0].event_time).total_seconds() / 3600:.1f}h."
                                ),
                                evidence_limitations=(
                                    "Sequential transfer timing does not guarantee that the exact same principal was forwarded.",
                                    "Does not establish common ownership of intermediary accounts.",
                                ),
                                alternative_legitimate_explanations=(
                                    "Supply chain payments cascading from general contractor to subcontractors.",
                                    "Correspondent bank clearing across clearing entities.",
                                    "Escrow and title agency disbursements during real estate transactions.",
                                ),
                                supporting_source_systems=tuple(sorted({tx.source_system for tx in current_path})),
                                transaction_ids=tx_ids,
                                monetary_total=current_path[-1].amount,
                                currency=curr,
                                confidence=0.82,
                            )
                        )
            if depth >= min_hops + 1:
                return

        last_tx = current_path[-1]
        next_candidates = outgoing.get(last_tx.target_account, [])
        for nxt in next_candidates:
            if nxt.event_time >= last_tx.event_time and (nxt.event_time - last_tx.event_time) <= max_hop_delay:
                if nxt.target_account not in [tx.source_account for tx in current_path]:
                    dfs_paths(current_path + [nxt], depth + 1)

    for t in valid_transfers:
        if len(findings) >= max_findings:
            break
        dfs_paths([t], 1)

    return findings[:max_findings]


def detect_circular_movement(
    transfers: list[TransferObservation],
    *,
    max_hops: int = 5,
    max_cycle_window: timedelta = timedelta(days=7),
    as_of: datetime | None = None,
    max_findings: int = 50,
) -> list[NetworkPatternFinding]:
    """Detect circular flow of funds returning to the origin account (e.g. A -> B -> C -> A)."""
    valid_transfers = [
        t for t in transfers
        if as_of is None or _ensure_utc(t.available_at) <= _ensure_utc(as_of)
    ]
    valid_transfers.sort(key=lambda t: t.event_time)

    outgoing: dict[str, list[TransferObservation]] = defaultdict(list)
    for t in valid_transfers:
        outgoing[t.source_account].append(t)

    findings: list[NetworkPatternFinding] = []
    now = datetime.now(timezone.utc)

    def find_cycles(path: list[TransferObservation]) -> None:
        if len(findings) >= max_findings:
            return
        origin = path[0].source_account
        last = path[-1]

        # Check if last transaction returns to origin
        if last.target_account == origin and len(path) >= 2:
            ev_ids = tuple(tx.event_id for tx in path)
            tx_ids = tuple(tx.transaction_id for tx in path if tx.transaction_id)
            accounts = [tx.source_account for tx in path]
            curr = path[0].currency
            if all(tx.currency == curr for tx in path):
                inst_id = path[0].installation_id
                pid = f"pat_cycle_{_pattern_digest(inst_id, 'circular_movement', origin, ev_ids)}"
                if not any(f.pattern_id == pid for f in findings):
                    findings.append(
                        NetworkPatternFinding(
                            pattern_id=pid,
                            installation_id=inst_id,
                            pattern_type="circular_movement",
                            anchor_entity=origin,
                            related_entities=tuple(accounts[1:]),
                            event_ids=ev_ids,
                            start_time=path[0].event_time,
                            end_time=path[-1].event_time,
                            detection_time=now,
                            explanation=(
                                f"Circular transfer cycle: funds moved through {len(accounts)} accounts "
                                f"and returned to origin account {origin}."
                            ),
                            evidence_limitations=(
                                "Cycle detection is based on account graph paths; does not account for unrelated concurrent balances.",
                            ),
                            alternative_legitimate_explanations=(
                                "Corporate treasury inter-company liquidity rebalancing.",
                                "Short-term bridge loan between partners subsequently repaid.",
                                "Erroneous transfer and subsequent reversal / refund loop.",
                            ),
                            supporting_source_systems=tuple(sorted({tx.source_system for tx in path})),
                            transaction_ids=tx_ids,
                            monetary_total=last.amount,
                            currency=curr,
                            confidence=0.88,
                        )
                    )
            return

        if len(path) >= max_hops:
            return

        for nxt in outgoing.get(last.target_account, []):
            if nxt.event_time >= last.event_time and (nxt.event_time - path[0].event_time) <= max_cycle_window:
                # Intermediaries should not repeat until origin
                visited_intermediaries = {tx.target_account for tx in path[:-1]}
                if nxt.target_account not in visited_intermediaries:
                    find_cycles(path + [nxt])

    for t in valid_transfers:
        if len(findings) >= max_findings:
            break
        find_cycles([t])

    return findings[:max_findings]


def detect_common_beneficiaries(
    transfers: list[TransferObservation],
    *,
    min_accounts: int = 3,
    as_of: datetime | None = None,
    max_findings: int = 50,
) -> list[NetworkPatternFinding]:
    """Detect when several otherwise distinct accounts repeatedly transfer to a common beneficiary."""
    valid_transfers = [
        t for t in transfers
        if as_of is None or _ensure_utc(t.available_at) <= _ensure_utc(as_of)
    ]
    beneficiary_map: dict[tuple[str, str], list[TransferObservation]] = defaultdict(list)
    for t in valid_transfers:
        beneficiary_map[(t.installation_id, t.target_account)].append(t)

    findings: list[NetworkPatternFinding] = []
    now = datetime.now(timezone.utc)

    for (inst_id, beneficiary), tx_list in beneficiary_map.items():
        distinct_sources = sorted({tx.source_account for tx in tx_list})
        if len(distinct_sources) >= min_accounts:
            ev_ids = tuple(sorted({tx.event_id for tx in tx_list}))
            tx_ids = tuple(sorted({tx.transaction_id for tx in tx_list if tx.transaction_id}))
            pid = f"pat_common_beneficiary_{_pattern_digest(inst_id, 'common_beneficiary', beneficiary, ev_ids)}"
            if not any(f.pattern_id == pid for f in findings):
                findings.append(
                    NetworkPatternFinding(
                        pattern_id=pid,
                        installation_id=inst_id,
                        pattern_type="common_beneficiary",
                        anchor_entity=beneficiary,
                        related_entities=tuple(distinct_sources),
                        event_ids=ev_ids,
                        start_time=min(tx.event_time for tx in tx_list),
                        end_time=max(tx.event_time for tx in tx_list),
                        detection_time=now,
                        explanation=(
                            f"Common beneficiary: {len(distinct_sources)} distinct accounts sent funds "
                            f"to recipient {beneficiary}."
                        ),
                        evidence_limitations=(
                            "A common beneficiary does not prove collusion between payors without shared control evidence.",
                        ),
                        alternative_legitimate_explanations=(
                            "Utility provider, telecommunications company, or municipality tax office.",
                            "Commercial landlord or university tuition registry.",
                            "Major marketplace seller or reputable merchant.",
                        ),
                        supporting_source_systems=tuple(sorted({tx.source_system for tx in tx_list})),
                        transaction_ids=tx_ids,
                        confidence=0.75,
                    )
                )

    return findings[:max_findings]


def detect_shared_infrastructure(
    events: list[dict[str, Any]],
    installation_id: str,
    *,
    min_accounts: int = 3,
    as_of: datetime | None = None,
    max_findings: int = 50,
) -> list[NetworkPatternFinding]:
    """Detect multiple distinct customer accounts interacting through identical device/technical infrastructure."""
    infra_map: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for ev in events:
        if ev.get("installation_id") != installation_id:
            continue
        ev_time = ev.get("event_time")
        if isinstance(ev_time, str):
            ev_time = datetime.fromisoformat(ev_time)
        avail_at = ev.get("available_at", ev_time)
        if isinstance(avail_at, str):
            avail_at = datetime.fromisoformat(avail_at)

        if as_of and avail_at and _ensure_utc(avail_at) > _ensure_utc(as_of):
            continue

        dev = ev.get("device_id") or ev.get("ip_address") or ev.get("attributes", {}).get("device_id")
        acc = ev.get("account_id") or ev.get("subject") or ev.get("actor")
        if dev and acc:
            infra_map[str(dev)].append({"event": ev, "account": str(acc), "time": ev_time})

    findings: list[NetworkPatternFinding] = []
    now = datetime.now(timezone.utc)

    for dev_id, entries in infra_map.items():
        distinct_accounts = sorted({e["account"] for e in entries})
        if len(distinct_accounts) >= min_accounts:
            ev_ids = tuple(sorted({e["event"].get("event_id", "") for e in entries if e["event"].get("event_id")}))
            pid = f"pat_shared_infra_{_pattern_digest(installation_id, 'shared_infrastructure', dev_id, ev_ids)}"
            if not any(f.pattern_id == pid for f in findings):
                findings.append(
                    NetworkPatternFinding(
                        pattern_id=pid,
                        installation_id=installation_id,
                        pattern_type="shared_infrastructure",
                        anchor_entity=dev_id,
                        related_entities=tuple(distinct_accounts),
                        event_ids=ev_ids,
                        start_time=min(e["time"] for e in entries),
                        end_time=max(e["time"] for e in entries),
                        detection_time=now,
                        explanation=(
                            f"Shared infrastructure: {len(distinct_accounts)} distinct accounts accessed banking services "
                            f"from shared identifier {dev_id}."
                        ),
                        evidence_limitations=(
                            "A shared device or IP does NOT prove common ownership or illicit collusion.",
                            "Public/NAT IP addresses frequently host thousands of unrelated users.",
                        ),
                        alternative_legitimate_explanations=(
                            "Shared household computer or family tablet.",
                            "Public library workstation or university campus network.",
                            "In-branch customer self-service kiosk.",
                            "Corporate VPN gateway sharing a common egress IP.",
                        ),
                        supporting_source_systems=("channel_telemetry", "siem"),
                        confidence=0.70,
                    )
                )

    return findings[:max_findings]
