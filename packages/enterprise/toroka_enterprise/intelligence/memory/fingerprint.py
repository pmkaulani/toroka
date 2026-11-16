from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from ..events import IntelligenceEvent
from .control_weakness import ControlWeaknessType, detect_control_weaknesses

EXTRACTOR_VERSION = "v1"

EVENT_FEATURES: dict[str, str] = {
    "customer_record_access": "event.customer_record_access",
    "beneficiary_change": "event.beneficiary_change",
    "limit_change": "event.limit_change",
    "contact_details_changed": "event.contact_details_changed",
    "password_reset": "event.password_reset",
    "mfa_disabled": "event.mfa_disabled",
    "high_value_transfer": "event.high_value_transfer",
    "transfer_initiated": "event.transfer_initiated",
    "account_restricted": "event.account_restricted",
    "account_unrestricted": "event.account_unrestricted",
    "privileged_login": "event.privileged_login",
    "role_change": "event.role_change",
    "customer_complaint": "event.customer_complaint",
    "service_ticket_created": "event.service_ticket_created",
}

# Expected default institutional source systems for telemetry coverage evaluation
EXPECTED_SOURCE_SYSTEMS: tuple[str, ...] = (
    "core_banking",
    "identity_access",
    "payments",
    "crm_support",
    "hr_system",
)

# Canonical source mappings for event types (used to differentiate absent from unknown)
EVENT_SOURCE_MAPPING: dict[str, str] = {
    "beneficiary_change": "core_banking",
    "limit_change": "core_banking",
    "account_restricted": "core_banking",
    "account_unrestricted": "core_banking",
    "transfer_initiated": "payments",
    "high_value_transfer": "payments",
    "privileged_login": "identity_access",
    "password_reset": "identity_access",
    "mfa_disabled": "identity_access",
    "role_change": "hr_system",
    "customer_record_access": "crm_support",
    "contact_details_changed": "crm_support",
    "customer_complaint": "crm_support",
    "service_ticket_created": "crm_support",
}

SEQUENCE_RULES: tuple[tuple[str, str], ...] = (
    ("customer_record_access", "beneficiary_change"),
    ("beneficiary_change", "transfer_initiated"),
    ("beneficiary_change", "high_value_transfer"),
    ("password_reset", "beneficiary_change"),
    ("mfa_disabled", "high_value_transfer"),
    ("contact_details_changed", "transfer_initiated"),
    ("privileged_login", "beneficiary_change"),
    ("privileged_login", "role_change"),
    ("customer_record_access", "contact_details_changed"),
)


@dataclass(frozen=True)
class FingerprintEvidence:
    dimension: str
    event_ids: tuple[str, ...]
    source_systems: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension,
            "event_ids": list(self.event_ids),
            "source_systems": list(self.source_systems),
        }


@dataclass(frozen=True)
class CaseFingerprint:
    """Zero-PII structured behavioral signature of an investigated case."""

    case_id: str
    installation_id: str
    extractor_version: str
    features: dict[str, str]
    evidence: tuple[FingerprintEvidence, ...]
    source_systems: tuple[str, ...]
    source_coverage: float
    total_events: int
    first_event_time: datetime | None
    last_event_time: datetime | None
    control_weaknesses: tuple[str, ...]
    adjudicated_label: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "installation_id": self.installation_id,
            "extractor_version": self.extractor_version,
            "features": dict(self.features),
            "evidence": [e.to_dict() for e in self.evidence],
            "source_systems": list(self.source_systems),
            "source_coverage": self.source_coverage,
            "total_events": self.total_events,
            "first_event_time": self.first_event_time.isoformat() if self.first_event_time else None,
            "last_event_time": self.last_event_time.isoformat() if self.last_event_time else None,
            "control_weaknesses": list(self.control_weaknesses),
            "adjudicated_label": self.adjudicated_label,
            "created_at": self.created_at.isoformat(),
        }


def _time_bucket(seconds: float) -> str:
    if seconds < 60:
        return "<1m"
    if seconds < 900:
        return "1m-15m"
    if seconds < 3600:
        return "15m-1h"
    if seconds < 86400:
        return "1h-24h"
    return ">24h"


def _share_entity_link(e1: IntelligenceEvent, e2: IntelligenceEvent) -> bool:
    """Verify supported entity relationship or shared pseudonymised reference between two events."""
    # 1. Direct actor match (same employee or operator)
    if e1.actor and e2.actor and e1.actor == e2.actor:
        return True
    # 2. Direct subject match (same account or target customer)
    if e1.subject and e2.subject and e1.subject == e2.subject:
        return True
    # 3. Actor of e1 acted on subject of e2 or vice versa
    if e1.actor and e2.subject and e1.actor == e2.subject:
        return True
    if e1.subject and e2.actor and e1.subject == e2.actor:
        return True
    # 4. Overlapping resolved entities
    set1 = set(e1.entities)
    set2 = set(e2.entities)
    if set1 and set2 and not set1.isdisjoint(set2):
        return True
    # 5. Shared case_id or session_id in attributes
    s1 = e1.attributes.get("session_id")
    s2 = e2.attributes.get("session_id")
    if s1 and s2 and s1 == s2:
        return True
    c1 = e1.attributes.get("case_id")
    c2 = e2.attributes.get("case_id")
    if c1 and c2 and c1 == c2:
        return True
    return False


def build_case_fingerprint(
    case_id: str,
    installation_id: str,
    events: list[IntelligenceEvent],
    adjudicated_label: str | None = None,
    expected_sources: tuple[str, ...] = EXPECTED_SOURCE_SYSTEMS,
    extractor_version: str = EXTRACTOR_VERSION,
) -> CaseFingerprint:
    """Deterministically extracts a zero-PII CaseFingerprint from case intelligence events."""
    # Deduplicate events by event_id
    seen_ids: set[str] = set()
    deduped_events: list[IntelligenceEvent] = []
    for ev in events:
        if ev.event_id not in seen_ids:
            seen_ids.add(ev.event_id)
            deduped_events.append(ev)

    # Sort strictly chronologically, breaking ties with event_id
    ev_sorted = sorted(deduped_events, key=lambda e: (e.event_time, e.event_id))

    observed_sources = sorted(set(e.source_system for e in ev_sorted if e.source_system))
    observed_source_set = set(observed_sources)

    # Source coverage metric
    matching_sources = [s for s in expected_sources if s in observed_source_set]
    source_coverage = round(len(matching_sources) / len(expected_sources), 4) if expected_sources else 1.0

    features: dict[str, str] = {}
    evidence_map: dict[str, FingerprintEvidence] = {}

    # 1. Source system presence
    for src in expected_sources:
        dim = f"source_presence.{src}"
        features[dim] = "present" if src in observed_source_set else "absent"

    # 2. Individual Normalized Event Features
    events_by_type: dict[str, list[IntelligenceEvent]] = {}
    for ev in ev_sorted:
        events_by_type.setdefault(ev.event_type, []).append(ev)

    for ev_type, dim in EVENT_FEATURES.items():
        ev_list = events_by_type.get(ev_type, [])
        mapped_src = EVENT_SOURCE_MAPPING.get(ev_type)

        if ev_list:
            features[dim] = "present"
            evidence_map[dim] = FingerprintEvidence(
                dimension=dim,
                event_ids=tuple(e.event_id for e in ev_list),
                source_systems=tuple(sorted(set(e.source_system for e in ev_list if e.source_system))),
            )
        elif mapped_src and mapped_src in observed_source_set:
            # Source system was present in telemetry, but event did not occur
            features[dim] = "absent"
        elif mapped_src and mapped_src not in observed_source_set:
            # Telemetry for that source system was missing; preserve unknown!
            features[dim] = "unknown"
        else:
            features[dim] = "absent"

    # 3. Sensitive Account / Permission Changes
    sensitive_mappings = {
        "sensitive_change.beneficiary": ("beneficiary_change", "core_banking"),
        "sensitive_change.contact_details": ("contact_details_changed", "crm_support"),
        "sensitive_change.limit": ("limit_change", "core_banking"),
        "sensitive_change.credentials": (("password_reset", "mfa_disabled"), "identity_access"),
        "sensitive_change.privileged_session": (("privileged_login", "role_change"), "identity_access"),
    }
    for dim, (target_types, src) in sensitive_mappings.items():
        t_list = (target_types,) if isinstance(target_types, str) else target_types
        matched_evs = [e for e in ev_sorted if e.event_type in t_list]
        if matched_evs:
            features[dim] = "present"
            evidence_map[dim] = FingerprintEvidence(
                dimension=dim,
                event_ids=tuple(e.event_id for e in matched_evs),
                source_systems=tuple(sorted(set(e.source_system for e in matched_evs if e.source_system))),
            )
        elif src in observed_source_set:
            features[dim] = "absent"
        else:
            features[dim] = "unknown"

    # 4. Temporal Event Sequences with Entity Linkage
    for type_a, type_b in SEQUENCE_RULES:
        seq_dim = f"sequence.{type_a}_to_{type_b}"
        evs_a = events_by_type.get(type_a, [])
        evs_b = events_by_type.get(type_b, [])

        src_a = EVENT_SOURCE_MAPPING.get(type_a)
        src_b = EVENT_SOURCE_MAPPING.get(type_b)

        # Look for valid ordered sequence pair with entity link
        matched_pair: tuple[IntelligenceEvent, IntelligenceEvent] | None = None
        for ea in evs_a:
            for eb in evs_b:
                if ea.event_time <= eb.event_time and _share_entity_link(ea, eb):
                    matched_pair = (ea, eb)
                    break
            if matched_pair:
                break

        if matched_pair:
            ea, eb = matched_pair
            delta_sec = (eb.event_time - ea.event_time).total_seconds()
            bucket = _time_bucket(delta_sec)
            features[seq_dim] = f"present_{bucket}"
            evidence_map[seq_dim] = FingerprintEvidence(
                dimension=seq_dim,
                event_ids=(ea.event_id, eb.event_id),
                source_systems=tuple(
                    sorted(set(s for s in (ea.source_system, eb.source_system) if s))
                ),
            )
        else:
            # Check source telemetry availability
            sources_present = True
            if src_a and src_a not in observed_source_set:
                sources_present = False
            if src_b and src_b not in observed_source_set:
                sources_present = False

            if sources_present:
                features[seq_dim] = "absent"
            else:
                features[seq_dim] = "unknown"

    # 5. Control Weaknesses
    detected_weaknesses = detect_control_weaknesses(ev_sorted)
    weakness_types = tuple(w.weakness_type.value for w in detected_weaknesses)
    for wt in ControlWeaknessType:
        dim = f"control_weakness.{wt.value}"
        matching_w = next((w for w in detected_weaknesses if w.weakness_type == wt), None)
        if matching_w:
            features[dim] = "present"
            evidence_map[dim] = FingerprintEvidence(
                dimension=dim,
                event_ids=matching_w.event_ids,
                source_systems=matching_w.source_systems,
            )
        else:
            features[dim] = "absent"

    first_time = ev_sorted[0].event_time if ev_sorted else None
    last_time = ev_sorted[-1].event_time if ev_sorted else None

    return CaseFingerprint(
        case_id=case_id,
        installation_id=installation_id,
        extractor_version=extractor_version,
        features=features,
        evidence=tuple(evidence_map.values()),
        source_systems=tuple(observed_sources),
        source_coverage=source_coverage,
        total_events=len(ev_sorted),
        first_event_time=first_time,
        last_event_time=last_time,
        control_weaknesses=weakness_types,
        adjudicated_label=adjudicated_label,
    )
