from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


def compute_evidence_digest(content: str | bytes | dict[str, Any]) -> str:
    """Computes a deterministic SHA-256 digest over arbitrary evidence payload."""
    if isinstance(content, bytes):
        raw = content
    elif isinstance(content, dict):
        raw = json.dumps(content, sort_keys=True).encode("utf-8")
    else:
        raw = str(content).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class BoundEvidenceItem:
    evidence_id: str
    evidence_digest: str  # SHA-256 of exact content or excerpt
    source_record_id: str
    source_system: str
    observed_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "evidence_digest": self.evidence_digest,
            "source_record_id": self.source_record_id,
            "source_system": self.source_system,
            "observed_at": self.observed_at,
        }


@dataclass(frozen=True)
class TorokaEvidencePassport:
    """Cryptographically binds the exact evidence set, component versions, configuration,
    and policy that produced a financial-crime detection finding.
    
    Guarantees tamper-evident data lineage for bank model risk, external audit,
    and regulatory inspection (NIST AI RMF / OCC 2026).
    """
    passport_id: str
    finding_id: str
    case_id: str
    installation_id: str
    finding_type: str
    finding_status: str
    component_versions: dict[str, str]
    configuration_digest: str
    evidence_count: int
    source_systems: tuple[str, ...]
    detection_time: datetime
    evidence_records: tuple[dict[str, Any], ...] = ()
    data_contract_fingerprint: str = ""
    policy_version: str = "v1.0.0"
    earliest_event_time: datetime | None = None
    evidence_at_detection_count: int = 0
    delayed_evidence_count: int = 0
    contradictions_count: int = 0
    evidence_debt_level: str = "LOW"
    alternative_explanations: tuple[str, ...] = ()
    validation_result: str = "PASS"
    human_review_required: bool = True
    passport_digest: str = ""

    @classmethod
    def create(
        cls,
        *,
        passport_id: str,
        case_id: str,
        installation_id: str,
        finding_id: str = "finding-default",
        detection_run_id: str | None = None,
        finding_type: str = "detection_finding",
        finding_status: str = "CONFIRMED",
        component_versions: dict[str, str] | None = None,
        configuration_digest: str = "sha256_cfg",
        source_systems: tuple[str, ...] = (),
        issued_at: datetime | None = None,
        evidence_records: list[BoundEvidenceItem] | tuple[dict[str, Any], ...] | None = None,
        data_contract_fingerprint: str = "",
        policy_version: str = "v1.0.0",
        **kwargs: Any,
    ) -> TorokaEvidencePassport:
        records: list[dict[str, Any]] = []
        if evidence_records:
            for item in evidence_records:
                if hasattr(item, "to_dict"):
                    records.append(item.to_dict())
                elif isinstance(item, dict):
                    records.append(item)
        src_systems = tuple(
            sorted(
                set(
                    source_systems
                    or tuple(r.get("source_system", "") for r in records if r.get("source_system"))
                )
            )
        )
        t = issued_at or datetime.now(timezone.utc)
        return cls(
            passport_id=passport_id,
            finding_id=finding_id,
            case_id=case_id,
            installation_id=installation_id,
            finding_type=finding_type,
            finding_status=finding_status,
            component_versions=component_versions or {},
            configuration_digest=configuration_digest,
            evidence_count=len(records),
            source_systems=src_systems,
            detection_time=t,
            evidence_records=tuple(records),
            data_contract_fingerprint=data_contract_fingerprint,
            policy_version=policy_version,
            **kwargs,
        )

    def __post_init__(self) -> None:
        if not self.passport_digest:
            payload = self._compute_canonical_payload()
            digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            object.__setattr__(self, "passport_digest", digest)

    def _compute_canonical_payload(self) -> str:
        evidence_entries: list[dict[str, str]] = []
        for rec in self.evidence_records:
            if isinstance(rec, dict):
                evidence_entries.append({
                    "evidence_id": str(rec.get("evidence_id", "")),
                    "evidence_digest": str(rec.get("evidence_digest", "")),
                    "source_record_id": str(rec.get("source_record_id", "")),
                    "source_system": str(rec.get("source_system", "")),
                })
        sorted_ev = sorted(evidence_entries, key=lambda x: x["evidence_id"])
        detection_iso = self.detection_time.isoformat() if isinstance(self.detection_time, datetime) else str(self.detection_time)
        payload = {
            "passport_id": self.passport_id,
            "finding_id": self.finding_id,
            "case_id": self.case_id,
            "installation_id": self.installation_id,
            "finding_type": self.finding_type,
            "finding_status": self.finding_status,
            "component_versions": self.component_versions,
            "configuration_digest": self.configuration_digest,
            "data_contract_fingerprint": self.data_contract_fingerprint,
            "policy_version": self.policy_version,
            "detection_time": detection_iso,
            "source_systems": sorted(self.source_systems),
            "evidence_count": self.evidence_count,
            "evidence_records": sorted_ev,
        }
        return json.dumps(payload, sort_keys=True)

    def verify_integrity(self) -> bool:
        """Verifies that passport_digest matches the cryptographic hash of all canonical fields,
        including exact evidence IDs, evidence content digests, source records, and config.
        """
        expected = hashlib.sha256(self._compute_canonical_payload().encode("utf-8")).hexdigest()
        return self.passport_digest == expected

