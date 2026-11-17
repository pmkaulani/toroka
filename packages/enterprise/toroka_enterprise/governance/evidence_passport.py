from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any


def compute_evidence_digest(content: str | bytes | dict[str, Any]) -> str:
    """Computes a deterministic SHA-256 digest over arbitrary evidence payload."""
    if isinstance(content, bytes):
        raw = content
    elif isinstance(content, dict):
        raw = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
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


def canonical_evidence_record(item: BoundEvidenceItem) -> dict[str, Any]:
    required = (item.evidence_id, item.evidence_digest, item.source_record_id, item.source_system)
    if any(not str(value).strip() for value in required):
        raise ValueError("Evidence passport items require ID, digest, source record and source system")
    if len(item.evidence_digest) != 64:
        raise ValueError("Evidence digest must be a SHA-256 hex digest")
    return {
        "evidence_id": item.evidence_id,
        "evidence_digest": item.evidence_digest.lower(),
        "source_record_id": item.source_record_id,
        "source_system": item.source_system,
        "observed_at": item.observed_at,
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
    detection_time: datetime | str
    evidence_records: tuple[dict[str, Any], ...] = ()
    detection_run_id: str | None = None
    data_contract_fingerprint: str = ""
    policy_version: str = "v1.0.0"
    earliest_event_time: datetime | str | None = None
    evidence_at_detection_count: int = 0
    delayed_evidence_count: int = 0
    contradictions_count: int = 0
    evidence_debt_level: str = "LOW"
    alternative_explanations: tuple[str, ...] = ()
    validation_result: str = "PASS"
    human_review_required: bool = True
    signing_key_id: str | None = None
    signature_algorithm: str | None = None
    signature: str | None = None
    signature_bundle: dict[str, Any] | None = None
    merkle_proof: dict[str, Any] | None = None
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
                if isinstance(item, BoundEvidenceItem):
                    records.append(canonical_evidence_record(item))
                elif hasattr(item, "to_dict"):
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
            detection_run_id=detection_run_id,
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

    @classmethod
    def from_payload(cls, payload: dict[str, Any], passport_digest: str = "") -> TorokaEvidencePassport:
        raw_records = payload.get("evidence_records", [])
        return cls(
            passport_id=str(payload.get("passport_id", "")),
            finding_id=str(payload.get("finding_id", "")),
            case_id=str(payload.get("case_id", "")),
            installation_id=str(payload.get("installation_id", "")),
            finding_type=str(payload.get("finding_type", "CORRELATED_FRAUD_PATTERN")),
            finding_status=str(payload.get("finding_status", "GROUNDED")),
            detection_run_id=payload.get("detection_run_id"),
            component_versions=dict(payload.get("component_versions", {})),
            configuration_digest=str(payload.get("configuration_digest", "")),
            data_contract_fingerprint=str(payload.get("data_contract_fingerprint", "")),
            policy_version=str(payload.get("policy_version", "v1.0.0")),
            detection_time=payload.get("detection_time", ""),
            earliest_event_time=payload.get("earliest_event_time"),
            evidence_count=int(payload.get("evidence_count", len(raw_records))),
            source_systems=tuple(payload.get("source_systems", [])),
            evidence_records=tuple(raw_records),
            evidence_at_detection_count=int(payload.get("evidence_at_detection_count", len(raw_records))),
            delayed_evidence_count=int(payload.get("delayed_evidence_count", 0)),
            contradictions_count=int(payload.get("contradictions_count", 0)),
            evidence_debt_level=str(payload.get("evidence_debt_level", "LOW")),
            alternative_explanations=tuple(payload.get("alternative_explanations", [])),
            validation_result=str(payload.get("validation_result", "PASS")),
            human_review_required=bool(payload.get("human_review_required", True)),
            signing_key_id=payload.get("signing_key_id"),
            signature_algorithm=payload.get("signature_algorithm"),
            signature=payload.get("signature"),
            signature_bundle=payload.get("signature_bundle"),
            merkle_proof=payload.get("merkle_proof"),
            passport_digest=passport_digest,
        )

    def __post_init__(self) -> None:
        if not self.passport_digest:
            payload = self._compute_canonical_payload()
            digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            object.__setattr__(self, "passport_digest", digest)

    def canonical_payload(self) -> dict[str, Any]:
        evidence_entries: list[dict[str, Any]] = []
        for rec in self.evidence_records:
            if isinstance(rec, dict):
                evidence_entries.append({
                    "evidence_id": str(rec.get("evidence_id", "")),
                    "evidence_digest": str(rec.get("evidence_digest", "")).lower(),
                    "source_record_id": str(rec.get("source_record_id", "")),
                    "source_system": str(rec.get("source_system", "")),
                    "observed_at": rec.get("observed_at"),
                })
            elif hasattr(rec, "to_dict"):
                d = rec.to_dict()
                evidence_entries.append({
                    "evidence_id": str(d.get("evidence_id", "")),
                    "evidence_digest": str(d.get("evidence_digest", "")).lower(),
                    "source_record_id": str(d.get("source_record_id", "")),
                    "source_system": str(d.get("source_system", "")),
                    "observed_at": d.get("observed_at"),
                })
        sorted_ev = sorted(evidence_entries, key=lambda x: str(x.get("evidence_id", "")))
        det_time = (
            self.detection_time.isoformat()
            if isinstance(self.detection_time, datetime)
            else str(self.detection_time)
        )
        earliest_time = (
            self.earliest_event_time.isoformat()
            if isinstance(self.earliest_event_time, datetime)
            else (str(self.earliest_event_time) if self.earliest_event_time else None)
        )
        return {
            "schema": "toroka.evidence-passport.v1",
            "passport_id": self.passport_id,
            "finding_id": self.finding_id,
            "case_id": self.case_id,
            "installation_id": self.installation_id,
            "finding_type": self.finding_type,
            "finding_status": self.finding_status,
            "detection_run_id": self.detection_run_id,
            "component_versions": dict(sorted(self.component_versions.items())),
            "configuration_digest": self.configuration_digest,
            "data_contract_fingerprint": self.data_contract_fingerprint,
            "policy_version": self.policy_version,
            "detection_time": det_time,
            "earliest_event_time": earliest_time,
            "source_systems": sorted(self.source_systems),
            "evidence_count": len(sorted_ev) if sorted_ev else self.evidence_count,
            "evidence_records": sorted_ev,
            "evidence_at_detection_count": self.evidence_at_detection_count,
            "delayed_evidence_count": self.delayed_evidence_count,
            "contradictions_count": self.contradictions_count,
            "evidence_debt_level": self.evidence_debt_level,
            "alternative_explanations": sorted(self.alternative_explanations),
            "validation_result": self.validation_result,
            "human_review_required": self.human_review_required,
        }

    def _compute_canonical_payload(self) -> str:
        return json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )

    def verify_integrity(self) -> bool:
        """Verifies that passport_digest matches the cryptographic hash of all canonical fields,
        including exact evidence IDs, evidence content digests, source records, and config.
        """
        expected = hashlib.sha256(self._compute_canonical_payload().encode("utf-8")).hexdigest()
        return hmac.compare_digest(self.passport_digest, expected)

    def sign(self, signer: Any) -> TorokaEvidencePassport:
        """Asymmetrically signs the canonical passport payload using bank HSM or KMS."""
        bundle = signer.sign(self.canonical_payload())
        return replace(
            self,
            signature_bundle=bundle.to_dict(),
            signing_key_id=bundle.key_id,
            signature_algorithm=bundle.algorithm,
            signature=bundle.signature,
        )

    def verify_digital_signature(self, trusted_public_key_pem: str | None = None) -> bool:
        """Verifies the asymmetric digital signature against the canonical passport payload."""
        if not self.signature_bundle:
            return False
        from toroka_enterprise.governance.pki import SignatureBundle, verify_asymmetric_signature
        bundle = SignatureBundle.from_dict(self.signature_bundle)
        return verify_asymmetric_signature(
            payload=self.canonical_payload(),
            bundle=bundle,
            trusted_public_key_pem=trusted_public_key_pem,
        )

    def to_dict(self) -> dict[str, Any]:
        """Produces full serializable dictionary representation."""
        data = dict(self.canonical_payload())
        data["passport_digest"] = self.passport_digest
        data["signing_key_id"] = self.signing_key_id
        data["signature_algorithm"] = self.signature_algorithm
        data["signature"] = self.signature
        data["signature_bundle"] = self.signature_bundle
        data["merkle_proof"] = self.merkle_proof
        return data

