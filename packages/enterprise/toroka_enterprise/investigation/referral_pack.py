"""Referral package assembly, cryptographic integrity, and dual-approver sign-off."""
from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4


@dataclass
class ReferralPackManifest:
    pack_id: UUID
    case_id: UUID
    installation_id: str
    schema_version: str = "toroka-referral-pack-v1"
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_timezone: str = "UTC"
    generating_principal: str = ""
    approving_principals: list[str] = field(default_factory=list)
    recipient_organisation: str = ""
    purpose: str = ""
    legal_basis: str = ""
    included_artefacts: list[dict[str, Any]] = field(default_factory=list)
    omitted_evidence: list[dict[str, str]] = field(default_factory=list)
    rule_versions: dict[str, str] = field(default_factory=dict)
    disclaimer: str = (
        "This referral package is an investigative assembly of institutional evidence and factual "
        "chronology prepared by authorized investigators. It does not constitute automated court "
        "certification, official police filing, or unilateral determination of criminal liability."
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_id": str(self.pack_id),
            "case_id": str(self.case_id),
            "installation_id": self.installation_id,
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "source_timezone": self.source_timezone,
            "generating_principal": self.generating_principal,
            "approving_principals": self.approving_principals,
            "recipient_organisation": self.recipient_organisation,
            "purpose": self.purpose,
            "legal_basis": self.legal_basis,
            "included_artefacts": self.included_artefacts,
            "omitted_evidence": self.omitted_evidence,
            "rule_versions": self.rule_versions,
            "disclaimer": self.disclaimer,
        }


class ReferralPackBuilder:
    """Builds preview and finalized reproducible referral packages."""

    @classmethod
    def build_package_files(
        cls,
        *,
        pack_id: UUID,
        case_id: UUID,
        installation_id: str,
        case_summary: dict[str, Any],
        entities: list[dict[str, Any]],
        relationships: list[dict[str, Any]],
        transactions: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        evidence_index: list[dict[str, Any]],
        generating_principal: str,
        recipient_org: str,
        purpose: str,
        legal_basis: str,
        rule_versions: dict[str, str] | None = None,
        approving_principals: list[str] | None = None,
    ) -> dict[str, bytes]:
        """Assembles all package files in memory and computes individual and manifest digests."""
        files: dict[str, bytes] = {}

        # 1. case-summary.json
        files["case-summary.json"] = json.dumps(case_summary, indent=2, sort_keys=True).encode("utf-8")

        # 2. chronology.csv
        chronology_events = []
        for t in transactions:
            chronology_events.append({
                "timestamp": t.get("occurred_at"),
                "event_type": f"TRANSACTION_{t.get('event_type', 'transfer').upper()}",
                "entity_from": t.get("source_entity_id"),
                "entity_to": t.get("destination_entity_id"),
                "amount": f"{t.get('amount')} {t.get('currency')}",
                "evidence_id": t.get("evidence_id"),
                "source_ref": t.get("source_record_ref"),
            })
        for f in findings:
            chronology_events.append({
                "timestamp": f.get("created_at") or case_summary.get("created_at"),
                "event_type": f"FINDING_{f.get('rule_id')}",
                "entity_from": "",
                "entity_to": "",
                "amount": "",
                "evidence_id": ",".join(str(e) for e in f.get("evidence_ids", [])),
                "source_ref": f.get("title"),
            })
        chronology_events.sort(key=lambda x: str(x.get("timestamp") or ""))

        chrono_buf = io.StringIO()
        chrono_writer = csv.DictWriter(
            chrono_buf,
            fieldnames=["timestamp", "event_type", "entity_from", "entity_to", "amount", "evidence_id", "source_ref"],
        )
        chrono_writer.writeheader()
        for c in chronology_events:
            chrono_writer.writerow(c)
        files["chronology.csv"] = chrono_buf.getvalue().encode("utf-8")

        # 3. entities.csv
        ent_buf = io.StringIO()
        ent_writer = csv.DictWriter(
            ent_buf,
            fieldnames=["id", "kind", "identifier_token", "display_label", "first_seen_at", "last_seen_at", "sensitivity"],
        )
        ent_writer.writeheader()
        for e in entities:
            ent_writer.writerow({
                "id": e.get("id"),
                "kind": e.get("kind"),
                "identifier_token": e.get("identifier_token"),
                "display_label": e.get("display_label", ""),
                "first_seen_at": e.get("first_seen_at"),
                "last_seen_at": e.get("last_seen_at"),
                "sensitivity": e.get("sensitivity", "restricted"),
            })
        files["entities.csv"] = ent_buf.getvalue().encode("utf-8")

        # 4. relationships.csv
        rel_buf = io.StringIO()
        rel_writer = csv.DictWriter(
            rel_buf,
            fieldnames=["id", "source_entity_id", "target_entity_id", "relationship_type", "state", "explanation"],
        )
        rel_writer.writeheader()
        for r in relationships:
            rel_writer.writerow({
                "id": r.get("id"),
                "source_entity_id": r.get("source_entity_id"),
                "target_entity_id": r.get("target_entity_id"),
                "relationship_type": r.get("relationship_type"),
                "state": r.get("state"),
                "explanation": r.get("explanation"),
            })
        files["relationships.csv"] = rel_buf.getvalue().encode("utf-8")

        # 5. transactions.csv
        tx_buf = io.StringIO()
        tx_writer = csv.DictWriter(
            tx_buf,
            fieldnames=["id", "source_entity_id", "destination_entity_id", "amount", "currency", "occurred_at", "channel", "event_type", "evidence_id"],
        )
        tx_writer.writeheader()
        for t in transactions:
            tx_writer.writerow({
                "id": t.get("id"),
                "source_entity_id": t.get("source_entity_id"),
                "destination_entity_id": t.get("destination_entity_id"),
                "amount": t.get("amount"),
                "currency": t.get("currency"),
                "occurred_at": t.get("occurred_at"),
                "channel": t.get("channel"),
                "event_type": t.get("event_type"),
                "evidence_id": t.get("evidence_id"),
            })
        files["transactions.csv"] = tx_buf.getvalue().encode("utf-8")

        # 6. findings.json
        files["findings.json"] = json.dumps(findings, indent=2, sort_keys=True).encode("utf-8")

        # 7. evidence-index.csv
        ev_buf = io.StringIO()
        ev_writer = csv.DictWriter(
            ev_buf,
            fieldnames=["id", "source_type", "source_system", "source_record_ref", "sha256", "collected_by", "observed_at", "collected_at"],
        )
        ev_writer.writeheader()
        for ev in evidence_index:
            ev_writer.writerow({
                "id": ev.get("id"),
                "source_type": ev.get("source_type"),
                "source_system": ev.get("source_system"),
                "source_record_ref": ev.get("source_record_ref", ""),
                "sha256": ev.get("sha256"),
                "collected_by": ev.get("collected_by"),
                "observed_at": ev.get("observed_at"),
                "collected_at": ev.get("collected_at"),
            })
        files["evidence-index.csv"] = ev_buf.getvalue().encode("utf-8")

        # Compute SHA-256 sums for integrity/sha256sums.txt
        sums_lines = []
        included_meta = []
        for fname in sorted(files.keys()):
            h = hashlib.sha256(files[fname]).hexdigest()
            sums_lines.append(f"{h}  {fname}")
            included_meta.append({"filename": fname, "sha256": h, "bytes": len(files[fname])})
        files["integrity/sha256sums.txt"] = ("\n".join(sums_lines) + "\n").encode("utf-8")

        # 8. manifest.json
        manifest = ReferralPackManifest(
            pack_id=pack_id,
            case_id=case_id,
            installation_id=installation_id,
            generating_principal=generating_principal,
            approving_principals=approving_principals or [],
            recipient_organisation=recipient_org,
            purpose=purpose,
            legal_basis=legal_basis,
            included_artefacts=included_meta,
            omitted_evidence=[],
            rule_versions=rule_versions or {"engine": "institution-policy-2026-v1"},
        )
        files["manifest.json"] = json.dumps(manifest.to_dict(), indent=2, sort_keys=True).encode("utf-8")

        return files

    @classmethod
    def compute_overall_pack_hash(cls, files: dict[str, bytes]) -> str:
        """Computes a deterministic root hash over all assembled files (excluding manifest)."""
        root_digest = hashlib.sha256()
        for fname in sorted(files.keys()):
            if fname == "manifest.json":
                continue
            root_digest.update(fname.encode("utf-8"))
            root_digest.update(b"\x00")
            root_digest.update(files[fname])
            root_digest.update(b"\x00")
        return root_digest.hexdigest()
