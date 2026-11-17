"""Court-Ready Forensic Evidence Dossier & Section 106B Electronic Records Admissibility.

Provides legally binding evidentiary dossier packages for law enforcement (DCI / BFIU),
judicial presentation, and regulatory discovery under the Kenya Evidence Act (Cap 80, Sec 106B),
UK PACE Section 69, and US Federal Rule of Evidence 902(13)/(14).
"""
from __future__ import annotations

import hashlib
import hmac
import html
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .deployment import _canonical_utc, canonical_json
from .pki import (
    LocalHSMKeyProvider,
    MerkleTree,
    SignatureBundle,
    verify_asymmetric_signature,
)


@dataclass(frozen=True)
class CustodyEvent:
    """An immutable step in the forensic chain of custody."""
    event_id: str
    timestamp: datetime
    actor_subject: str
    actor_role: str
    action: str
    source_hash: str
    destination_hash: str
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": _canonical_utc(self.timestamp),
            "actor_subject": self.actor_subject,
            "actor_role": self.actor_role,
            "action": self.action,
            "source_hash": self.source_hash,
            "destination_hash": self.destination_hash,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class Section106BCertificate:
    """Electronic Evidence Certificate under Section 106B of the Kenya Evidence Act (Cap 80).
    
    Certifies the continuous proper operation of the computing device, the integrity
    of the digital recording, and unbroken forensic chain of custody.
    """
    certificate_id: str
    statutory_framework: str
    certifier_name: str
    certifier_designation: str
    certifier_organization: str
    device_identification: str
    operating_condition_statement: str
    hash_algorithm: str
    merkle_root_hash: str
    certified_at: datetime
    declaration_text: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "statutory_framework": self.statutory_framework,
            "certifier_name": self.certifier_name,
            "certifier_designation": self.certifier_designation,
            "certifier_organization": self.certifier_organization,
            "device_identification": self.device_identification,
            "operating_condition_statement": self.operating_condition_statement,
            "hash_algorithm": self.hash_algorithm,
            "merkle_root_hash": self.merkle_root_hash,
            "certified_at": _canonical_utc(self.certified_at),
            "declaration_text": self.declaration_text,
        }


def forensic_dossier_payload(
    *,
    dossier_id: str,
    case_id: str,
    installation_id: str,
    title: str,
    incident_type: str,
    fraud_loss_amount: float,
    currency: str,
    examiner_subject: str,
    examiner_role: str,
    created_at: datetime,
    case_summary: str,
    attack_path_summary: dict[str, Any],
    identified_mule_nodes: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    evidence_records: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    section_106b_certificate: Section106BCertificate | None,
    chain_of_custody: list[CustodyEvent] | tuple[CustodyEvent, ...] | None = None,
) -> dict[str, Any]:
    """Generates the canonical dictionary payload for deterministic hashing.
    
    Excludes chain_of_custody, status, and signature_bundle: these are mutable
    lifecycle tracking fields that append as custody is transferred or signed.
    """
    sorted_mules = sorted(
        (dict(m) for m in identified_mule_nodes),
        key=lambda m: (str(m.get("account_number", "")), str(m.get("entity_id", ""))),
    )
    sorted_evidence = sorted(
        (dict(e) for e in evidence_records),
        key=lambda e: (str(e.get("evidence_id", e.get("event_id", ""))), canonical_json(e)),
    )
    cert_dict = section_106b_certificate.to_dict() if section_106b_certificate else None

    return {
        "schema": "toroka.forensic-dossier.v1",
        "dossier_id": dossier_id,
        "case_id": case_id,
        "installation_id": installation_id,
        "title": title,
        "incident_type": incident_type,
        "fraud_loss_amount": float(fraud_loss_amount),
        "currency": currency,
        "examiner_subject": examiner_subject,
        "examiner_role": examiner_role,
        "created_at": _canonical_utc(created_at),
        "case_summary": case_summary,
        "attack_path_summary": dict(attack_path_summary),
        "identified_mule_nodes": sorted_mules,
        "evidence_records": sorted_evidence,
        "section_106b_certificate": cert_dict,
    }


def compute_forensic_dossier_digest(**kwargs: Any) -> str:
    """Computes SHA-256 digest over the canonical JSON representation of the dossier."""
    payload = forensic_dossier_payload(**kwargs)
    raw = canonical_json(payload).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass
class ForensicDossier:
    """Authoritative court-ready evidentiary package."""
    dossier_id: str
    case_id: str
    installation_id: str
    title: str
    incident_type: str
    fraud_loss_amount: float
    currency: str
    examiner_subject: str
    examiner_role: str
    created_at: datetime
    case_summary: str
    attack_path_summary: dict[str, Any]
    identified_mule_nodes: tuple[dict[str, Any], ...]
    evidence_records: tuple[dict[str, Any], ...]
    chain_of_custody: tuple[CustodyEvent, ...]
    section_106b_certificate: Section106BCertificate | None = None
    dossier_digest: str = ""
    signature_bundle: SignatureBundle | None = None

    def __post_init__(self) -> None:
        if not self.dossier_digest:
            self.dossier_digest = compute_forensic_dossier_digest(
                dossier_id=self.dossier_id,
                case_id=self.case_id,
                installation_id=self.installation_id,
                title=self.title,
                incident_type=self.incident_type,
                fraud_loss_amount=self.fraud_loss_amount,
                currency=self.currency,
                examiner_subject=self.examiner_subject,
                examiner_role=self.examiner_role,
                created_at=self.created_at,
                case_summary=self.case_summary,
                attack_path_summary=self.attack_path_summary,
                identified_mule_nodes=self.identified_mule_nodes,
                evidence_records=self.evidence_records,
                chain_of_custody=self.chain_of_custody,
                section_106b_certificate=self.section_106b_certificate,
            )

    def verify_dossier_integrity(self) -> bool:
        """Verifies constant-time hash integrity of all dossier contents."""
        computed = compute_forensic_dossier_digest(
            dossier_id=self.dossier_id,
            case_id=self.case_id,
            installation_id=self.installation_id,
            title=self.title,
            incident_type=self.incident_type,
            fraud_loss_amount=self.fraud_loss_amount,
            currency=self.currency,
            examiner_subject=self.examiner_subject,
            examiner_role=self.examiner_role,
            created_at=self.created_at,
            case_summary=self.case_summary,
            attack_path_summary=self.attack_path_summary,
            identified_mule_nodes=self.identified_mule_nodes,
            evidence_records=self.evidence_records,
            chain_of_custody=self.chain_of_custody,
            section_106b_certificate=self.section_106b_certificate,
        )
        return hmac.compare_digest(self.dossier_digest, computed)

    def sign(self, signer: LocalHSMKeyProvider) -> None:
        """Digitally signs the immutable dossier digest using the examiner's HSM key."""
        if not self.verify_dossier_integrity():
            raise ValueError("Cannot sign corrupted or tampered forensic dossier")
        data_to_sign = self.dossier_digest.encode("utf-8")
        self.signature_bundle = signer.sign(data_to_sign)

    def verify_digital_signature(self, trusted_public_key_pem: str | None = None) -> bool:
        """Verifies the asymmetric signature certifying non-repudiation."""
        if not self.signature_bundle:
            return False
        if not self.verify_dossier_integrity():
            return False
        data_signed = self.dossier_digest.encode("utf-8")
        return verify_asymmetric_signature(
            payload=data_signed,
            bundle=self.signature_bundle,
            trusted_public_key_pem=trusted_public_key_pem,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serializes the complete dossier including signatures and certificate."""
        payload = forensic_dossier_payload(
            dossier_id=self.dossier_id,
            case_id=self.case_id,
            installation_id=self.installation_id,
            title=self.title,
            incident_type=self.incident_type,
            fraud_loss_amount=self.fraud_loss_amount,
            currency=self.currency,
            examiner_subject=self.examiner_subject,
            examiner_role=self.examiner_role,
            created_at=self.created_at,
            case_summary=self.case_summary,
            attack_path_summary=self.attack_path_summary,
            identified_mule_nodes=self.identified_mule_nodes,
            evidence_records=self.evidence_records,
            chain_of_custody=self.chain_of_custody,
            section_106b_certificate=self.section_106b_certificate,
        )
        custody_dicts = [c.to_dict() for c in self.chain_of_custody]
        payload["chain_of_custody"] = sorted(custody_dicts, key=lambda c: str(c.get("timestamp", "")))
        payload["dossier_digest"] = self.dossier_digest
        payload["signature_bundle"] = self.signature_bundle.to_dict() if self.signature_bundle else None
        return payload

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ForensicDossier:
        """Reconstructs a ForensicDossier from serialized JSON/dict."""
        custody = tuple(
            CustodyEvent(
                event_id=c["event_id"],
                timestamp=datetime.fromisoformat(c["timestamp"]),
                actor_subject=c["actor_subject"],
                actor_role=c["actor_role"],
                action=c["action"],
                source_hash=c["source_hash"],
                destination_hash=c["destination_hash"],
                notes=c.get("notes", ""),
            )
            for c in data.get("chain_of_custody", [])
        )
        cert_data = data.get("section_106b_certificate")
        cert = (
            Section106BCertificate(
                certificate_id=cert_data["certificate_id"],
                statutory_framework=cert_data["statutory_framework"],
                certifier_name=cert_data["certifier_name"],
                certifier_designation=cert_data["certifier_designation"],
                certifier_organization=cert_data["certifier_organization"],
                device_identification=cert_data["device_identification"],
                operating_condition_statement=cert_data["operating_condition_statement"],
                hash_algorithm=cert_data["hash_algorithm"],
                merkle_root_hash=cert_data["merkle_root_hash"],
                certified_at=datetime.fromisoformat(cert_data["certified_at"]),
                declaration_text=cert_data["declaration_text"],
            )
            if cert_data
            else None
        )
        sig_data = data.get("signature_bundle")
        sig_bundle = (
            SignatureBundle.from_dict(sig_data)
            if sig_data
            else None
        )

        return cls(
            dossier_id=data["dossier_id"],
            case_id=data["case_id"],
            installation_id=data["installation_id"],
            title=data["title"],
            incident_type=data["incident_type"],
            fraud_loss_amount=float(data["fraud_loss_amount"]),
            currency=data["currency"],
            examiner_subject=data["examiner_subject"],
            examiner_role=data["examiner_role"],
            created_at=datetime.fromisoformat(data["created_at"]),
            case_summary=data["case_summary"],
            attack_path_summary=dict(data.get("attack_path_summary", {})),
            identified_mule_nodes=tuple(data.get("identified_mule_nodes", ())),
            evidence_records=tuple(data.get("evidence_records", ())),
            chain_of_custody=custody,
            section_106b_certificate=cert,
            dossier_digest=data.get("dossier_digest", ""),
            signature_bundle=sig_bundle,
        )

    def render_html_dossier(self) -> str:
        """Renders publication-grade, court-admissible HTML dossier with legal styling."""
        cert_html = ""
        if self.section_106b_certificate:
            c = self.section_106b_certificate
            cert_html = f"""
            <div class="legal-box certification-block">
                <h3>CERTIFICATE OF ELECTRONIC EVIDENCE</h3>
                <p class="statute-cite"><strong>Pursuant to:</strong> {html.escape(c.statutory_framework)}</p>
                <table class="meta-table">
                    <tr><th>Certificate ID:</th><td><code>{html.escape(c.certificate_id)}</code></td></tr>
                    <tr><th>Certifying Officer:</th><td>{html.escape(c.certifier_name)} ({html.escape(c.certifier_designation)})</td></tr>
                    <tr><th>Organization:</th><td>{html.escape(c.certifier_organization)}</td></tr>
                    <tr><th>Recording Device / System:</th><td><code>{html.escape(c.device_identification)}</code></td></tr>
                    <tr><th>Cryptographic Hash Algorithm:</th><td>{html.escape(c.hash_algorithm)}</td></tr>
                    <tr><th>Merkle Root Hash:</th><td><code>{html.escape(c.merkle_root_hash)}</code></td></tr>
                    <tr><th>Certification Timestamp:</th><td>{_canonical_utc(c.certified_at)}</td></tr>
                </table>
                <div class="declaration-text">
                    <p><strong>Operating Condition Affirmation:</strong> {html.escape(c.operating_condition_statement)}</p>
                    <p><strong>Solemn Declaration:</strong> {html.escape(c.declaration_text)}</p>
                </div>
            </div>
            """

        sig_html = ""
        if self.signature_bundle:
            s = self.signature_bundle
            sig_html = f"""
            <div class="legal-box signature-block">
                <h3>DIGITAL SIGNATURE & NON-REPUDIATION SEAL</h3>
                <table class="meta-table">
                    <tr><th>Algorithm:</th><td><code>{html.escape(s.algorithm)}</code></td></tr>
                    <tr><th>Key Identifier:</th><td><code>{html.escape(s.key_id)}</code></td></tr>
                    <tr><th>Timestamp (UTC):</th><td>{html.escape(str(s.signed_at))}</td></tr>
                    <tr><th>Signature Digest (Hex):</th><td><code class="break-word">{html.escape(s.signature_hex)}</code></td></tr>
                </table>
            </div>
            """
        else:
            sig_html = """
            <div class="legal-box signature-block warning">
                <h3>DIGITAL SIGNATURE STATUS</h3>
                <p><em>UNASSIGNED / PENDING HSM SIGNATURE (TAMPER-EVIDENT DIGEST ONLY)</em></p>
            </div>
            """

        mule_rows = "".join(
            f"<tr><td>{html.escape(str(m.get('account_number', 'N/A')))}</td>"
            f"<td>{html.escape(str(m.get('entity_name', 'Unknown')))}</td>"
            f"<td>{html.escape(str(m.get('risk_score', 'N/A')))}</td>"
            f"<td>{html.escape(str(m.get('role', 'Pass-Through Mule')))}</td></tr>"
            for m in self.identified_mule_nodes
        ) or "<tr><td colspan='4'>No distinct mule nodes identified.</td></tr>"

        custody_rows = "".join(
            f"<tr><td>{html.escape(_canonical_utc(c.timestamp))}</td>"
            f"<td>{html.escape(c.actor_subject)} ({html.escape(c.actor_role)})</td>"
            f"<td><strong>{html.escape(c.action)}</strong></td>"
            f"<td><code>{html.escape(c.destination_hash[:16])}...</code></td>"
            f"<td>{html.escape(c.notes)}</td></tr>"
            for c in self.chain_of_custody
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Evidence Dossier - {html.escape(self.dossier_id)}</title>
<style>
    body {{ font-family: 'Times New Roman', serif; font-size: 13pt; line-height: 1.5; color: #111; margin: 40px; }}
    .header {{ text-align: center; border-bottom: 2px solid #000; padding-bottom: 12px; margin-bottom: 24px; }}
    .header h1 {{ margin: 0; font-size: 18pt; text-transform: uppercase; letter-spacing: 1px; }}
    .header h2 {{ margin: 5px 0 0 0; font-size: 14pt; font-weight: normal; }}
    .header h3 {{ margin: 5px 0 0 0; font-size: 12pt; color: #444; }}
    .court-badge {{ margin-top: 8px; font-weight: bold; font-size: 11pt; letter-spacing: 0.5px; }}
    .legal-box {{ border: 1px solid #444; padding: 15px; margin: 20px 0; background-color: #fafafa; }}
    .legal-box h3 {{ margin-top: 0; border-bottom: 1px solid #999; padding-bottom: 6px; font-size: 13pt; }}
    .statute-cite {{ font-style: italic; color: #333; }}
    .meta-table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
    .meta-table th, .meta-table td {{ text-align: left; padding: 6px; vertical-align: top; border-bottom: 1px dotted #ccc; font-size: 11pt; }}
    .meta-table th {{ width: 28%; font-weight: bold; color: #222; }}
    .break-word {{ word-break: break-all; }}
    .data-table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
    .data-table th, .data-table td {{ border: 1px solid #777; padding: 6px 10px; font-size: 11pt; text-align: left; }}
    .data-table th {{ background-color: #eee; font-weight: bold; }}
    .declaration-text {{ margin-top: 15px; font-style: italic; font-size: 11pt; }}
    .digest-banner {{ background-color: #f0f4f8; border-left: 4px solid #0f4c81; padding: 10px; margin: 15px 0; }}
    .digest-banner code {{ font-size: 11pt; }}
    @media print {{ body {{ margin: 20mm; font-size: 11pt; }} }}
</style>
</head>
<body>
<div class="header">
    <h1>REPUBLIC OF KENYA</h1>
    <h2>BANKING FRAUD INVESTIGATIONS UNIT & FINANCIAL CRIME COMPLIANCE</h2>
    <h3>IN THE HIGH COURT OF KENYA (ANTI-CORRUPTION & ECONOMIC CRIMES DIVISION)</h3>
    <div class="court-badge">EXHIBIT DOSSIER NO: {html.escape(self.dossier_id)} | CASE FILE REF: {html.escape(self.case_id)}</div>
</div>

<div class="digest-banner">
    <strong>IMMUTABLE CANONICAL DOSSIER SHA-256 DIGEST:</strong><br>
    <code class="break-word">{html.escape(self.dossier_digest)}</code>
</div>

<table class="meta-table">
    <tr><th>Incident Title:</th><td><strong>{html.escape(self.title)}</strong></td></tr>
    <tr><th>Incident Classification:</th><td>{html.escape(self.incident_type)}</td></tr>
    <tr><th>Quantified Financial Loss:</th><td><strong>{self.currency} {self.fraud_loss_amount:,.2f}</strong></td></tr>
    <tr><th>Lead Forensic Examiner:</th><td>{html.escape(self.examiner_subject)} ({html.escape(self.examiner_role)})</td></tr>
    <tr><th>Installation Sovereign ID:</th><td><code>{html.escape(self.installation_id)}</code></td></tr>
    <tr><th>Dossier Compilation Date:</th><td>{_canonical_utc(self.created_at)}</td></tr>
</table>

<div class="legal-box">
    <h3>EXECUTIVE INVESTIGATION FINDINGS</h3>
    <p>{html.escape(self.case_summary)}</p>
</div>

<div class="legal-box">
    <h3>IDENTIFIED MULE ACCOUNTS & HIGH-RISK COUNTERPARTIES</h3>
    <table class="data-table">
        <thead>
            <tr><th>Account Number</th><th>Entity Name</th><th>Risk Score</th><th>Assigned Role</th></tr>
        </thead>
        <tbody>
            {mule_rows}
        </tbody>
    </table>
</div>

{cert_html}

{sig_html}

<div class="legal-box">
    <h3>CHAIN OF CUSTODY AUDIT LOG</h3>
    <table class="data-table">
        <thead>
            <tr><th>Timestamp (UTC)</th><th>Custodian / Examiner</th><th>Action</th><th>Target State Hash</th><th>Notes</th></tr>
        </thead>
        <tbody>
            {custody_rows}
        </tbody>
    </table>
</div>

</body>
</html>
"""
