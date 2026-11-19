"""Investigation service orchestrating evidence graphs, money flow, and referral packs."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from toroka_enterprise.investigation.contracts import (
    EntityIn,
    EntityKind,
    EntityOut,
    EvidenceArtifactIn,
    EvidenceArtifactOut,
    EvidenceSourceType,
    EvidenceState,
    FindingIn,
    FindingOut,
    GraphQueryResponse,
    RelationshipIn,
    RelationshipOut,
    TimelineEventOut,
    TimelineResponse,
    TransactionEventIn,
    TransactionEventOut,
)
from toroka_enterprise.investigation.evidence import sha256_bytes, verify_evidence_bytes
from toroka_enterprise.investigation.money_flow import reconstruct_money_flow
from toroka_enterprise.investigation.referral_pack import ReferralPackBuilder
from toroka_enterprise.investigation.rules import InstitutionPolicyProfile, InvestigationRuleEngine
from ..auth import EnterprisePrincipal
from ..persistence.audit import append_audit
from ..persistence.models import (
    EnterpriseCase,
    InvestigationEntity,
    InvestigationEvidenceArtifact,
    InvestigationFinding,
    InvestigationRelationship,
    InvestigationTransaction,
    ReferralPackRecord,
)


class InvestigationService:
    def __init__(self, session: Session, audit_repo: AuditRepository | None = None) -> None:
        self.session = session
        self.audit_repo = audit_repo
        self.rule_engine = InvestigationRuleEngine()

    def _verify_case_access(self, installation_id: str, case_id: str) -> EnterpriseCase:
        stmt = select(EnterpriseCase).where(
            EnterpriseCase.installation_id == installation_id,
            EnterpriseCase.id == case_id,
        )
        case = self.session.execute(stmt).scalar_one_or_none()
        if case is None:
            raise LookupError(f"Case {case_id} not found in installation {installation_id}")
        return case

    # --- Evidence Ingestion ---
    def add_evidence(
        self,
        principal: EnterprisePrincipal,
        installation_id: str,
        case_id: str,
        payload: EvidenceArtifactIn,
    ) -> EvidenceArtifactOut:
        self._verify_case_access(installation_id, case_id)
        ev_id = str(uuid4())

        record = InvestigationEvidenceArtifact(
            id=ev_id,
            installation_id=installation_id,
            case_id=case_id,
            source_type=payload.source_type.value,
            source_system=payload.source_system,
            source_record_ref=payload.source_record_ref,
            source_locator_ciphertext=payload.source_locator_ciphertext,
            observed_at=payload.observed_at,
            collected_at=payload.collected_at,
            collected_by=payload.collected_by,
            source_timezone=payload.source_timezone,
            sha256=payload.sha256,
            media_type=payload.media_type,
            extractor_name=payload.extractor_name,
            extractor_version=payload.extractor_version,
            state="observed",
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)

        try:
            append_audit(
                self.session,
                installation_id=installation_id,
                actor_subject=principal.subject,
                actor_role=principal.roles[0] if principal.roles else "investigator",
                action="evidence.ingested",
                target_type="evidence_artifact",
                target_id=ev_id,
                safe_metadata={
                    "case_id": case_id,
                    "sha256": payload.sha256,
                    "source_type": payload.source_type.value,
                },
            )
        except Exception:
            pass

        return EvidenceArtifactOut(
            id=UUID(record.id),
            installation_id=record.installation_id,
            case_id=UUID(record.case_id),
            source_type=EvidenceSourceType(record.source_type),
            source_system=record.source_system,
            source_record_ref=record.source_record_ref,
            observed_at=record.observed_at,
            collected_at=record.collected_at,
            collected_by=record.collected_by,
            source_timezone=record.source_timezone,
            sha256=record.sha256,
            media_type=record.media_type,
            extractor_name=record.extractor_name,
            extractor_version=record.extractor_version,
            state=EvidenceState(record.state),
            created_at=record.created_at,
        )

    # --- Entity Registration ---
    def add_entity(
        self,
        principal: EnterprisePrincipal,
        installation_id: str,
        case_id: str,
        payload: EntityIn,
    ) -> EntityOut:
        self._verify_case_access(installation_id, case_id)

        # Check existing entity with same identifier_token
        existing = self.session.execute(
            select(InvestigationEntity).where(
                InvestigationEntity.installation_id == installation_id,
                InvestigationEntity.case_id == case_id,
                InvestigationEntity.identifier_token == payload.identifier_token,
            )
        ).scalar_one_or_none()

        if existing:
            return EntityOut(
                id=UUID(existing.id),
                installation_id=existing.installation_id,
                case_id=UUID(existing.case_id),
                kind=EntityKind(existing.kind),
                identifier_token=existing.identifier_token,
                display_label=existing.display_label,
                first_seen_at=existing.first_seen_at,
                last_seen_at=existing.last_seen_at,
                sensitivity=existing.sensitivity,
                created_at=existing.created_at,
            )

        ent_id = str(uuid4())
        record = InvestigationEntity(
            id=ent_id,
            installation_id=installation_id,
            case_id=case_id,
            kind=payload.kind.value,
            identifier_token=payload.identifier_token,
            display_label=payload.display_label,
            first_seen_at=payload.first_seen_at,
            last_seen_at=payload.last_seen_at,
            sensitivity=payload.sensitivity,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)

        return EntityOut(
            id=UUID(record.id),
            installation_id=record.installation_id,
            case_id=UUID(record.case_id),
            kind=EntityKind(record.kind),
            identifier_token=record.identifier_token,
            display_label=record.display_label,
            first_seen_at=record.first_seen_at,
            last_seen_at=record.last_seen_at,
            sensitivity=record.sensitivity,
            created_at=record.created_at,
        )

    # --- Relationship ---
    def add_relationship(
        self,
        principal: EnterprisePrincipal,
        installation_id: str,
        case_id: str,
        payload: RelationshipIn,
    ) -> RelationshipOut:
        self._verify_case_access(installation_id, case_id)

        # Verify evidence records exist in this installation and case
        ev_str_ids = [str(eid) for eid in payload.evidence_ids]
        found_ev = self.session.execute(
            select(InvestigationEvidenceArtifact.id).where(
                InvestigationEvidenceArtifact.installation_id == installation_id,
                InvestigationEvidenceArtifact.case_id == case_id,
                InvestigationEvidenceArtifact.id.in_(ev_str_ids),
                InvestigationEvidenceArtifact.state != "revoked",
            )
        ).scalars().all()

        if len(found_ev) != len(payload.evidence_ids):
            raise ValueError("All cited evidence IDs must exist, be unrevoked, and belong to this case.")

        rel_id = str(uuid4())
        record = InvestigationRelationship(
            id=rel_id,
            installation_id=installation_id,
            case_id=case_id,
            source_entity_id=str(payload.source_entity_id),
            target_entity_id=str(payload.target_entity_id),
            relationship_type=payload.relationship_type,
            state=payload.state.value,
            evidence_ids=[str(e) for e in payload.evidence_ids],
            valid_from=payload.valid_from,
            valid_to=payload.valid_to,
            explanation=payload.explanation,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)

        return RelationshipOut(
            id=UUID(record.id),
            installation_id=record.installation_id,
            case_id=UUID(record.case_id),
            source_entity_id=UUID(record.source_entity_id),
            target_entity_id=UUID(record.target_entity_id),
            relationship_type=record.relationship_type,
            state=EvidenceState(record.state),
            evidence_ids=[UUID(e) for e in record.evidence_ids],
            valid_from=record.valid_from,
            valid_to=record.valid_to,
            explanation=record.explanation,
            created_at=record.created_at,
        )

    # --- Transactions ---
    def add_transaction(
        self,
        principal: EnterprisePrincipal,
        installation_id: str,
        case_id: str,
        payload: TransactionEventIn,
    ) -> TransactionEventOut:
        self._verify_case_access(installation_id, case_id)

        # Verify evidence exists and is not revoked
        ev = self.session.execute(
            select(InvestigationEvidenceArtifact).where(
                InvestigationEvidenceArtifact.installation_id == installation_id,
                InvestigationEvidenceArtifact.case_id == case_id,
                InvestigationEvidenceArtifact.id == str(payload.evidence_id),
                InvestigationEvidenceArtifact.state != "revoked",
            )
        ).scalar_one_or_none()
        if ev is None:
            raise ValueError(f"Evidence {payload.evidence_id} not found or revoked.")

        tx_id = str(uuid4())
        record = InvestigationTransaction(
            id=tx_id,
            installation_id=installation_id,
            case_id=case_id,
            source_entity_id=str(payload.source_entity_id),
            destination_entity_id=str(payload.destination_entity_id),
            amount=payload.amount,
            currency=payload.currency,
            occurred_at=payload.occurred_at,
            source_timezone=payload.source_timezone,
            channel=payload.channel,
            source_system=payload.source_system,
            source_record_ref=payload.source_record_ref,
            evidence_id=str(payload.evidence_id),
            reference_token=payload.reference_token,
            event_type=payload.event_type,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)

        return TransactionEventOut(
            id=UUID(record.id),
            installation_id=record.installation_id,
            case_id=UUID(record.case_id),
            source_entity_id=UUID(record.source_entity_id),
            destination_entity_id=UUID(record.destination_entity_id),
            amount=record.amount,
            currency=record.currency,
            occurred_at=record.occurred_at,
            source_timezone=record.source_timezone,
            channel=record.channel,
            source_system=record.source_system,
            source_record_ref=record.source_record_ref,
            evidence_id=UUID(record.evidence_id),
            reference_token=record.reference_token,
            event_type=record.event_type,
            created_at=record.created_at,
        )

    # --- Graph Query ---
    def get_case_graph(
        self,
        installation_id: str,
        case_id: str,
        max_hops: int = 3,
        max_nodes: int = 50,
    ) -> GraphQueryResponse:
        self._verify_case_access(installation_id, case_id)

        entities_orm = self.session.execute(
            select(InvestigationEntity)
            .where(
                InvestigationEntity.installation_id == installation_id,
                InvestigationEntity.case_id == case_id,
            )
            .limit(max_nodes)
        ).scalars().all()

        entity_ids = {e.id for e in entities_orm}

        relationships_orm = self.session.execute(
            select(InvestigationRelationship)
            .where(
                InvestigationRelationship.installation_id == installation_id,
                InvestigationRelationship.case_id == case_id,
                InvestigationRelationship.source_entity_id.in_(entity_ids),
                InvestigationRelationship.target_entity_id.in_(entity_ids),
                InvestigationRelationship.state != "revoked",
            )
        ).scalars().all()

        entities_out = [
            EntityOut(
                id=UUID(e.id),
                installation_id=e.installation_id,
                case_id=UUID(e.case_id),
                kind=EntityKind(e.kind),
                identifier_token=e.identifier_token,
                display_label=e.display_label,
                first_seen_at=e.first_seen_at,
                last_seen_at=e.last_seen_at,
                sensitivity=e.sensitivity,
                created_at=e.created_at,
            )
            for e in entities_orm
        ]

        relationships_out = [
            RelationshipOut(
                id=UUID(r.id),
                installation_id=r.installation_id,
                case_id=UUID(r.case_id),
                source_entity_id=UUID(r.source_entity_id),
                target_entity_id=UUID(r.target_entity_id),
                relationship_type=r.relationship_type,
                state=EvidenceState(r.state),
                evidence_ids=[UUID(eid) for eid in r.evidence_ids],
                valid_from=r.valid_from,
                valid_to=r.valid_to,
                explanation=r.explanation,
                created_at=r.created_at,
            )
            for r in relationships_orm
        ]

        return GraphQueryResponse(
            installation_id=installation_id,
            case_id=UUID(case_id),
            entities=entities_out,
            relationships=relationships_out,
            hop_limit=max_hops,
            node_limit=max_nodes,
            truncated=(len(entities_orm) >= max_nodes),
        )

    # --- Run Findings ---
    def run_findings(
        self,
        principal: EnterprisePrincipal,
        installation_id: str,
        case_id: str,
    ) -> list[FindingOut]:
        self._verify_case_access(installation_id, case_id)

        txs = self.session.execute(
            select(InvestigationTransaction).where(
                InvestigationTransaction.installation_id == installation_id,
                InvestigationTransaction.case_id == case_id,
            )
        ).scalars().all()

        rels = self.session.execute(
            select(InvestigationRelationship).where(
                InvestigationRelationship.installation_id == installation_id,
                InvestigationRelationship.case_id == case_id,
                InvestigationRelationship.state != "revoked",
            )
        ).scalars().all()

        evs = self.session.execute(
            select(InvestigationEvidenceArtifact).where(
                InvestigationEvidenceArtifact.installation_id == installation_id,
                InvestigationEvidenceArtifact.case_id == case_id,
                InvestigationEvidenceArtifact.state != "revoked",
            )
        ).scalars().all()

        generated = self.rule_engine.evaluate_case(
            transactions=list(txs),
            relationships=list(rels),
            evidence_items=list(evs),
        )

        persisted: list[FindingOut] = []
        for f in generated:
            f_id = str(uuid4())
            rec = InvestigationFinding(
                id=f_id,
                installation_id=installation_id,
                case_id=case_id,
                rule_id=f.rule_id,
                rule_version=f.rule_version,
                title=f.title,
                explanation=f.explanation,
                state=f.state.value,
                evidence_ids=[str(e) for e in f.evidence_ids],
                counter_evidence_ids=[str(e) for e in f.counter_evidence_ids],
                unresolved_questions=f.unresolved_questions,
                recommended_human_action=f.recommended_human_action,
            )
            self.session.add(rec)
            self.session.commit()
            self.session.refresh(rec)

            persisted.append(
                FindingOut(
                    id=UUID(rec.id),
                    installation_id=rec.installation_id,
                    case_id=UUID(rec.case_id),
                    rule_id=rec.rule_id,
                    rule_version=rec.rule_version,
                    title=rec.title,
                    explanation=rec.explanation,
                    state=EvidenceState(rec.state),
                    evidence_ids=[UUID(e) for e in rec.evidence_ids],
                    counter_evidence_ids=[UUID(e) for e in rec.counter_evidence_ids],
                    unresolved_questions=rec.unresolved_questions,
                    recommended_human_action=rec.recommended_human_action,
                    created_at=rec.created_at,
                )
            )

        return persisted

    # --- Timeline ---
    def get_timeline(
        self,
        installation_id: str,
        case_id: str,
    ) -> TimelineResponse:
        self._verify_case_access(installation_id, case_id)

        txs = self.session.execute(
            select(InvestigationTransaction).where(
                InvestigationTransaction.installation_id == installation_id,
                InvestigationTransaction.case_id == case_id,
            )
        ).scalars().all()

        evs = self.session.execute(
            select(InvestigationEvidenceArtifact).where(
                InvestigationEvidenceArtifact.installation_id == installation_id,
                InvestigationEvidenceArtifact.case_id == case_id,
            )
        ).scalars().all()

        events: list[TimelineEventOut] = []
        for t in txs:
            events.append(
                TimelineEventOut(
                    event_id=t.id,
                    event_type=f"TRANSACTION_{t.event_type.upper()}",
                    timestamp=t.occurred_at,
                    source_timezone=t.source_timezone,
                    source_system=t.source_system,
                    source_record_ref=t.source_record_ref,
                    evidence_id=UUID(t.evidence_id),
                    summary=f"{t.event_type.capitalize()} of {t.amount} {t.currency} via {t.channel}",
                    confidence_state="observed",
                    details={"amount": str(t.amount), "currency": t.currency, "channel": t.channel},
                )
            )

        for e in evs:
            events.append(
                TimelineEventOut(
                    event_id=e.id,
                    event_type=f"EVIDENCE_{e.source_type.upper()}",
                    timestamp=e.observed_at,
                    source_timezone=e.source_timezone,
                    source_system=e.source_system,
                    source_record_ref=e.source_record_ref,
                    evidence_id=UUID(e.id),
                    summary=f"Evidence observed from {e.source_system} ({e.source_type})",
                    confidence_state=e.state,
                    details={"sha256": e.sha256, "collected_by": e.collected_by},
                )
            )

        events.sort(key=lambda x: x.timestamp)

        return TimelineResponse(
            installation_id=installation_id,
            case_id=UUID(case_id),
            events=events,
            total_events=len(events),
        )

    # --- Money Flow ---
    def get_money_flow(
        self,
        installation_id: str,
        case_id: str,
        root_entity_id: UUID,
        max_hops: int = 5,
        max_nodes: int = 50,
    ) -> dict[str, Any]:
        self._verify_case_access(installation_id, case_id)

        txs = self.session.execute(
            select(InvestigationTransaction).where(
                InvestigationTransaction.installation_id == installation_id,
                InvestigationTransaction.case_id == case_id,
            )
        ).scalars().all()

        flow = reconstruct_money_flow(
            transactions=list(txs),
            root_entity_id=root_entity_id,
            max_hops=max_hops,
            max_nodes=max_nodes,
        )
        return flow.to_dict()

    # --- Referral Pack Preview & Approval ---
    def preview_referral_pack(
        self,
        principal: EnterprisePrincipal,
        installation_id: str,
        case_id: str,
        recipient_org: str,
        purpose: str,
        legal_basis: str,
    ) -> dict[str, Any]:
        case = self._verify_case_access(installation_id, case_id)
        pack_id = uuid4()

        txs = self.session.execute(
            select(InvestigationTransaction).where(
                InvestigationTransaction.installation_id == installation_id,
                InvestigationTransaction.case_id == case_id,
            )
        ).scalars().all()

        entities = self.session.execute(
            select(InvestigationEntity).where(
                InvestigationEntity.installation_id == installation_id,
                InvestigationEntity.case_id == case_id,
            )
        ).scalars().all()

        rels = self.session.execute(
            select(InvestigationRelationship).where(
                InvestigationRelationship.installation_id == installation_id,
                InvestigationRelationship.case_id == case_id,
                InvestigationRelationship.state != "revoked",
            )
        ).scalars().all()

        findings = self.session.execute(
            select(InvestigationFinding).where(
                InvestigationFinding.installation_id == installation_id,
                InvestigationFinding.case_id == case_id,
            )
        ).scalars().all()

        evs = self.session.execute(
            select(InvestigationEvidenceArtifact).where(
                InvestigationEvidenceArtifact.installation_id == installation_id,
                InvestigationEvidenceArtifact.case_id == case_id,
                InvestigationEvidenceArtifact.state != "revoked",
            )
        ).scalars().all()

        case_summary = {
            "case_id": case.id,
            "installation_id": case.installation_id,
            "label": case.label,
            "focus": case.focus,
            "status": case.status,
            "created_by": case.created_by,
            "created_at": case.created_at.isoformat(),
        }

        files = ReferralPackBuilder.build_package_files(
            pack_id=pack_id,
            case_id=UUID(case_id),
            installation_id=installation_id,
            case_summary=case_summary,
            entities=[
                {
                    "id": e.id,
                    "kind": e.kind,
                    "identifier_token": e.identifier_token,
                    "display_label": e.display_label,
                    "first_seen_at": e.first_seen_at.isoformat(),
                    "last_seen_at": e.last_seen_at.isoformat(),
                    "sensitivity": e.sensitivity,
                }
                for e in entities
            ],
            relationships=[
                {
                    "id": r.id,
                    "source_entity_id": r.source_entity_id,
                    "target_entity_id": r.target_entity_id,
                    "relationship_type": r.relationship_type,
                    "state": r.state,
                    "explanation": r.explanation,
                }
                for r in rels
            ],
            transactions=[
                {
                    "id": t.id,
                    "source_entity_id": t.source_entity_id,
                    "destination_entity_id": t.destination_entity_id,
                    "amount": str(t.amount),
                    "currency": t.currency,
                    "occurred_at": t.occurred_at.isoformat(),
                    "channel": t.channel,
                    "event_type": t.event_type,
                    "evidence_id": t.evidence_id,
                }
                for t in txs
            ],
            findings=[
                {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "rule_version": f.rule_version,
                    "title": f.title,
                    "explanation": f.explanation,
                    "state": f.state,
                    "evidence_ids": f.evidence_ids,
                    "counter_evidence_ids": f.counter_evidence_ids,
                    "unresolved_questions": f.unresolved_questions,
                    "recommended_human_action": f.recommended_human_action,
                }
                for f in findings
            ],
            evidence_index=[
                {
                    "id": ev.id,
                    "source_type": ev.source_type,
                    "source_system": ev.source_system,
                    "source_record_ref": ev.source_record_ref,
                    "sha256": ev.sha256,
                    "collected_by": ev.collected_by,
                    "observed_at": ev.observed_at.isoformat(),
                    "collected_at": ev.collected_at.isoformat(),
                }
                for ev in evs
            ],
            generating_principal=principal.subject,
            recipient_org=recipient_org,
            purpose=purpose,
            legal_basis=legal_basis,
        )

        pack_hash = ReferralPackBuilder.compute_overall_pack_hash(files)
        manifest_data = json.loads(files["manifest.json"].decode("utf-8"))

        rec = ReferralPackRecord(
            id=str(pack_id),
            installation_id=installation_id,
            case_id=case_id,
            status="preview",
            pack_hash=pack_hash,
            recipient_org=recipient_org,
            purpose=purpose,
            legal_basis=legal_basis,
            generating_principal=principal.subject,
            approving_principals=[],
            manifest_data=manifest_data,
        )
        self.session.add(rec)
        self.session.commit()
        self.session.refresh(rec)

        try:
            append_audit(
                self.session,
                installation_id=installation_id,
                actor_subject=principal.subject,
                actor_role=principal.roles[0] if principal.roles else "investigator",
                action="referral_pack.previewed",
                target_type="referral_pack",
                target_id=str(pack_id),
                safe_metadata={
                    "case_id": case_id,
                    "pack_hash": pack_hash,
                    "recipient_org": recipient_org,
                },
            )
        except Exception:
            pass

        return {
            "pack_id": str(pack_id),
            "pack_hash": pack_hash,
            "status": "preview",
            "manifest": manifest_data,
            "file_names": sorted(list(files.keys())),
        }

    def approve_referral_pack(
        self,
        principal: EnterprisePrincipal,
        installation_id: str,
        case_id: str,
        pack_id: str,
        expected_pack_hash: str,
    ) -> dict[str, Any]:
        self._verify_case_access(installation_id, case_id)

        rec = self.session.execute(
            select(ReferralPackRecord).where(
                ReferralPackRecord.installation_id == installation_id,
                ReferralPackRecord.case_id == case_id,
                ReferralPackRecord.id == pack_id,
            )
        ).scalar_one_or_none()

        if rec is None:
            raise LookupError(f"Referral pack {pack_id} not found in case {case_id}")

        if rec.status != "preview":
            raise ValueError(f"Referral pack is already in status {rec.status}")

        if rec.pack_hash != expected_pack_hash:
            raise PermissionError(
                "Pack hash mismatch! The referral package contents or metadata have been modified "
                "since the preview was generated. Approval is invalid."
            )

        # Dual-approver verification: generator cannot be sole approver
        if rec.generating_principal == principal.subject and "investigator" in principal.roles and "authoriser" not in principal.roles:
            raise PermissionError("Secondary authoriser approval required; generator cannot approve own pack alone.")

        now = datetime.now(timezone.utc)
        rec.status = "approved"
        rec.approved_at = now
        rec.approving_principals = list(rec.approving_principals or []) + [principal.subject]

        manifest = dict(rec.manifest_data)
        manifest["approving_principals"] = rec.approving_principals
        rec.manifest_data = manifest

        self.session.commit()
        self.session.refresh(rec)

        try:
            append_audit(
                self.session,
                installation_id=installation_id,
                actor_subject=principal.subject,
                actor_role=principal.roles[0] if principal.roles else "authoriser",
                action="referral_pack.approved",
                target_type="referral_pack",
                target_id=pack_id,
                safe_metadata={
                    "case_id": case_id,
                    "pack_hash": rec.pack_hash,
                    "approver": principal.subject,
                },
            )
        except Exception:
            pass

        return {
            "pack_id": rec.id,
            "status": rec.status,
            "pack_hash": rec.pack_hash,
            "approving_principals": rec.approving_principals,
            "approved_at": rec.approved_at.isoformat() if rec.approved_at else None,
            "manifest": rec.manifest_data,
        }

    def get_referral_pack(
        self,
        installation_id: str,
        pack_id: str,
    ) -> dict[str, Any]:
        rec = self.session.execute(
            select(ReferralPackRecord).where(
                ReferralPackRecord.installation_id == installation_id,
                ReferralPackRecord.id == pack_id,
            )
        ).scalar_one_or_none()

        if rec is None:
            raise LookupError(f"Referral pack {pack_id} not found in installation {installation_id}")

        return {
            "pack_id": rec.id,
            "case_id": rec.case_id,
            "installation_id": rec.installation_id,
            "status": rec.status,
            "pack_hash": rec.pack_hash,
            "recipient_org": rec.recipient_org,
            "purpose": rec.purpose,
            "legal_basis": rec.legal_basis,
            "generating_principal": rec.generating_principal,
            "approving_principals": rec.approving_principals,
            "manifest": rec.manifest_data,
            "created_at": rec.created_at.isoformat(),
            "approved_at": rec.approved_at.isoformat() if rec.approved_at else None,
        }
