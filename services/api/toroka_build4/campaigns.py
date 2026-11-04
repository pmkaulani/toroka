from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session
from ssi_rules import normalize as nz
from ssi_rules.fingerprint import similarity

from app import db as m
from toroka_phase6.image_intelligence import hamming_distance


IMAGE_CONSENT_SCOPE = "cross_case_campaign"
IMAGE_HAMMING_THRESHOLD = 6
MAX_INDEXED_IMAGES = 600
MAX_REPORTS_FOR_CLUSTERING = 350


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _campaign_id(kind: str, fingerprint: str) -> str:
    return "cmp_" + hashlib.sha256(f"{kind}:{fingerprint}".encode()).hexdigest()[:20]


def _extract_subjects(text: str, crypto) -> list[dict[str, str]]:
    """Extract only public identifiers, then immediately HMAC them for lookup."""
    found: dict[tuple[str, str], dict[str, str]] = {}

    def add(kind: str, value: str, masked: str | None = None) -> None:
        if not value:
            return
        normalized = value.strip().casefold()
        digest = crypto.lookup(kind, normalized)
        found[(kind, digest)] = {
            "kind": kind,
            "lookup_hmac": digest,
            "masked": masked or (normalized[:3] + "••••" + normalized[-3:] if len(normalized) > 8 else "••••"),
        }

    for phone in nz.extract_phones(text or "")[:8]:
        add("phone", phone.normalized, nz.mask_phone(phone.normalized))

    for payment in nz.extract_payment_ids(text or "")[:8]:
        kind, _, number = payment.normalized.partition(":")
        if kind in {"till", "paybill"} and number.isdigit():
            add(kind, number, f"{kind.title()} ••{number[-3:]}")

    for parsed in nz.extract_urls(text or "")[:12]:
        host = (parsed.registered_domain or "").lower()
        if host and not parsed.is_ip and host not in {"instagram.com", "tiktok.com", "facebook.com", "x.com", "twitter.com", "whatsapp.com"}:
            add("domain", host, host)

    social_pattern = re.compile(r"(?i)(?:https?://)?(?:www\.)?(instagram|tiktok|facebook|x|twitter)\.com/@?([a-z0-9_.-]{2,50})")
    for match in social_pattern.finditer(text or ""):
        platform = "x" if match.group(1).lower() == "twitter" else match.group(1).lower()
        handle = match.group(2).strip(".").lower()
        if handle not in {"p", "reel", "reels", "stories", "explore", "login", "share"}:
            add("handle", f"{platform}:{handle}", f"@{handle} ({platform})")

    return list(found.values())[:24]


def _published_indicator_context(db: Session, identifiers: list[dict[str, str]]) -> dict[str, Any]:
    if not identifiers:
        return {"matched_indicators": [], "related_identifiers": []}

    digest_pairs = [(item["kind"], item["lookup_hmac"]) for item in identifiers]
    current_rows = db.execute(
        select(m.Subject, m.Indicator)
        .join(m.Indicator, m.Indicator.subject_id == m.Subject.id)
        .where(m.Indicator.status == "published")
        .where(m.Subject.lookup_hmac.in_([digest for _, digest in digest_pairs]))
        .where(m.Subject.subject_type.in_([kind for kind, _ in digest_pairs]))
    ).all()
    # Enforce the composite type + HMAC match; same digest in a different namespace is not a match.
    wanted = {(kind, digest) for kind, digest in digest_pairs}
    current = [(subject, indicator) for subject, indicator in current_rows if (subject.subject_type, subject.lookup_hmac) in wanted]
    if not current:
        return {"matched_indicators": [], "related_identifiers": []}

    matched = []
    source_subject_ids = [subject.id for subject, _ in current]
    for subject, indicator in current[:12]:
        matched.append({
            "kind": subject.subject_type,
            "masked_value": subject.display_masked,
            "independent_reports": int(indicator.independent_reports or 0),
            "last_reported": indicator.last_reported,
            "status": "published_indicator",
            "interpretation": "This exact identifier has a moderated public indicator. It is not a conclusion about every account or business using it.",
        })

    cutoff = (_now() - timedelta(days=365)).isoformat()
    report_rows = db.execute(
        select(m.Report, m.ReportSubject.subject_id)
        .join(m.ReportSubject, m.ReportSubject.report_id == m.Report.id)
        .where(m.ReportSubject.subject_id.in_(source_subject_ids))
        .where(m.Report.moderation_status == "approved")
        .where(m.Report.created_at >= cutoff)
        .limit(1200)
    ).all()
    report_map: dict[str, m.Report] = {}
    subject_to_reporters: dict[str, set[str]] = defaultdict(set)
    for report, subject_id in report_rows:
        report_map[report.id] = report
        subject_to_reporters[subject_id].add(report.reporter_key)
    report_ids = list(report_map)
    if not report_ids:
        return {"matched_indicators": matched, "related_identifiers": []}

    related_rows = db.execute(
        select(m.ReportSubject.report_id, m.Subject, m.Indicator)
        .join(m.Subject, m.Subject.id == m.ReportSubject.subject_id)
        .join(m.Indicator, m.Indicator.subject_id == m.Subject.id)
        .where(m.ReportSubject.report_id.in_(report_ids))
        .where(m.Indicator.status == "published")
    ).all()
    grouped: dict[str, dict[str, Any]] = {}
    source_set = set(source_subject_ids)
    for report_id, other_subject, other_indicator in related_rows:
        if other_subject.id in source_set:
            continue
        record = grouped.setdefault(other_subject.id, {
            "kind": other_subject.subject_type,
            "masked_value": other_subject.display_masked,
            "report_ids": set(),
            "reporters": set(),
            "dates": [],
        })
        report = report_map.get(report_id)
        if not report:
            continue
        record["report_ids"].add(report_id)
        record["reporters"].add(report.reporter_key)
        record["dates"].append(report.incident_date or report.created_at[:10])

    related = []
    for record in grouped.values():
        if len(record["reporters"]) < 2:
            continue
        dates = sorted(record["dates"])
        related.append({
            "kind": record["kind"],
            "masked_value": record["masked_value"],
            "independent_reports": len(record["reporters"]),
            "shared_reviewed_reports": len(record["report_ids"]),
            "first_seen": dates[0] if dates else None,
            "last_seen": dates[-1] if dates else None,
            "relationship": "appeared_together_in_independently_reported_moderated_cases",
            "risk_propagation": "never_automatic",
        })
    related.sort(key=lambda item: (-item["shared_reviewed_reports"], item["kind"], item["masked_value"]))
    return {"matched_indicators": matched, "related_identifiers": related[:12]}


def _image_reuse_context(db: Session, check: m.Check, current_hashes: list[str]) -> dict[str, Any] | None:
    # Both sides must opt in. A current upload left at the default check-only
    # scope is never searched against the cross-case fingerprint index.
    opted_in_rows = db.execute(
        select(m.EvidenceFile.dhash)
        .where(m.EvidenceFile.check_id == check.id)
        .where(m.EvidenceFile.consent_scope == IMAGE_CONSENT_SCOPE)
    ).scalars().all()
    allowed_hashes = set(opted_in_rows)
    hashes = [value for value in current_hashes if re.fullmatch(r"[0-9a-fA-F]{16}", value or "") and value in allowed_hashes]
    if not hashes:
        return None
    now_iso = m.now_iso()
    stmt = (
        select(m.EvidenceFile, m.Check)
        .join(m.Check, m.Check.id == m.EvidenceFile.check_id)
        .where(m.EvidenceFile.consent_scope == IMAGE_CONSENT_SCOPE)
        .where(m.EvidenceFile.retention_until > now_iso)
        .where(m.Check.expires_at > now_iso)
        .where(m.EvidenceFile.check_id != check.id)
        .order_by(m.EvidenceFile.created_at.desc())
        .limit(MAX_INDEXED_IMAGES)
    )
    if check.user_id:
        stmt = stmt.where(m.Check.user_id != check.user_id)
    previous = db.execute(stmt).all()

    match_cases: dict[str, dict[str, Any]] = {}
    for current_hash in hashes:
        for stored, prior_check in previous:
            try:
                distance = hamming_distance(current_hash.lower(), stored.dhash.lower())
            except (TypeError, ValueError):
                continue
            exact = distance == 0
            if exact or distance <= IMAGE_HAMMING_THRESHOLD:
                current = match_cases.setdefault(prior_check.id, {"best_distance": distance, "exact": exact})
                current["best_distance"] = min(current["best_distance"], distance)
                current["exact"] = current["exact"] or exact

    if not match_cases:
        return {"status": "no_match_found", "matching_opted_in_checks": 0,
                "interpretation_note": "No match was found in the currently retained, opted-in image fingerprints. This is not proof that the image is original."}

    exact_count = sum(1 for item in match_cases.values() if item["exact"])
    near_count = len(match_cases) - exact_count
    return {
        "status": "matches_found",
        "matching_opted_in_checks": len(match_cases),
        "exact_file_matches": exact_count,
        "perceptual_similarity_matches": near_count,
        "threshold_hamming_distance": IMAGE_HAMMING_THRESHOLD,
        "interpretation_note": "Toroka found matching or visually similar fingerprints in other checks whose submitters explicitly opted into cross-case image matching. This can reflect a common catalogue/product photo, reposting or reuse; it does not identify the uploader or prove fraud. Case identities and private content are not disclosed.",
    }


def build4_case_context(db: Session, crypto, check: m.Check, text: str, image_hashes: list[str] | None = None) -> dict[str, Any] | None:
    identifiers = _extract_subjects(text, crypto)
    public_context = _published_indicator_context(db, identifiers)
    image_context = _image_reuse_context(db, check, image_hashes or [])
    matched = public_context["matched_indicators"]
    related = public_context["related_identifiers"]
    if not matched and not related and not image_context:
        return None

    limitations = [
        "Campaign relationships are contextual leads, not proof of common ownership, coordinated control or wrongdoing.",
        "Shared payment identifiers can be used by legitimate agents, staff, families, marketplaces or payment intermediaries.",
        "Public indicator matches apply to the exact matched identifier, not automatically to the seller, profile or every offer.",
    ]
    if image_context:
        limitations.append("Image similarity can arise from common catalogue images, stock photography, cropping or reposting; it does not establish who created or uploaded the image.")
    return {
        "status": "context_found",
        "matched_published_indicators": matched,
        "related_public_identifiers": related,
        "image_reuse": image_context,
        "interpretation_note": "Toroka checked for relationships among previously published community indicators and, where the original contributor opted in, retained image fingerprints. Each relationship is shown with its basis and limitations. Nothing in this panel independently changes the fraud assessment.",
        "limitations": limitations,
        "risk_propagation": "never_automatic",
    }


def _report_clusters(db: Session, limit: int = MAX_REPORTS_FOR_CLUSTERING) -> list[dict[str, Any]]:
    cutoff = (_now() - timedelta(days=180)).isoformat()
    reports = list(db.execute(
        select(m.Report)
        .where(m.Report.moderation_status.in_(["pending", "approved", "needs_info"]))
        .where(m.Report.created_at >= cutoff)
        .order_by(m.Report.created_at.desc())
        .limit(limit)
    ).scalars())
    parent = list(range(len(reports)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    by_script: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, report in enumerate(reports):
        by_script[(report.category, report.script_hash)].append(i)
    for indexes in by_script.values():
        for idx in indexes[1:]:
            union(indexes[0], idx)

    # Bounded near-duplicate pass. Only same-category reports in the same 90-day window.
    for i in range(len(reports)):
        left = reports[i]
        left_date = _parse_dt(left.created_at)
        if not left_date:
            continue
        for j in range(i + 1, min(len(reports), i + 60)):
            right = reports[j]
            if left.category != right.category:
                continue
            right_date = _parse_dt(right.created_at)
            if not right_date or abs((left_date - right_date).days) > 90:
                continue
            try:
                score = similarity(left.minhash, right.minhash)
            except Exception:
                score = 0
            if score >= 0.92:
                union(i, j)

    groups: dict[int, list[m.Report]] = defaultdict(list)
    for i, report in enumerate(reports):
        groups[find(i)].append(report)
    output = []
    for group in groups.values():
        reporters = {item.reporter_key for item in group}
        if len(group) < 2 or len(reporters) < 2:
            continue
        seed_report = min(group, key=lambda item: (item.created_at, item.id))
        fingerprint = hashlib.sha256(f"{seed_report.id}:{seed_report.script_hash}".encode()).hexdigest()
        subjects = db.execute(
            select(m.Subject).join(m.ReportSubject, m.ReportSubject.subject_id == m.Subject.id)
            .where(m.ReportSubject.report_id.in_([item.id for item in group]))
        ).scalars().all()
        subject_summary = {}
        for subject in subjects:
            subject_summary[(subject.subject_type, subject.lookup_hmac)] = {
                "kind": subject.subject_type, "masked_value": subject.display_masked,
            }
        dates = sorted(item.incident_date or item.created_at[:10] for item in group)
        output.append({
            "campaign_id": _campaign_id("repeated_advertisement_text", fingerprint),
            "campaign_type": "repeated_advertisement_text",
            "evidence_basis": "exact_or_near_duplicate_report_text",
            "reports": len(group),
            "distinct_reporters": len(reporters),
            "categories": sorted({item.category for item in group}),
            "moderation_statuses": dict((status, sum(item.moderation_status == status for item in group)) for status in ("pending", "approved", "needs_info")),
            "first_seen": dates[0], "last_seen": dates[-1],
            "identifiers": list(subject_summary.values())[:12],
            "report_ids": [item.id for item in group],
            "interpretation_note": "Repeated wording across independently submitted reports is a candidate campaign lead. Similar wording can also come from copied public notices or templates; inspect each report and source separately.",
        })
    return output


def _shared_identifier_clusters(db: Session) -> list[dict[str, Any]]:
    cutoff = (_now() - timedelta(days=180)).isoformat()
    subjects = db.execute(
        select(m.Subject)
        .where(m.Subject.subject_type.in_(["phone", "till", "paybill", "domain", "handle"]))
        .limit(2000)
    ).scalars().all()
    output = []
    for subject in subjects:
        report_rows = db.execute(
            select(m.Report)
            .join(m.ReportSubject, m.ReportSubject.report_id == m.Report.id)
            .where(m.ReportSubject.subject_id == subject.id)
            .where(m.Report.moderation_status.in_(["pending", "approved", "needs_info"]))
            .where(m.Report.created_at >= cutoff)
            .limit(300)
        ).scalars().all()
        reporters = {item.reporter_key for item in report_rows}
        if len(reporters) < 2:
            continue
        fingerprint = subject.lookup_hmac
        output.append({
            "campaign_id": _campaign_id("shared_identifier", subject.subject_type + ":" + fingerprint),
            "campaign_type": "shared_payment_identifier" if subject.subject_type in {"phone", "till", "paybill"} else "shared_digital_identifier",
            "evidence_basis": "same_hmac_identifier_in_independent_reports",
            "identifier": {"kind": subject.subject_type, "masked_value": subject.display_masked},
            "reports": len(report_rows), "distinct_reporters": len(reporters),
            "first_seen": min(item.created_at[:10] for item in report_rows),
            "last_seen": max(item.created_at[:10] for item in report_rows),
            "report_ids": [item.id for item in report_rows],
            "interpretation_note": "A shared identifier is a contextual link only. It can be used by agents, staff, family members, marketplaces or legitimate payment intermediaries.",
        })
    return output


def _image_clusters(db: Session) -> list[dict[str, Any]]:
    now_iso = m.now_iso()
    rows = db.execute(
        select(m.EvidenceFile, m.Check)
        .join(m.Check, m.Check.id == m.EvidenceFile.check_id)
        .where(m.EvidenceFile.consent_scope == IMAGE_CONSENT_SCOPE)
        .where(m.EvidenceFile.retention_until > now_iso)
        .where(m.Check.expires_at > now_iso)
        .order_by(m.EvidenceFile.created_at.desc())
        .limit(250)
    ).all()
    parent = list(range(len(rows)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i in range(len(rows)):
        for j in range(i + 1, min(len(rows), i + 40)):
            left, left_check = rows[i]
            right, right_check = rows[j]
            if left_check.id == right_check.id:
                continue
            try:
                distance = hamming_distance(left.dhash, right.dhash)
            except (TypeError, ValueError):
                continue
            if distance <= IMAGE_HAMMING_THRESHOLD:
                union(i, j)

    groups: dict[int, list[tuple[m.EvidenceFile, m.Check]]] = defaultdict(list)
    for i, row in enumerate(rows):
        groups[find(i)].append(row)
    output = []
    for group in groups.values():
        check_ids = sorted({check.id for _, check in group})
        if len(check_ids) < 2:
            continue
        seed_evidence = min((ev for ev, _ in group), key=lambda item: (item.created_at, item.id))
        fingerprint = hashlib.sha256(f"{seed_evidence.id}:{seed_evidence.dhash}".encode()).hexdigest()
        dates = sorted(ev.created_at[:10] for ev, _ in group)
        distances = []
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                try:
                    distances.append(hamming_distance(group[i][0].dhash, group[j][0].dhash))
                except ValueError:
                    pass
        output.append({
            "campaign_id": _campaign_id("opted_in_image_reuse", fingerprint),
            "campaign_type": "opted_in_image_reuse",
            "evidence_basis": "perceptual_image_fingerprint_similarity",
            "distinct_checks": len(check_ids),
            "check_ids": check_ids[:40],
            "evidence_file_ids": [ev.id for ev, _ in group[:60]],
            "images": len(group),
            "minimum_hamming_distance": min(distances) if distances else None,
            "first_seen": dates[0], "last_seen": dates[-1],
            "interpretation_note": "Only images explicitly opted into cross-case campaign matching are included. Similar images may be common product/catalogue photos or edits; no uploader or seller is identified by this match.",
        })
    return output


def moderation_campaign_candidates(db: Session, limit: int = 50) -> list[dict[str, Any]]:
    """Moderator-only, bounded campaign leads from reviewed/pending data and opted-in image hashes."""
    candidates = _report_clusters(db) + _shared_identifier_clusters(db) + _image_clusters(db)
    reviews = db.execute(select(m.CampaignReview)).scalars().all()
    by_id = {item.campaign_id: item for item in reviews}
    for item in candidates:
        review = by_id.get(item["campaign_id"])
        item["review"] = {
            "status": review.status if review else "candidate",
            "reason_code": review.reason_code if review else None,
            "reviewed_at": review.reviewed_at if review else None,
            "reviewer_id": review.reviewer_id if review else None,
        }
    candidates.sort(key=lambda item: (item["review"]["status"] != "candidate", -int(item.get("distinct_reporters", item.get("distinct_checks", 0))), item["campaign_type"]))
    return candidates[:max(1, min(limit, 100))]
