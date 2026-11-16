from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
import uuid

from .fingerprint import CaseFingerprint
from .patterns import InstitutionalPattern, PatternStatus
from .similarity import CaseSimilarity, compare_fingerprints, feature_weight


@dataclass(frozen=True)
class PatternMatch:
    """Explainable match between a case and a validated or candidate institutional pattern."""

    pattern_id: str
    pattern_version: int
    pattern_title: str
    pattern_status: str
    similarity_index: float | None
    comparison_coverage: float
    matched_features: tuple[str, ...]
    different_features: tuple[str, ...]
    control_weaknesses: tuple[str, ...]
    explanation: str
    confirmed_fraud_cases_count: int
    confirmed_legitimate_cases_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "pattern_version": self.pattern_version,
            "pattern_title": self.pattern_title,
            "pattern_status": self.pattern_status,
            "similarity_index": self.similarity_index,
            "comparison_coverage": self.comparison_coverage,
            "matched_features": list(self.matched_features),
            "different_features": list(self.different_features),
            "control_weaknesses": list(self.control_weaknesses),
            "explanation": self.explanation,
            "confirmed_fraud_cases_count": self.confirmed_fraud_cases_count,
            "confirmed_legitimate_cases_count": self.confirmed_legitimate_cases_count,
        }


def retrieve_similar_historical_cases(
    current: CaseFingerprint,
    historical_fingerprints: list[CaseFingerprint],
    min_coverage: float = 0.1,
    limit: int = 10,
) -> list[CaseSimilarity]:
    """Retrieve and rank historical investigated cases by deterministic feature similarity.

    Enforces installation isolation and separates similarity index from comparison coverage.
    """
    results: list[CaseSimilarity] = []

    for hist in historical_fingerprints:
        if hist.installation_id != current.installation_id:
            continue
        if hist.case_id == current.case_id:
            continue

        sim = compare_fingerprints(current, hist, min_coverage=min_coverage)
        if sim.comparison_coverage >= min_coverage:
            results.append(sim)

    # Sort deterministically: highest similarity index first, then coverage, then case_id
    results.sort(
        key=lambda s: (
            s.similarity_index is not None,
            s.similarity_index or 0.0,
            s.comparison_coverage,
            s.historical_case_id,
        ),
        reverse=True,
    )
    return results[:limit]


def match_case_against_patterns(
    current: CaseFingerprint,
    patterns: list[InstitutionalPattern],
    min_coverage: float = 0.1,
) -> list[PatternMatch]:
    """Match a case fingerprint against institutional patterns, explaining matched and differing features."""
    matches: list[PatternMatch] = []

    for pattern in patterns:
        if pattern.installation_id != current.installation_id:
            continue

        pat_features = pattern.feature_signature
        if not pat_features:
            continue

        total_sig_weight = sum(feature_weight(d) for d in pat_features.keys())
        comparable_weight = 0.0
        matched_weight = 0.0

        matched_dims: list[str] = []
        differing_dims: list[str] = []

        for dim, v_pat in pat_features.items():
            v_curr = current.features.get(dim, "unknown")

            if v_curr != "unknown":
                w = feature_weight(dim)
                comparable_weight += w

                # Match if exact or both represent the same sequence occurrence
                is_match = False
                if v_curr == v_pat:
                    is_match = True
                elif v_curr.startswith("present") and v_pat.startswith("present"):
                    is_match = True

                if is_match:
                    matched_weight += w
                    matched_dims.append(dim)
                else:
                    differing_dims.append(dim)

        coverage = (
            round(comparable_weight / total_sig_weight, 4) if total_sig_weight > 0 else 0.0
        )
        sim_index = (
            round(matched_weight / comparable_weight, 4) if comparable_weight > 0 else None
        )

        if coverage >= min_coverage and sim_index is not None:
            # Build explainable narrative
            matched_seq = [d for d in matched_dims if d.startswith("sequence.")]
            matched_cw = [d for d in matched_dims if d.startswith("control_weakness.")]

            narrative = (
                f"Matches {len(matched_dims)} of {len(pat_features)} signature feature(s) "
                f"in pattern '{pattern.title}' (coverage: {coverage * 100:.1f}%). "
            )
            if matched_seq:
                narrative += f"Sequence matched: {', '.join(matched_seq[:2])}. "
            if matched_cw:
                narrative += f"Aligned control weakness: {', '.join(matched_cw[:2])}. "
            if differing_dims:
                narrative += f"{len(differing_dims)} feature(s) differ from pattern baseline."

            matches.append(
                PatternMatch(
                    pattern_id=pattern.pattern_id,
                    pattern_version=pattern.version,
                    pattern_title=pattern.title,
                    pattern_status=pattern.status.value,
                    similarity_index=sim_index,
                    comparison_coverage=coverage,
                    matched_features=tuple(matched_dims),
                    different_features=tuple(differing_dims),
                    control_weaknesses=pattern.control_weaknesses,
                    explanation=narrative.strip(),
                    confirmed_fraud_cases_count=len(pattern.confirmed_fraud_case_ids),
                    confirmed_legitimate_cases_count=len(pattern.confirmed_legitimate_case_ids),
                )
            )

    matches.sort(
        key=lambda m: (
            m.similarity_index is not None,
            m.similarity_index or 0.0,
            m.comparison_coverage,
            m.pattern_id,
        ),
        reverse=True,
    )
    return matches


def discover_candidate_patterns(
    fingerprints: list[CaseFingerprint],
    installation_id: str,
    curator_subject: str = "system",
    min_cases_support: int = 2,
) -> list[InstitutionalPattern]:
    """Deterministically mine recurring fraud methods and control weaknesses from adjudicated cases."""
    # Filter by installation
    inst_fps = [fp for fp in fingerprints if fp.installation_id == installation_id]

    fraud_fps = [fp for fp in inst_fps if fp.adjudicated_label == "confirmed_fraud"]
    legit_fps = [fp for fp in inst_fps if fp.adjudicated_label == "confirmed_legitimate"]

    if len(fraud_fps) < min_cases_support:
        return []

    # Map all sequences and control weaknesses occurring across fraud cases
    feature_counts: dict[str, list[CaseFingerprint]] = {}
    for fp in fraud_fps:
        for dim, val in fp.features.items():
            if val.startswith("present"):
                feature_counts.setdefault(dim, []).append(fp)

    # Filter features that appear in at least min_cases_support fraud cases
    recurring_dims = {
        dim: cases for dim, cases in feature_counts.items() if len(cases) >= min_cases_support
    }

    # Group recurring dimensions into typologies
    typologies: list[dict[str, Any]] = []

    # Typology 1: Beneficiary Manipulation & Fund Extraction
    seq_ben_keys = [
        d for d in recurring_dims if "beneficiary_change" in d and d.startswith("sequence.")
    ]
    if seq_ben_keys:
        involved_cases = list(
            set(c.case_id for k in seq_ben_keys for c in recurring_dims[k])
        )
        if len(involved_cases) >= min_cases_support:
            sig = {k: "present" for k in seq_ben_keys}
            sig["sensitive_change.beneficiary"] = "present"
            typologies.append(
                {
                    "title": "Beneficiary Modification Followed by Fund Transfer",
                    "description": (
                        "Recurring operational sequence where customer or account beneficiary "
                        "was modified shortly before outbound payment execution."
                    ),
                    "signature": sig,
                    "case_ids": tuple(sorted(involved_cases)),
                    "control_weaknesses": ("customer_authorisation_evidence_gap",),
                }
            )

    # Typology 2: Privileged Access Elevation & Credential Alteration
    seq_priv_keys = [
        d
        for d in recurring_dims
        if ("privileged_login" in d or "password_reset" in d or "mfa_disabled" in d)
        and d.startswith("sequence.")
    ]
    if seq_priv_keys:
        involved_cases = list(
            set(c.case_id for k in seq_priv_keys for c in recurring_dims[k])
        )
        if len(involved_cases) >= min_cases_support:
            sig = {k: "present" for k in seq_priv_keys}
            sig["sensitive_change.credentials"] = "present"
            typologies.append(
                {
                    "title": "Privileged Session Credential & Role Alteration Typology",
                    "description": (
                        "Pattern involving privileged administrative session establishment "
                        "accompanied by credential resets, MFA alteration, or role elevation."
                    ),
                    "signature": sig,
                    "case_ids": tuple(sorted(involved_cases)),
                    "control_weaknesses": ("access_governance_weakness",),
                }
            )

    # Typology 3: Customer Record Access Followed by Contact Alteration
    seq_contact_keys = [
        d
        for d in recurring_dims
        if "contact_details_changed" in d and d.startswith("sequence.")
    ]
    if seq_contact_keys:
        involved_cases = list(
            set(c.case_id for k in seq_contact_keys for c in recurring_dims[k])
        )
        if len(involved_cases) >= min_cases_support:
            sig = {k: "present" for k in seq_contact_keys}
            sig["sensitive_change.contact_details"] = "present"
            typologies.append(
                {
                    "title": "Customer Record Access Preceding Contact Detail Re-routing",
                    "description": (
                        "Pattern demonstrating CRM/customer record lookup immediately followed "
                        "by contact phone or email re-routing prior to downstream transactions."
                    ),
                    "signature": sig,
                    "case_ids": tuple(sorted(involved_cases)),
                    "control_weaknesses": (
                        "customer_authorisation_evidence_gap",
                        "delayed_detection_opportunity",
                    ),
                }
            )

    # Build InstitutionalPattern candidate objects
    candidates: list[InstitutionalPattern] = []
    now = datetime.now(timezone.utc)

    for idx, typo in enumerate(typologies, start=1):
        fraud_c_ids = typo["case_ids"]
        # Find confirmed legitimate cases that also exhibit some of these features (counterexamples)
        legit_counterexamples: list[str] = []
        for lfp in legit_fps:
            overlap = any(lfp.features.get(k, "").startswith("present") for k in typo["signature"])
            if overlap:
                legit_counterexamples.append(lfp.case_id)

        # Collect unique independent source systems from contributing cases
        source_systems = set()
        supporting_events = set()
        for c_id in fraud_c_ids:
            matching_fp = next((fp for fp in fraud_fps if fp.case_id == c_id), None)
            if matching_fp:
                source_systems.update(matching_fp.source_systems)
                for ev in matching_fp.evidence:
                    if ev.dimension in typo["signature"]:
                        supporting_events.update(ev.event_ids)

        pattern_id = f"PAT-{installation_id[:8].upper()}-{idx:03d}"

        candidates.append(
            InstitutionalPattern(
                pattern_id=pattern_id,
                installation_id=installation_id,
                version=1,
                title=typo["title"],
                description=typo["description"],
                feature_signature=typo["signature"],
                confirmed_fraud_case_ids=fraud_c_ids,
                confirmed_legitimate_case_ids=tuple(sorted(legit_counterexamples)),
                independent_source_systems=tuple(sorted(source_systems)),
                status=PatternStatus.CANDIDATE,
                created_by=curator_subject,
                created_at=now,
                extractor_version="v1",
                supporting_event_ids=tuple(sorted(supporting_events)),
                control_weaknesses=typo.get("control_weaknesses", ()),
                curator=curator_subject,
                limitations=(
                    "Discovered from historical case clustering; requires dual-control review "
                    "and legitimate baseline comparison before operational activation.",
                ),
            )
        )

    return candidates
