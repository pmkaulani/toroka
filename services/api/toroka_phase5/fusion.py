from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .models import EvidenceSignal

_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "context": 0}


def fuse_evidence(signals: Iterable[EvidenceSignal]) -> dict:
    """Produce a review band, not a probability or final scam/legitimate verdict.

    Multiple patterns from one source group count as one corroboration family. Context
    and reassuring signals never increase the risk band.
    """
    rows = list(signals)
    dedup: dict[tuple[str, str, str], EvidenceSignal] = {}
    for signal in rows:
        key = (signal.evidence_ref, signal.source_group, signal.category)
        old = dedup.get(key)
        if old is None or _SEVERITY[signal.severity] > _SEVERITY[old.severity]:
            dedup[key] = signal
    unique = list(dedup.values())
    risk_rows = [s for s in unique if s.polarity == "risk" and s.severity != "context"]
    # All user-supplied artefacts belong to the same provenance family by default.
    # Merely uploading an SMS and a screenshot must not manufacture independent corroboration.
    def independence_family(group: str) -> str:
        return "user_submitted_artifact" if group.startswith("user_") else group

    source_groups = {independence_family(s.source_group) for s in risk_rows}
    high_present = any(_SEVERITY[s.severity] >= 3 for s in risk_rows)
    critical_present = any(s.severity == "critical" for s in risk_rows)
    medium_refs = {s.evidence_ref for s in risk_rows if s.severity == "medium"}

    if not risk_rows:
        band = "insufficient_evidence"
        strength = "none_or_context_only"
    elif len(source_groups) >= 2 and high_present:
        band = "elevated_signals"
        strength = "multiple_source_families"
    elif critical_present or high_present or len(medium_refs) >= 2:
        band = "review_recommended"
        strength = "single_or_limited_source_families"
    else:
        band = "limited_signals"
        strength = "low_severity_or_single_source"

    return {
        "indicator_band": band,
        "evidence_strength": strength,
        "independent_source_groups": len(source_groups),
        "risk_signal_count": len(risk_rows),
        "context_signal_count": sum(1 for s in unique if s.polarity != "risk" or s.severity == "context"),
        "highest_risk_severity": max((s.severity for s in risk_rows), key=lambda x: _SEVERITY[x], default="none"),
        "deduplicated_signal_count": len(unique),
        "limitations": [
            "Indicator bands are workflow guidance, not probabilities or proof of fraud.",
            "Independent source families are defined by the backend; two user uploads are not automatically independent corroboration.",
            "Campaign similarity, brand mentions, location matches and ordinary payment instructions must remain contextual unless separately supported.",
            "A lack of risk signals is not a finding that a seller or message is legitimate.",
        ],
    }
