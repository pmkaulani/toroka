from __future__ import annotations

from .fingerprint import (
    CaseFingerprint,
    FingerprintEvidence,
    build_case_fingerprint,
    EVENT_FEATURES,
    EXPECTED_SOURCE_SYSTEMS,
    SEQUENCE_RULES,
)
from .similarity import (
    CaseSimilarity,
    FeatureComparison,
    compare_fingerprints,
    feature_weight,
)
from .patterns import (
    PatternStatus,
    InstitutionalPattern,
    PatternValidationPolicy,
    PatternValidationResult,
    PatternReview,
    evaluate_pattern,
    approve_pattern,
    reject_pattern,
    suspend_pattern,
    reinstate_pattern,
    retire_pattern,
)
from .control_weakness import (
    ControlWeaknessType,
    ControlWeaknessEvidence,
    CONTROL_WEAKNESS_DESCRIPTIONS,
    detect_control_weaknesses,
)
from .retrieval import (
    PatternMatch,
    retrieve_similar_historical_cases,
    match_case_against_patterns,
    discover_candidate_patterns,
)

__all__ = [
    "CaseFingerprint",
    "FingerprintEvidence",
    "build_case_fingerprint",
    "EVENT_FEATURES",
    "EXPECTED_SOURCE_SYSTEMS",
    "SEQUENCE_RULES",
    "CaseSimilarity",
    "FeatureComparison",
    "compare_fingerprints",
    "feature_weight",
    "PatternStatus",
    "InstitutionalPattern",
    "PatternValidationPolicy",
    "PatternValidationResult",
    "PatternReview",
    "evaluate_pattern",
    "approve_pattern",
    "reject_pattern",
    "suspend_pattern",
    "reinstate_pattern",
    "retire_pattern",
    "ControlWeaknessType",
    "ControlWeaknessEvidence",
    "CONTROL_WEAKNESS_DESCRIPTIONS",
    "detect_control_weaknesses",
    "PatternMatch",
    "retrieve_similar_historical_cases",
    "match_case_against_patterns",
    "discover_candidate_patterns",
]
