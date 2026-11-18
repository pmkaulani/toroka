"""Confirmation of Payee (CoP) Pre-Flight Name Verification Engine.

Provides algorithmic pre-clearing beneficiary name verification compliant with:
  - UK Payment Systems Regulator (PSR) Confirmation of Payee Rules
  - Central Bank of Kenya (CBK) National Payments System Fraud Directives
  - East African PesaLink, M-Pesa Paybill/Till, and Interbank Clearing Rails

Determines whether the payee name entered by the payer matches the legal name
registered on the destination account prior to payment authorization.

Outcomes:
  - MATCH (Score >= 0.88 or valid token permutation/initial expansion)
  - CLOSE_MATCH (0.65 <= Score < 0.88, provides registered name suggestion)
  - NO_MATCH (Score < 0.65, triggers high-risk impersonation / scam warning)
"""
from __future__ import annotations

import hashlib
import json
import re
import unicodedata
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class CopStatus(StrEnum):
    MATCH = "MATCH"
    CLOSE_MATCH = "CLOSE_MATCH"
    NO_MATCH = "NO_MATCH"


class CopAccountType(StrEnum):
    PERSONAL = "PERSONAL"
    BUSINESS = "BUSINESS"


@dataclass(frozen=True)
class CopInquiryRequest:
    """Inquiry parameters for Confirmation of Payee verification."""
    intended_name: str
    registered_name: str
    account_number: str
    account_type: CopAccountType = CopAccountType.PERSONAL
    clearing_rail: str = "PESALINK"
    bank_bic: str = ""
    inquiry_id: str = field(default_factory=lambda: f"cop-{uuid.uuid4().hex[:12]}")
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "inquiry_id": self.inquiry_id,
            "intended_name": self.intended_name,
            "registered_name": self.registered_name,
            "account_number": self.account_number,
            "account_type": self.account_type.value,
            "clearing_rail": self.clearing_rail,
            "bank_bic": self.bank_bic,
            "created_at": self.created_at.isoformat(),
        }


@dataclass(frozen=True)
class CopVerificationResult:
    """Outcome of a Confirmation of Payee pre-clearing evaluation."""
    inquiry_id: str
    status: CopStatus
    match_score: float
    intended_name_normalized: str
    registered_name_normalized: str
    suggested_name: str | None
    reason_code: str
    advisory_message: str
    inquiry_digest: str
    verified_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "inquiry_id": self.inquiry_id,
            "status": self.status.value,
            "match_score": round(self.match_score, 4),
            "intended_name_normalized": self.intended_name_normalized,
            "registered_name_normalized": self.registered_name_normalized,
            "suggested_name": self.suggested_name,
            "reason_code": self.reason_code,
            "advisory_message": self.advisory_message,
            "inquiry_digest": self.inquiry_digest,
            "verified_at": self.verified_at.isoformat(),
        }


class ConfirmationOfPayeeEngine:
    """Pure-Python algorithmic name-matching engine for Confirmation of Payee."""

    # Honorifics and personal titles to strip before comparison
    TITLES_TO_STRIP = {
        "mr", "mrs", "ms", "miss", "dr", "prof", "professor", "rev", "reverend",
        "pastor", "bishop", "hon", "honourable", "honorable", "eng", "engineer",
        "arch", "architect", "cpa", "sc", "mheshimiwa", "mwalimu", "mwl", "mama",
        "baba", "sir", "madam", "lady",
    }

    # Standardized organizational and corporate suffix canonical mappings
    CORP_SYNONYMS = {
        "ltd": "limited",
        "plc": "public limited company",
        "inc": "incorporated",
        "corp": "corporation",
        "co": "company",
        "ent": "enterprises",
        "coop": "cooperative",
        "co-op": "cooperative",
        "co-operative": "cooperative",
        "sacco": "sacco",
        "assn": "association",
        "assoc": "associates",
        "intl": "international",
        "serv": "services",
        "svcs": "services",
        "tech": "technologies",
        "grp": "group",
    }

    # Mobile money paybill / till / agent prefixes to remove for comparison
    PAYBILL_PREFIX_PATTERN = re.compile(
        r"^(?:paybill|till|buy\s*goods|agent|lipa\s*na\s*mpesa)\s*(?:no\.?|number|#)?\s*\d+\s*[-:]*\s*",
        re.IGNORECASE,
    )

    @classmethod
    def normalize_name(cls, name: str, is_business: bool = False) -> list[str]:
        """Normalizes a raw name into an ordered list of clean comparison tokens."""
        if not name:
            return []

        # 1. Unicode NFKC normalization
        norm = unicodedata.normalize("NFKC", name).lower()

        # 2. Strip paybill/till prefixes (e.g. "Paybill 522522 - Acme Corp" -> "Acme Corp")
        norm = cls.PAYBILL_PREFIX_PATTERN.sub("", norm)

        # 3. Replace punctuation and special characters with spaces
        norm = re.sub(r"[^\w\s]", " ", norm)

        # 4. Tokenize
        raw_tokens = norm.split()
        clean_tokens: list[str] = []

        for tok in raw_tokens:
            if not is_business and tok in cls.TITLES_TO_STRIP:
                continue
            canonical_tok = cls.CORP_SYNONYMS.get(tok, tok)
            clean_tokens.append(canonical_tok)

        return clean_tokens

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Computes Levenshtein edit distance."""
        if s1 == s2:
            return 0
        if not s1:
            return len(s2)
        if not s2:
            return len(s1)

        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    @classmethod
    def _levenshtein_ratio(cls, s1: str, s2: str) -> float:
        """Computes normalized Levenshtein similarity ratio between 0.0 and 1.0."""
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        dist = cls._levenshtein_distance(s1, s2)
        return max(0.0, 1.0 - (dist / max_len))

    @staticmethod
    def _jaro_winkler_similarity(s1: str, s2: str) -> float:
        """Computes Jaro-Winkler string similarity with prefix bonus."""
        if s1 == s2:
            return 1.0
        len1, len2 = len(s1), len(s2)
        if len1 == 0 or len2 == 0:
            return 0.0

        match_distance = max(len1, len2) // 2 - 1
        s1_matches = [False] * len1
        s2_matches = [False] * len2
        matches = 0

        for i in range(len1):
            start = max(0, i - match_distance)
            end = min(i + match_distance + 1, len2)
            for j in range(start, end):
                if not s2_matches[j] and s1[i] == s2[j]:
                    s1_matches[i] = True
                    s2_matches[j] = True
                    matches += 1
                    break

        if matches == 0:
            return 0.0

        transpositions = 0
        k = 0
        for i in range(len1):
            if not s1_matches[i]:
                continue
            while not s2_matches[k]:
                k += 1
            if s1[i] != s2[k]:
                transpositions += 1
            k += 1

        jaro = (
            (matches / len1) + (matches / len2) + ((matches - transpositions / 2) / matches)
        ) / 3.0

        # Winkler prefix bonus (up to 4 chars)
        prefix = 0
        for i in range(min(len1, len2, 4)):
            if s1[i] == s2[i]:
                prefix += 1
            else:
                break

        return min(1.0, jaro + (prefix * 0.1 * (1.0 - jaro)))

    @classmethod
    def _match_initials_and_surname(cls, tokens1: list[str], tokens2: list[str]) -> bool:
        """Checks if tokens1 matches tokens2 via initials + surname expansion."""
        if not tokens1 or not tokens2:
            return False

        # One token list must be initials or shorter
        short_tokens, long_tokens = (tokens1, tokens2) if len(tokens1) <= len(tokens2) else (tokens2, tokens1)
        if len(short_tokens) < 2:
            return False

        # Surname (last token) must match or be a very close edit
        if cls._levenshtein_ratio(short_tokens[-1], long_tokens[-1]) < 0.85:
            return False

        # Check preceding initials
        short_prefixes = short_tokens[:-1]
        long_prefixes = long_tokens[:-1]

        # There must be at least one single-letter initial among the prefixes to be an initial match
        has_initial = any(len(tok) == 1 for tok in short_prefixes)
        if not has_initial:
            return False

        matched_prefixes = 0
        for s_tok in short_prefixes:
            matched = False
            for l_tok in long_prefixes:
                if len(s_tok) == 1 and l_tok.startswith(s_tok):
                    matched = True
                    break
                elif s_tok == l_tok or cls._levenshtein_ratio(s_tok, l_tok) >= 0.85:
                    matched = True
                    break
            if matched:
                matched_prefixes += 1

        return matched_prefixes == len(short_prefixes)

    @classmethod
    def verify(cls, request: CopInquiryRequest) -> CopVerificationResult:
        """Executes full Confirmation of Payee verification algorithm."""
        is_biz = request.account_type == CopAccountType.BUSINESS
        t_intended = cls.normalize_name(request.intended_name, is_business=is_biz)
        t_registered = cls.normalize_name(request.registered_name, is_business=is_biz)

        s_intended = " ".join(t_intended)
        s_registered = " ".join(t_registered)

        # Empty name edge case
        if not s_intended or not s_registered:
            digest = cls._compute_digest(request, CopStatus.NO_MATCH, 0.0)
            return CopVerificationResult(
                inquiry_id=request.inquiry_id,
                status=CopStatus.NO_MATCH,
                match_score=0.0,
                intended_name_normalized=s_intended,
                registered_name_normalized=s_registered,
                suggested_name=None,
                reason_code="EMPTY_NAME_NO_MATCH",
                advisory_message="Warning - No Match: One or both names are empty or could not be normalized.",
                inquiry_digest=digest,
            )

        # 1. Exact string match after normalization
        if s_intended == s_registered:
            digest = cls._compute_digest(request, CopStatus.MATCH, 1.0)
            return CopVerificationResult(
                inquiry_id=request.inquiry_id,
                status=CopStatus.MATCH,
                match_score=1.0,
                intended_name_normalized=s_intended,
                registered_name_normalized=s_registered,
                suggested_name=None,
                reason_code="EXACT_NAME_MATCH",
                advisory_message="Verified: Payee name exactly matches registered account records.",
                inquiry_digest=digest,
            )

        # 2. Token set / permutation exact match (e.g. "Mwangi Patrick" vs "Patrick Mwangi")
        if set(t_intended) == set(t_registered):
            digest = cls._compute_digest(request, CopStatus.MATCH, 0.98)
            return CopVerificationResult(
                inquiry_id=request.inquiry_id,
                status=CopStatus.MATCH,
                match_score=0.98,
                intended_name_normalized=s_intended,
                registered_name_normalized=s_registered,
                suggested_name=None,
                reason_code="TOKEN_PERMUTATION_MATCH",
                advisory_message="Verified: Payee name matches registered account records (word order transposed).",
                inquiry_digest=digest,
            )

        # 3. Token subset match (e.g. "Kamau Enterprises" vs "Kamau Enterprises Limited")
        set_intended = set(t_intended)
        set_registered = set(t_registered)
        if set_intended.issubset(set_registered) and len(set_intended) >= 2:
            # High match if key tokens are all present
            digest = cls._compute_digest(request, CopStatus.MATCH, 0.94)
            return CopVerificationResult(
                inquiry_id=request.inquiry_id,
                status=CopStatus.MATCH,
                match_score=0.94,
                intended_name_normalized=s_intended,
                registered_name_normalized=s_registered,
                suggested_name=None,
                reason_code="TOKEN_SUBSET_MATCH",
                advisory_message=f"Verified: Payee name matches primary tokens of registered account '{request.registered_name}'.",
                inquiry_digest=digest,
            )

        # 4. Initials & Surname match (e.g. "Patrick K Mwangi" vs "Patrick Kariuki Mwangi")
        if cls._match_initials_and_surname(t_intended, t_registered):
            digest = cls._compute_digest(request, CopStatus.MATCH, 0.92)
            return CopVerificationResult(
                inquiry_id=request.inquiry_id,
                status=CopStatus.MATCH,
                match_score=0.92,
                intended_name_normalized=s_intended,
                registered_name_normalized=s_registered,
                suggested_name=None,
                reason_code="INITIALS_EXPANSION_MATCH",
                advisory_message=f"Verified: Name matches registered account holder with initial expansion.",
                inquiry_digest=digest,
            )

        # 5. Composite Fuzzy Similarity Calculation
        jw_sim = cls._jaro_winkler_similarity(s_intended, s_registered)
        lev_sim = cls._levenshtein_ratio(s_intended, s_registered)

        # Token overlap ratio
        intersection = set_intended.intersection(set_registered)
        union = set_intended.union(set_registered)
        token_sim = len(intersection) / len(union) if union else 0.0

        # Weighted score: Jaro-Winkler (40%) + Levenshtein (30%) + Token Jaccard (30%)
        composite_score = (0.40 * jw_sim) + (0.30 * lev_sim) + (0.30 * token_sim)

        # Evaluate threshold tiers
        if composite_score >= 0.88:
            status = CopStatus.MATCH
            suggested = None
            reason = "FUZZY_HIGH_SIMILARITY_MATCH"
            advisory = f"Verified: Name matches registered account records with minor formatting variance."
        elif composite_score >= 0.65:
            status = CopStatus.CLOSE_MATCH
            suggested = request.registered_name
            reason = "CLOSE_NAME_VARIANT"
            advisory = (
                f"Close Match: The registered account name is '{request.registered_name}'. "
                f"Please confirm this matches your intended payee before sending."
            )
        else:
            status = CopStatus.NO_MATCH
            suggested = None
            reason = "LOW_SIMILARITY_NO_MATCH"
            advisory = (
                f"Warning - No Match: The name you entered does not match the registered account records. "
                f"If you were instructed to send money over the telephone or by an unverified third party, "
                f"this transaction may be a social engineering scam."
            )

        digest = cls._compute_digest(request, status, composite_score)

        return CopVerificationResult(
            inquiry_id=request.inquiry_id,
            status=status,
            match_score=composite_score,
            intended_name_normalized=s_intended,
            registered_name_normalized=s_registered,
            suggested_name=suggested,
            reason_code=reason,
            advisory_message=advisory,
            inquiry_digest=digest,
        )

    @classmethod
    def _compute_digest(
        cls,
        request: CopInquiryRequest,
        status: CopStatus,
        match_score: float,
    ) -> str:
        """Computes immutable SHA-256 cryptographic digest of the inquiry."""
        canonical = {
            "inquiry_id": request.inquiry_id,
            "intended_name": request.intended_name,
            "registered_name": request.registered_name,
            "account_number": request.account_number,
            "account_type": request.account_type.value,
            "clearing_rail": request.clearing_rail,
            "bank_bic": request.bank_bic,
            "status": status.value,
            "match_score": round(match_score, 4),
        }
        encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
