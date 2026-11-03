"""Feature extraction pipeline for Toroka's Machine Learning system.

Extracts:
1. Word n-grams (1-2) for semantic phrases.
2. Character n-grams (3-5) for capturing obfuscations, Sheng spellings, and typo variations.
3. High-signal domain structural features for Kenyan fraud forensics.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from typing import Any

# Domain regex patterns for structural feature indicators
_UPFRONT_FEE_RX = re.compile(
    r"(?i)\b(?:pay|send|tuma|deposit|clearance|processing|registration|activation|tax|customs|release|delivery)\b[^\n.]{0,35}\b(?:fee|charge|cost|amount|ksh|kes|\$|pesa|gharama)\b"
    r"|\b(?:fee|charge|cost|deposit)\s+of\s+(?:ksh|kes|\$)?\s*\d+"
    r"|\bpay\s+(?:half|deposit|part|advance)\b"
    r"|\blipa\s+(?:kwanza|nusu|pesa)\b"
)

_CREDENTIAL_RX = re.compile(
    r"(?i)\b(?:pin|otp|password|nywila|one-time\s+pin|secret\s+code|m-pesa\s+pin|mpesa\s+pin)\b"
)

_PAYOUT_WINNINGS_RX = re.compile(
    r"(?i)\b(?:awarded|congratulations|hongera|you\s+have\s+won|winnings?|prize|grant|payout|inheritance|funds?\s+waiting|freebets?|bonus|jackpot|compensation|unclaimed\b|disbursement|claim\b[^\n.]{0,25}\b(?:prize|gift|laptop|phone|funds|money|reward|cash))\b"
)

_BETTING_PROMOTION_RX = re.compile(
    r"(?i)\b(?:aviator|freebets?|casino\s+bonus|register\s+on\s+\w+\.com|betika|sportpesa|chezagame|mozzart|1xbet|shabiki|free\s+bet)\b"
)

_REVERSAL_RX = re.compile(
    r"(?i)\b(?:nimetuma\s+(?:kwa\s+)?makosa|nimekosea|tuma\s+nyuma|nitumie\b[^\n.]{0,25}\bnyuma|rudisha|sent\s+by\s+mistake|reverse\s+the\s+money|send\s+it\s+back)\b"
)

_TASK_OR_BOOSTER_RX = re.compile(
    r"(?i)\b(?:task\s+boost|order\s+grab|daily\s+income|earn\s+\d+\s+daily|like\s+videos?|recharge\s+to\s+withdraw|commission\s+deposit)\b"
)

_JOB_RECRUITMENT_RX = re.compile(
    r"(?i)\b(?:kra|tsc|police|kdf|nhif|sha|nssf|recruitment|appointment\s+letter|interview\s+fee|medical\s+fee|processing\s+fee)\b"
)

_URGENCY_RX = re.compile(
    r"(?i)\b(?:immediately|act\s+now|urgent|haraka|sasa\s+hivi|within\s+\d+\s+hours?|(?:account|m-pesa|mpesa|sim|line)\s+(?:is\s+)?(?:locked|closed|suspended)|ita?fungwa|locked|blocked)\b"
)

_LEGIT_SAFETY_RX = re.compile(
    r"(?i)\b(?:never\s+share\b[^\n.]{0,25}\b(?:pin|otp|password|nywila)|usitume\s+(?:nywila|pin)|dial\s+\*334#|official\s+customer\s+care|100\s+or\s+234)\b"
)

_LEGIT_COMMERCE_RX = re.compile(
    r"(?i)\b(?:pay\s+on\s+delivery|lipa\s+baada\s+ya\s+kupokea|inspect\s+before\s+pay|free\s+returns?|return\s+policy|warranty)\b"
)

_SHORT_URL_RX = re.compile(
    r"(?i)\b(?:bit\.ly|tinyurl\.com|t\.co|rb\.gy|is\.gd|cutt\.ly|shorturl\.at|wa\.link)\b"
)

_MPESA_RECEIPT_RX = re.compile(
    r"(?i)\b[a-z0-9]{10}\s+confirmed\.\s*(?:ksh|kes)\.?\s*[\d,]+(?:\.\d{2})?\s+(?:sent\s+to|received\s+from|paid\s+to)\b"
)


def extract_structural_features(text: str) -> dict[str, float]:
    """Extract interpretable, documented evidence features."""
    length = len(text)
    words = re.findall(r"\w+", text)
    word_count = len(words)

    feats: dict[str, float] = {
        "feat_upfront_fee_demand": 1.0 if _UPFRONT_FEE_RX.search(text) else 0.0,
        "feat_credential_harvesting": 1.0 if _CREDENTIAL_RX.search(text) else 0.0,
        "feat_payout_or_winnings_claim": 1.0 if _PAYOUT_WINNINGS_RX.search(text) else 0.0,
        "feat_betting_or_casino_promotion": 1.0 if _BETTING_PROMOTION_RX.search(text) else 0.0,
        "feat_reversal_tuma_nyuma_claim": 1.0 if _REVERSAL_RX.search(text) else 0.0,
        "feat_task_booster_claim": 1.0 if _TASK_OR_BOOSTER_RX.search(text) else 0.0,
        "feat_job_recruitment_claim": 1.0 if _JOB_RECRUITMENT_RX.search(text) else 0.0,
        "feat_urgency_pressure": 1.0 if _URGENCY_RX.search(text) else 0.0,
        "feat_legit_safety_guidance": 1.0 if _LEGIT_SAFETY_RX.search(text) else 0.0,
        "feat_legit_commerce_terms": 1.0 if _LEGIT_COMMERCE_RX.search(text) else 0.0,
        "feat_shortened_url": 1.0 if _SHORT_URL_RX.search(text) else 0.0,
        "feat_mpesa_receipt_structure": 1.0 if _MPESA_RECEIPT_RX.search(text) else 0.0,
        "feat_has_https_link": 1.0 if "https://" in text.lower() else 0.0,
        "feat_has_phone_number": 1.0 if re.search(r"\b(?:07|01|\+?254)\d{8}\b", text) else 0.0,
        "feat_has_currency_amount": 1.0 if re.search(r"(?i)\b(?:ksh|kes|\$|usd)\s*[\d,]+", text) else 0.0,
        "feat_log_word_count": math.log1p(word_count),
    }

    # Combined composite feature: Payout claim + Upfront fee demand (Classic Advance-Fee Fraud)
    feats["feat_composite_advance_fee"] = (
        1.0 if feats["feat_payout_or_winnings_claim"] > 0 and feats["feat_upfront_fee_demand"] > 0 else 0.0
    )

    # Combined composite feature: Credential demand + Urgency (Phishing / Account Takeover)
    feats["feat_composite_credential_phish"] = (
        1.0 if feats["feat_credential_harvesting"] > 0 and feats["feat_urgency_pressure"] > 0 else 0.0
    )

    return feats


class TfidfCharWordExtractor:
    """Combines word (1-2) and char (3-5) n-grams with IDF weighting.
    
    Self-contained pure-Python vectorizer that guarantees zero deployment
    surprises across operating systems and runtimes while preserving high accuracy.
    """

    def __init__(self, max_features: int = 1200, min_df: int = 2):
        self.max_features = max_features
        self.min_df = min_df
        self.vocabulary: dict[str, int] = {}
        self.idf: list[float] = []

    def _tokenize_words(self, text: str) -> list[str]:
        words = [w.lower() for w in re.findall(r"\b[A-Za-z0-9_'-]{2,}\b", text)]
        tokens = list(words)
        # Add bigrams
        for i in range(len(words) - 1):
            tokens.append(f"{words[i]}_{words[i+1]}")
        return tokens

    def _tokenize_chars(self, text: str) -> list[str]:
        clean = " " + " ".join(text.lower().split()) + " "
        chars = []
        for n in (3, 4, 5):
            for i in range(len(clean) - n + 1):
                chars.append(f"c:{clean[i:i+n]}")
        return chars

    def fit(self, texts: list[str]) -> "TfidfCharWordExtractor":
        doc_counts: Counter[str] = Counter()
        n_docs = len(texts)

        for text in texts:
            unique_terms = set(self._tokenize_words(text) + self._tokenize_chars(text))
            for term in unique_terms:
                doc_counts[term] += 1

        # Filter by min_df and take top max_features
        eligible = [(term, count) for term, count in doc_counts.items() if count >= self.min_df]
        # Sort by frequency descending
        eligible.sort(key=lambda x: x[1], reverse=True)
        top_terms = eligible[: self.max_features]

        self.vocabulary = {term: idx for idx, (term, _) in enumerate(top_terms)}
        # Compute smooth IDF: log((N + 1) / (df + 1)) + 1
        self.idf = [0.0] * len(self.vocabulary)
        for term, idx in self.vocabulary.items():
            df = doc_counts[term]
            self.idf[idx] = math.log((n_docs + 1.0) / (df + 1.0)) + 1.0

        return self

    def transform_single(self, text: str) -> dict[int, float]:
        """Returns sparse representation: {feature_idx: tfidf_weight}."""
        terms = self._tokenize_words(text) + self._tokenize_chars(text)
        tf: Counter[str] = Counter(terms)
        sparse_vec: dict[int, float] = {}
        norm_sq = 0.0

        for term, count in tf.items():
            idx = self.vocabulary.get(term)
            if idx is not None:
                # Sublinear TF: 1 + log(tf)
                weight = (1.0 + math.log(count)) * self.idf[idx]
                sparse_vec[idx] = weight
                norm_sq += weight * weight

        # L2 normalize
        if norm_sq > 0:
            norm = math.sqrt(norm_sq)
            for idx in sparse_vec:
                sparse_vec[idx] /= norm

        return sparse_vec

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_features": self.max_features,
            "min_df": self.min_df,
            "vocabulary": self.vocabulary,
            "idf": self.idf,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TfidfCharWordExtractor":
        ext = cls(max_features=data["max_features"], min_df=data["min_df"])
        ext.vocabulary = data["vocabulary"]
        ext.idf = data["idf"]
        return ext
