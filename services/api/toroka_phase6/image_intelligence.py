from __future__ import annotations
import hashlib
import hmac
import re
import unicodedata


def exact_file_hash(data: bytes) -> str:
    if not isinstance(data, (bytes, bytearray)) or not data or len(data) > 20 * 1024 * 1024:
        raise ValueError("image must be non-empty bytes up to 20 MiB")
    return hashlib.sha256(data).hexdigest()


def dhash_from_grayscale(rows: list[list[int]]) -> str:
    """Compute a 64-bit difference hash from an 8x9 grayscale pixel matrix."""
    if len(rows) != 8 or any(len(row) != 9 for row in rows):
        raise ValueError("dHash input must be exactly 8 rows by 9 columns")
    if any(not isinstance(px, int) or px < 0 or px > 255 for row in rows for px in row):
        raise ValueError("pixel values must be integers between 0 and 255")
    bits = 0
    for row in rows:
        for x in range(8):
            bits = (bits << 1) | int(row[x] > row[x + 1])
    return f"{bits:016x}"


def hamming_distance(hash_a: str, hash_b: str) -> int:
    if not re.fullmatch(r"[0-9a-fA-F]{16}", hash_a or "") or not re.fullmatch(r"[0-9a-fA-F]{16}", hash_b or ""):
        raise ValueError("both perceptual hashes must be 16 hexadecimal characters")
    return (int(hash_a, 16) ^ int(hash_b, 16)).bit_count()


def keyed_ocr_fingerprint(text: str, secret: bytes) -> str:
    """Create a keyed fingerprint; never persist raw OCR text in the reuse index."""
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("HMAC secret must contain at least 32 bytes")
    normalized = " ".join(unicodedata.normalize("NFKC", text).casefold().split())
    # Avoid turning IDs/phone/payment numbers into durable linkable values.
    normalized = re.sub(r"(?<!\w)(?:\+?\d[\d .-]{5,}\d)(?!\w)", " [number] ", normalized)
    return hmac.new(secret, normalized.encode("utf-8"), hashlib.sha256).hexdigest()


def compare_fingerprints(candidate: dict, known: dict, threshold: int = 6) -> dict:
    candidate_sha = candidate.get("exact_sha256", "")
    known_sha = known.get("exact_sha256", "")
    if (re.fullmatch(r"[0-9a-f]{64}", candidate_sha or "")
            and re.fullmatch(r"[0-9a-f]{64}", known_sha or "")
            and candidate_sha == known_sha):
        return {"match": "exact", "distance": 0, "strength": "exact_file_match", "meaning": "The uploaded files are byte-for-byte identical."}
    a, b = candidate.get("dhash"), known.get("dhash")
    if a and b:
        distance = hamming_distance(a, b)
        if distance <= threshold:
            return {"match": "likely_visual_reuse", "distance": distance, "strength": "perceptual_similarity", "meaning": "The images are visually similar. This may reflect reuse, a crop or a common product photo; it does not identify the uploader or prove fraud."}
        if distance <= threshold * 2:
            return {"match": "possible_visual_similarity", "distance": distance, "strength": "weak_similarity", "meaning": "The images have some visual similarity and need human review."}
    return {"match": "no_match_found", "distance": None, "strength": "none", "meaning": "No match was found in the available fingerprint index; this is not proof the image is original."}


def interpret_content_credentials(status: str, issuer: str | None = None) -> dict:
    allowed = {"valid", "invalid", "not_present", "not_checked", "unavailable"}
    if status not in allowed:
        raise ValueError("unsupported content-credentials status")
    if status == "valid":
        return {"status": status, "meaning": "A supported content-provenance manifest validated.",
                "attribution": issuer if issuer else "issuer not identified", "limitation": "A valid manifest is evidence about a signed media history, not a complete guarantee that the depicted claim is true."}
    if status == "invalid":
        return {"status": status, "meaning": "A manifest was present but did not validate.", "attribution": None,
                "limitation": "Validation failure requires technical review; it does not automatically prove malicious editing."}
    return {"status": status, "meaning": "No valid content-provenance result is available.", "attribution": None,
            "limitation": "Metadata and credentials may be removed by screenshots, compression, editing or platform processing. Absence is not proof of synthetic or deceptive content."}
