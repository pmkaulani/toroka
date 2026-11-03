from __future__ import annotations
import re
import unicodedata

PATTERNS = {
    "credential_theft": [r"\botp\b", r"one[- ]time (?:password|code)", r"pin yako", r"nambari ya siri", r"share (?:your )?(?:pin|password|code)", r"nipe (?:code|pin)"],
    "remote_access_pressure": [r"anydesk", r"teamviewer", r"remote access", r"install (?:this )?app.*screen", r"ruhusu .*screen"],
    "urgent_payment_pressure": [r"pay now", r"send (?:the )?money now", r"before your account is blocked", r"lipa sasa", r"tuma pesa sasa", r"utapoteza nafasi"],
    "impersonation_pressure": [r"i am calling from (?:your )?(?:bank|safaricom|police)", r"tunapiga kutoka safaricom", r"from the government", r"serikali imekuchagua"],
}


def analyze_call_transcript(transcript: str, *, consent_confirmed: bool, provider: str, artifact_ref: str,
                            speaker_role: str = "unknown", speaker_role_reviewed: bool = False) -> dict:
    """Analyze an already-transcribed recording. This is not voice-cloning detection."""
    if not consent_confirmed:
        raise PermissionError("explicit user notice/consent is required before processing a call recording")
    if not isinstance(transcript, str) or len(transcript) > 30_000:
        raise ValueError("transcript must be text up to 30,000 characters")
    if not provider or len(provider) > 80:
        raise ValueError("transcription provider must be identified")
    if speaker_role not in {"external_party", "user", "unknown"}:
        raise ValueError("speaker_role must be external_party, user or unknown")
    clean = unicodedata.normalize("NFKC", transcript).casefold()
    matched = []
    for category, patterns in PATTERNS.items():
        hits = [pattern for pattern in patterns if re.search(pattern, clean, re.IGNORECASE)]
        if hits:
            matched.append({"category": category, "pattern_count": len(hits)})
    findings = []
    for hit in matched:
        label = hit["category"].replace("_", " ")
        attributed_external = speaker_role == "external_party" and speaker_role_reviewed is True
        findings.append({"artifact_ref": artifact_ref, "source_group": "user_submitted_artifact", "category": f"audio_{hit['category']}",
                         "severity": "medium", "polarity": "risk" if attributed_external else "context", "confidence": 0.62,
                         "summary": f"Call transcript contains {label} language",
                         "explanation": "A transcript pattern indicates language associated with a common social-engineering tactic. It is risk-polarity only where a reviewer has attributed the words to the external party; otherwise it remains context. Transcription errors, quotation, jokes and legitimate contexts are possible; listen to the original before concluding.",
                         "excerpt": "Transcript content withheld; see consented source recording in the user's session.",
                         "limitations": ["Text analysis does not authenticate the caller or detect AI-cloned voices.", "Transcription can mishear Kiswahili, Sheng, accents, names and numbers."]})
    return {"provider": provider, "findings": findings, "matched_categories": [r["category"] for r in matched],
            "raw_transcript_stored": False, "speaker_role": speaker_role, "speaker_role_reviewed": bool(speaker_role_reviewed),
            "limitations": ["This module analyzes supplied transcript text only; audio bytes are not uploaded, retained or assessed here.",
                            "No voice identity or synthetic-voice conclusion is produced; speaker-role attribution, when present, is supplied by a reviewer rather than inferred here."]}
