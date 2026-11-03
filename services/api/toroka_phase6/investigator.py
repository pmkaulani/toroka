from __future__ import annotations
from .models import Finding, Phase6Result
import re
from .web_forensics import analyze_site_snapshot
from .social_intelligence import inspect_social_observation, social_observation_findings
from .image_intelligence import exact_file_hash, dhash_from_grayscale, compare_fingerprints, interpret_content_credentials
from .audio_intelligence import analyze_call_transcript
from .business_verification import compare_business_records


def _ref(value: str) -> str:
    if (not isinstance(value, str) or len(value) < 8 or len(value) > 80
            or re.fullmatch(r"\+?2547\d{8}|0?7\d{8}", value)):
        raise ValueError("artifact_ref must be an opaque 8-80 character identifier, not a phone number")
    return value


class Phase6Investigator:
    """Pure analysis/orchestration layer; provider networking is deliberately external."""
    def investigate(self, *, case_ref: str, website_snapshot: dict | None = None,
                    social_observations: list[dict] | None = None,
                    image_artifacts: list[dict] | None = None,
                    audio_transcripts: list[dict] | None = None,
                    business_checks: list[dict] | None = None) -> Phase6Result:
        _ref(case_ref)
        findings = []
        sections = {"website": [], "social": [], "images": [], "audio": [], "business": []}
        if website_snapshot:
            for idx, row in enumerate(analyze_site_snapshot(website_snapshot)):
                f = Finding(ref=f"webscan_{idx:04d}", source_group="public_web_observation", category=row["category"], severity=row["severity"],
                            polarity=row["polarity"], summary=row["summary"], explanation=row["explanation"], confidence=row["confidence"],
                            limitations=("Based on a supplied passive-scan snapshot, not a direct Toroka network fetch.",))
                findings.append(f); sections["website"].append(row)
        for index, observation in enumerate(social_observations or []):
            artifact_ref = _ref(observation.get("artifact_ref", f"social_{index:04d}"))
            record = inspect_social_observation(observation)
            for j, row in enumerate(social_observation_findings(record, artifact_ref)):
                findings.append(Finding(ref=f"soc_{index:03d}_{j:03d}", source_group=row["source_group"], category=row["category"], severity=row["severity"],
                                        polarity=row["polarity"], summary=row["summary"], explanation=row["explanation"], confidence=row["confidence"],
                                        limitations=tuple(record["limitations"])))
            sections["social"].append({k: v for k, v in record.items() if k != "public_fields"} | {"public_fields": record["public_fields"]})
        for index, image in enumerate(image_artifacts or []):
            artifact_ref = _ref(image.get("artifact_ref", f"image_{index:04d}"))
            raw = image.get("bytes", b"")
            digest = exact_file_hash(raw)
            dhash = dhash_from_grayscale(image["grayscale_8x9"]) if image.get("grayscale_8x9") else None
            candidate = {"exact_sha256": digest, "dhash": dhash}
            matches = [compare_fingerprints(candidate, known) for known in image.get("known_fingerprints", [])]
            best = next((m for m in matches if m["match"] == "exact"), None) or next((m for m in matches if m["match"] == "likely_visual_reuse"), None) or next((m for m in matches if m["match"] == "possible_visual_similarity"), None)
            credentials = interpret_content_credentials(image.get("c2pa_status", "not_checked"), image.get("c2pa_issuer"))
            row = {"artifact_ref": artifact_ref, "sha256": digest, "dhash": dhash, "reuse_match": best or {"match": "no_match_found", "strength": "none"},
                   "content_credentials": credentials, "raw_image_stored": False,
                   "limitations": ["Image similarity does not identify who uploaded an image or prove deception.", "No face recognition or identity matching is performed."]}
            sections["images"].append(row)
            if best and best["match"] in {"exact", "likely_visual_reuse"}:
                findings.append(Finding(ref=f"img_{index:04d}", source_group="public_web_observation" if best["match"] != "exact" else "user_submitted_artifact",
                                        category="image_reuse_match", severity="low", polarity="context", summary="Image matches a previously observed image",
                                        explanation=best["meaning"], confidence=0.95 if best["match"] == "exact" else 0.72,
                                        limitations=("A shared supplier catalogue or stock image can be legitimate; inspect ownership and context.",)))
        for index, item in enumerate(audio_transcripts or []):
            result = analyze_call_transcript(item.get("transcript", ""), consent_confirmed=item.get("consent_confirmed") is True,
                                             provider=item.get("provider", "unspecified"), artifact_ref=_ref(item.get("artifact_ref", f"audio_{index:04d}")),
                                             speaker_role=item.get("speaker_role", "unknown"), speaker_role_reviewed=item.get("speaker_role_reviewed") is True)
            sections["audio"].append({"provider": result["provider"], "matched_categories": result["matched_categories"],
                                      "speaker_role": result["speaker_role"], "speaker_role_reviewed": result["speaker_role_reviewed"],
                                      "raw_transcript_stored": False, "limitations": result["limitations"]})
            for j, row in enumerate(result["findings"]):
                findings.append(Finding(ref=f"aud_{index:03d}_{j:03d}", source_group=row["source_group"], category=row["category"], severity=row["severity"],
                                        polarity=row["polarity"], summary=row["summary"], explanation=row["explanation"], confidence=row["confidence"],
                                        excerpt=row["excerpt"], limitations=tuple(row["limitations"])))
        for index, item in enumerate(business_checks or []):
            _ref(item.get("artifact_ref", f"business_{index:04d}"))
            result = compare_business_records(item.get("claim", {}), item.get("record", {}))
            sections["business"].append(result)
            if result["status"] in {"registry_record_mismatch", "partial_registry_match", "location_candidate_discrepancy"}:
                category = "business_location_comparison" if result["status"] == "location_candidate_discrepancy" else "business_registry_comparison"
                findings.append(Finding(ref=f"biz_{index:04d}", source_group=result["source_group"], category=category,
                                        severity="medium" if result["status"] == "registry_record_mismatch" else "low", polarity="context",
                                        summary="Business details do not fully match the supplied registry record" if result["status"] == "registry_record_mismatch" else ("Claimed address differs from a map listing" if result["status"] == "location_candidate_discrepancy" else "Business details partially match the supplied registry record"),
                                        explanation="One or more submitted business details differ from, or are absent in, the supplied official record. Confirm spelling, branch details and document recency before drawing conclusions.",
                                        confidence=0.8 if result["status"] == "registry_record_mismatch" else 0.6,
                                        limitations=tuple(result["limitations"])))
        next_steps = ["Open the original source for each observation and confirm its date and collection method.",
                      "Ask the seller to provide independently verifiable business details when identity remains unclear.",
                      "Do not send money, OTPs, PINs or remote-access permissions while a material discrepancy remains unresolved."]
        limitations = ["Phase 6 performs no social-platform scraping and no direct outbound website requests.",
                       "Screenshot, audio transcript, map listing and similarity findings are observations, not proof of identity or criminal conduct.",
                       "A clean scan or no image match is not proof that a seller is legitimate."]
        return Phase6Result(case_ref=case_ref, findings=findings, sections=sections, next_steps=next_steps, limitations=limitations)

