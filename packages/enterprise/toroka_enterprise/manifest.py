"""Run manifests and reproducibility: 'can the bank reproduce a previous result?'

A manifest pins everything a result depends on: the exact input files (SHA-256), the mapping, the scoring policy, the thresholds, the tool
version and a fingerprint of the pseudonymisation key (never the key). The same manifest id plus the same inputs must give the same result digest.
Row-level hashes are not stored: (file hash + row number) identifies a source record, and the file hash is what an auditor can re-check.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from . import __version__


def file_fingerprint(path: Path) -> dict:
    h, n = hashlib.sha256(), 0
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
            n += len(chunk)
    return {"file": Path(path).name, "sha256": h.hexdigest(), "bytes": n}


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def build_manifest(quality, *, mapping_text: str | None, rules, profile, secret: str | bytes) -> dict:
    raw_secret = secret.encode() if isinstance(secret, str) else secret
    from .data_contract import CONTRACT_VERSION, contract_fingerprint
    body = {
        "schema": 1, "tool_version": __version__, "profile": profile.name,
        "contract_version": CONTRACT_VERSION,
        "contract_sha256": contract_fingerprint(),
        "scoring_policy_sha256": _sha(_canon(asdict(profile.scoring))), "rules": asdict(rules),
        "mapping_sha256": _sha(mapping_text) if mapping_text else "canonical-csv",
        "naive_tz_offset_hours": int(quality.naive_tz.utcoffset(None).total_seconds() // 3600),
        "inputs": {k: sorted(v, key=lambda f: f["file"]) for k, v in sorted(quality.inputs.items())},
        "rows_read": dict(sorted(quality.rows_read.items())),
        "pseudonym_key_fingerprint": hmac.new(raw_secret, b"toroka-ent:key-fingerprint", hashlib.sha256).hexdigest()[:12],
    }
    body["manifest_id"] = _sha(_canon(body))[:16]          # deterministic from inputs + configuration only
    body["ingested_at"] = datetime.now(timezone.utc).isoformat()
    return body


def result_digest(scan) -> str:
    """Digest of what the scan concluded. Random evidence ids are excluded so identical runs digest identically."""
    items = []
    for lead in scan.leads:
        d = lead.to_dict()
        ev = sorted((e["polarity"], e["source_group"], e["summary"], tuple(e["metadata"].get("record_refs", [])), e["strength"])
                    for k in ("risk_evidence", "supporting_evidence", "context_evidence") for e in d[k])
        items.append([d["focus"], d["verdict"], d["risk_index"], d["confidence"], ev])
    items.sort(key=lambda x: x[0])
    return _sha(_canon(items))


def reproduce(stored: dict, stored_digest: str, data_dir: str | Path, *, mapping_text: str | None, rules, profile, secret: str) -> dict:
    from .ingest import ingest_dir
    from .mapping import load_mapping
    from .pseudonym import Pseudonymiser
    from .scan import run_scan
    ds, q = ingest_dir(data_dir, Pseudonymiser(secret), load_mapping(mapping_text) if mapping_text else None)
    now = build_manifest(q, mapping_text=mapping_text, rules=rules, profile=profile, secret=secret)
    changed = []
    for feed in sorted(set(stored["inputs"]) | set(now["inputs"])):
        old = {f["file"]: f["sha256"] for f in stored["inputs"].get(feed, [])}
        new = {f["file"]: f["sha256"] for f in now["inputs"].get(feed, [])}
        changed += [f"{feed}/{name}" for name in sorted(set(old) | set(new)) if old.get(name) != new.get(name)]
    config_diff = [k for k in ("tool_version", "profile", "contract_version", "contract_sha256", "scoring_policy_sha256", "rules", "mapping_sha256", "naive_tz_offset_hours", "pseudonym_key_fingerprint")
                   if stored.get(k) != now.get(k)]
    digest = result_digest(run_scan(ds, rules, q))
    ok = not changed and not config_diff and digest == stored_digest
    if ok:
        why = "Inputs, configuration and result are identical to the original run."
    elif changed:
        why = "Source files differ from the original run (" + ", ".join(changed[:5]) + "): this is a different analysis, not a failed reproduction."
    elif config_diff:
        why = "Configuration differs from the original run (" + ", ".join(config_diff) + ")."
    else:
        why = "Inputs and configuration match but the result differs: investigate non-determinism."
    return {"ok": ok, "inputs_match": not changed, "changed_files": changed, "config_differences": config_diff, "digest_match": digest == stored_digest,
            "original_manifest_id": stored["manifest_id"], "current_manifest_id": now["manifest_id"], "explanation": why}
