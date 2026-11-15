"""Declarative source mapping: any system's export -> the canonical feeds, with no code per bank.



A mapping (TOML) says, per feed: which file, delimiter, encoding, which source column is each canonical column, how timestamps

are written, and how the bank's codes translate to canonical vocabulary. Unmapped codes are COUNTED and reported (never silently

dropped), and canonical columns the system does not supply are recorded as absent so detectors never infer risk from missing data.

"""

from __future__ import annotations



import csv

import glob

import os

import tomllib

from collections import Counter

from dataclasses import dataclass, field

from datetime import datetime, timezone

from pathlib import Path



CANONICAL_ACTIONS = ("profile_view", "contact_change", "card_issue", "beneficiary_add", "limit_change", "account_reactivate")



TS_COLUMNS = {"hr_roster": {"end_date"}, "audit_log": {"ts"}, "service_requests": {"opened_at", "closed_at"}, "instructions": {"received_at", "recorded_at"},

              "payments": {"ts"}, "customers": {"dormant_since"}, "postings": {"ts"}}

# Columns a system may legitimately not supply. Their absence is recorded and detectors that depend on them stand down.

OPTIONAL = {"audit_log": {"approver_account_id", "customer_id"}, "service_requests": {"closed_at", "staff_id"},

            "instructions": {"recorded_at"}, "customers": {"dormant_since", "deceased_flag", "is_sensitive"}, "system_accounts": {"is_privileged"},

            "hr_roster": {"end_date", "salary_account"}, "postings": {"approved_by_account", "counter_party"}, "payments": {"beneficiary"}}





class MappingError(ValueError):

    pass





@dataclass

class FeedMapping:

    file: str

    columns: dict[str, str]

    delimiter: str = ","

    encoding: str = "utf-8-sig"

    ts_format: str = "iso"                       # iso | epoch_s | epoch_ms | any strptime format

    values: dict[str, dict[str, str]] = field(default_factory=dict)

    defaults: dict[str, str] = field(default_factory=dict)





@dataclass

class Mapping:

    feeds: dict[str, FeedMapping]

    naive_tz_offset_hours: int = 3





def load_mapping(source: str | Path) -> Mapping:

    from .ingest import SPEC

    text = Path(source).read_text(encoding="utf-8") if (isinstance(source, Path) or (len(str(source)) < 300 and os.path.exists(str(source)))) else str(source)

    try:

        raw = tomllib.loads(text)

    except tomllib.TOMLDecodeError as exc:

        raise MappingError(f"mapping is not valid TOML: {exc}") from exc

    feeds: dict[str, FeedMapping] = {}

    for name, body in (raw.get("feeds") or {}).items():

        if name not in SPEC:

            raise MappingError(f"unknown feed '{name}'; valid feeds: {', '.join(SPEC)}")

        cols = body.get("columns") or {}

        bad = [c for c in cols if c not in SPEC[name]]

        if bad:

            raise MappingError(f"feed {name}: unknown canonical column(s) {', '.join(bad)}; valid: {', '.join(SPEC[name])}")

        defaults = {k: str(v) for k, v in (body.get("defaults") or {}).items()}

        missing = [c for c in SPEC[name] if c not in cols and c not in defaults and c not in OPTIONAL.get(name, set())]

        if missing:

            raise MappingError(f"feed {name}: required canonical column(s) not mapped: {', '.join(missing)}")

        if "file" not in body:

            raise MappingError(f"feed {name}: 'file' (name or glob) is required")

        feeds[name] = FeedMapping(file=body["file"], columns=dict(cols), delimiter=body.get("delimiter", ","), encoding=body.get("encoding", "utf-8-sig"),

                                  ts_format=body.get("timestamp_format", "iso"),

                                  values={c: {str(k): str(v) for k, v in m.items()} for c, m in (body.get("values") or {}).items()}, defaults=defaults)

    if not feeds:

        raise MappingError("mapping defines no feeds")

    return Mapping(feeds, int(raw.get("naive_tz_offset_hours", 3)))





def to_iso(value: str, fmt: str) -> str:

    v = (value or "").strip()

    if not v or fmt == "iso":

        return v

    if fmt in ("epoch_s", "epoch_ms"):

        n = float(v) / (1000 if fmt == "epoch_ms" else 1)

        return datetime.fromtimestamp(n, timezone.utc).isoformat()

    return datetime.strptime(v, fmt).isoformat()      # naive on purpose: ingest applies the declared offset and counts it





def read_mapped(directory: Path, name: str, fm: FeedMapping, q) -> list[tuple[int, dict]] | None:

    from .ingest import SPEC

    files = sorted(glob.glob(glob.escape(str(directory)) + os.sep + fm.file))

    if not files:

        q.feeds_missing.append(name)

        return None


    from .manifest import file_fingerprint

    q.inputs[name] = [file_fingerprint(Path(x)) for x in files]

    out: list[tuple[int, dict]] = []

    unmapped: Counter = Counter()

    ts_fail = 0

    for path in files:

        with open(path, newline="", encoding=fm.encoding) as fh:

            reader = csv.DictReader(fh, delimiter=fm.delimiter)

            headers = {(h or "").strip().lower(): h for h in (reader.fieldnames or [])}

            lookup = {}

            for canon, src in fm.columns.items():

                actual = headers.get(src.strip().lower())

                if actual is None:

                    raise MappingError(f"{Path(path).name}: mapped source column '{src}' (for {name}.{canon}) is not in the file; found: {', '.join(reader.fieldnames or [])}")

                lookup[canon] = actual

            for line, row in enumerate(reader, start=2):

                rec: dict[str, str] = {}

                for canon in SPEC[name]:

                    if canon in lookup:

                        v = (row.get(lookup[canon]) or "").strip()

                    else:

                        v = fm.defaults.get(canon, "")

                    if canon in fm.values and v:

                        m = fm.values[canon]

                        hit = m.get(v, m.get(v.upper(), m.get(v.lower())))

                        if hit is None:

                            unmapped[f"{canon}={v}"] += 1

                        else:

                            v = hit

                    if canon in TS_COLUMNS.get(name, ()) and v:

                        try:

                            v = to_iso(v, fm.ts_format)

                        except (ValueError, OverflowError):

                            ts_fail += 1            # left raw: the handler rejects the row with its own reason

                    rec[canon] = v

                out.append((line, rec))

    for canon in SPEC[name]:

        if canon not in fm.columns and canon not in fm.defaults:

            q.absent_fields.append(f"{name}.{canon}")

    if unmapped:

        q.unmapped_values[name] = dict(unmapped.most_common(15))

    if ts_fail:

        q.ts_format_failures[name] = ts_fail

    return out

