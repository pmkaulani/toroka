from __future__ import annotations

import csv
import hashlib
import io
import re
from datetime import date, datetime, timezone
from typing import Any

from .normalization import email_domain, normalize_domain, normalize_name, normalize_registration_number, GENERIC_EMAIL_DOMAINS

MAX_CSV_BYTES = 5 * 1024 * 1024
MAX_ROWS = 5000
ALLOWED_NEA_SOURCES = {
    "https://www.neaims.go.ke/employmentagencylist.aspx",
    "https://www.diaspora.go.ke/verify",
    "https://diaspora.go.ke/verify",
}


def validate_nea_source_url(source_url: str) -> str:
    from urllib.parse import urlsplit
    raw = str(source_url or "").strip()
    try:
        parsed = urlsplit(raw)
        host = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise ValueError("source_url is malformed") from exc
    canonical = f"https://{host}{parsed.path}".rstrip("/")
    if parsed.scheme != "https" or parsed.username or parsed.password or port not in (None, 443) or parsed.query or parsed.fragment or canonical.casefold() not in ALLOWED_NEA_SOURCES:
        raise ValueError("source_url must be an approved official NEA public-register URL")
    return canonical


def _field(row: dict[str, Any], *names: str) -> str:
    values = {re.sub(r"[^a-z0-9]+", "", str(k).casefold()): str(v or "").strip() for k, v in row.items()}
    for name in names:
        key = re.sub(r"[^a-z0-9]+", "", name.casefold())
        if values.get(key):
            return values[key]
    return ""


def parse_register_date(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw or raw.casefold() in {"n/a", "na", "none", "-", "nil"}:
        return None
    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%Y/%m/%d"):
        try:
            return datetime.strptime(raw, fmt).date().isoformat()
        except ValueError:
            continue
    return None


def parse_nea_csv(data: bytes, *, source_url: str, data_as_of: str) -> dict:
    if not isinstance(data, bytes) or not data or len(data) > MAX_CSV_BYTES:
        raise ValueError("CSV must be between 1 byte and 5 MB")
    validate_nea_source_url(source_url)
    try:
        as_of = date.fromisoformat(data_as_of)
    except Exception as exc:
        raise ValueError("data_as_of must be YYYY-MM-DD") from exc
    if as_of > date.today():
        raise ValueError("data_as_of cannot be in the future")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("NEA register CSV must be UTF-8") from exc
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    if not reader.fieldnames:
        raise ValueError("CSV has no header row")
    required = {
        "registration": ("NEA Reg No", "NEA Registration Number", "Registration Number", "Reg No"),
        "name": ("Agency Name", "Employment Agency", "Name"),
        "status": ("Status", "Licence Status", "License Status"),
    }
    header_keys = {re.sub(r"[^a-z0-9]+", "", x.casefold()) for x in reader.fieldnames}
    for field, aliases in required.items():
        if not any(re.sub(r"[^a-z0-9]+", "", x.casefold()) in header_keys for x in aliases):
            raise ValueError(f"CSV is missing required {field} column")

    rows: list[dict] = []
    seen: set[str] = set()
    invalid = 0
    processed = 0
    for raw in reader:
        processed += 1
        if processed > MAX_ROWS:
            raise ValueError(f"CSV exceeds {MAX_ROWS} records")
        reg_no = normalize_registration_number(_field(raw, *required["registration"]))
        name = _field(raw, *required["name"])
        if not reg_no or not name:
            invalid += 1
            continue
        if not re.fullmatch(r"[A-Z]{1,4}/\d{4}/\d{1,2}/\d{1,4}", reg_no):
            invalid += 1
            continue
        if len(name) > 180:
            name = name[:180]
        key = reg_no
        if key in seen:
            invalid += 1
            continue
        seen.add(key)
        status_raw = _field(raw, *required["status"]).casefold()
        if status_raw in {"valid", "active", "licensed", "licenced"}:
            status = "valid"
        elif status_raw in {"expired", "lapsed"}:
            status = "expired"
        elif status_raw in {"suspended", "suspend"}:
            status = "suspended"
        elif status_raw in {"revoked", "cancelled", "canceled", "withdrawn"}:
            status = "revoked"
        else:
            status = "unknown"
        valid_from = parse_register_date(_field(raw, "Certificate Valid From", "Valid From", "Start Date"))
        expires_on = parse_register_date(_field(raw, "Certificate Expiry", "Certificate Expiry Date", "Expiry Date", "Valid Until"))
        email_raw = _field(raw, "E-mail Address", "Email Address", "Email", "E-mail")
        email_domains = []
        for address in re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", email_raw, flags=re.I):
            domain = email_domain(address)
            if domain:
                email_domains.append(domain)
        websites_raw = _field(raw, "Website", "Web Site", "Website URL")
        website_domains = []
        for part in re.split(r"[;,\s]+", websites_raw):
            domain = normalize_domain(part)
            if domain and domain not in {"none", "nil", "n-a"}:
                website_domains.append(domain)
        service_type = _field(raw, "Service Type", "Services", "Agency Type")[:100]
        rows.append({
            "registration_number": reg_no,
            "agency_name": name,
            "normalized_name": normalize_name(name),
            "service_type": service_type,
            "email_domains": sorted(set(email_domains)),
            "website_domains": sorted(set(website_domains)),
            "licence_status": status,
            "valid_from": valid_from,
            "expires_on": expires_on,
            "row_sha256": hashlib.sha256("|".join([reg_no, name, status_raw, email_raw, websites_raw]).encode()).hexdigest(),
        })
    if not rows:
        raise ValueError("No valid NEA register rows were found")
    return {
        "source_url": validate_nea_source_url(source_url),
        "data_as_of": as_of.isoformat(),
        "retrieved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "content_sha256": hashlib.sha256(data).hexdigest(),
        "record_count": len(rows),
        "invalid_rows": invalid,
        "rows": rows,
    }


def snapshot_freshness(data_as_of: str, *, today: date | None = None) -> dict:
    today = today or date.today()
    try:
        age = max(0, (today - date.fromisoformat(data_as_of)).days)
    except Exception:
        return {"age_days": None, "freshness": "unknown"}
    label = "fresh" if age <= 7 else "aging" if age <= 30 else "stale"
    return {"age_days": age, "freshness": label}


def public_entry(row: Any, snapshot: Any, *, today: date | None = None) -> dict:
    freshness = snapshot_freshness(snapshot.data_as_of, today=today)
    effective = row.licence_status
    if freshness["freshness"] == "stale" and effective == "valid":
        status = "historical_valid_status_not_current"
    elif row.expires_on:
        try:
            if date.fromisoformat(row.expires_on) < (today or date.today()) and effective == "valid":
                status = "expired_by_record_date"
            else:
                status = effective
        except Exception:
            status = effective
    else:
        status = effective
    return {
        "registration_number": row.registration_number,
        "agency_name": row.agency_name,
        "service_type": row.service_type,
        "website_domains": row.website_domains or [],
        "email_domains": row.email_domains or [],
        "licence_status_in_source": row.licence_status,
        "display_status": status,
        "valid_from": row.valid_from,
        "expires_on": row.expires_on,
        "record_source_url": snapshot.source_url,
        "data_as_of": snapshot.data_as_of,
        "retrieved_at": snapshot.retrieved_at,
        **freshness,
        "limitations": [
            "This is an imported snapshot of the official public register, not a live NEAIMS query.",
            "A licence listing does not prove that a person contacting you represents the agency or that a specific vacancy is genuine.",
            "Public contact domains can be shared email providers and do not independently establish ownership.",
        ],
    }
