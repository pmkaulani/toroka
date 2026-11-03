from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import re
import sqlite3
from typing import Any, Iterable
from urllib.parse import urlsplit


@dataclass(frozen=True, slots=True)
class FeedPolicy:
    name: str
    source_group: str
    terms_url: str
    commercial_use_allowed: bool
    permission_confirmed: bool
    display_allowed: bool
    attribution: str
    freshness_ttl_hours: int = 24
    accuracy_note: str = "External threat data can be incomplete or incorrect."

    def validate(self, *, commercial_mode: bool) -> None:
        if commercial_mode and not self.commercial_use_allowed:
            raise PermissionError(f"{self.name} is not approved for commercial use")
        if not self.permission_confirmed:
            raise PermissionError(f"Permission for {self.name} has not been confirmed")
        if self.freshness_ttl_hours <= 0:
            raise ValueError("freshness_ttl_hours must be positive")


@dataclass(frozen=True, slots=True)
class IndicatorRecord:
    indicator_type: str
    value: str
    source_name: str
    confidence: float = 0.7
    first_seen: str | None = None
    valid_until: str | None = None
    labels: tuple[str, ...] = ()
    reference_url: str | None = None
    include_subdomains: bool = False


@dataclass(slots=True)
class ThreatMatch:
    indicator_type: str
    indicator: str
    source_name: str
    source_group: str
    confidence: float
    status: str
    observed_at: str
    expires_at: str | None
    attribution: str
    terms_url: str
    reference_url: str | None
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def normalize_indicator(indicator_type: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("indicator value is required")
    kind = indicator_type.lower().strip()
    raw = value.strip()
    if kind == "domain":
        candidate = raw if "://" in raw else "https://" + raw
        parts = urlsplit(candidate)
        if parts.username or parts.password or not parts.hostname:
            raise ValueError("invalid domain indicator")
        host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if "." not in host or len(host) > 253 or any(not p or len(p) > 63 for p in host.split(".")):
            raise ValueError("invalid domain indicator")
        if host in {"localhost", "127.0.0.1"} or host.endswith((".local", ".internal", ".test", ".invalid")):
            raise ValueError("non-public domain indicator")
        return host
    if kind == "url":
        parts = urlsplit(raw if "://" in raw else "https://" + raw)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
            raise ValueError("invalid URL indicator")
        host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if host in {"localhost", "127.0.0.1"} or host.endswith((".local", ".internal", ".test", ".invalid")):
            raise ValueError("non-public URL indicator")
        # Strip query and fragment; they can contain personal or session tokens.
        path = parts.path or "/"
        if re.search(r"(?i)(token|session|reset|auth|invite|otp|key)[=/_-]", path):
            path = "/"
        return f"{parts.scheme.lower()}://{host}{path}"
    if kind == "sha256":
        digest = raw.lower()
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            raise ValueError("SHA-256 indicators must be 64 hexadecimal characters")
        return digest
    if kind == "ipv4":
        import ipaddress
        ip = ipaddress.ip_address(raw)
        if ip.version != 4 or not ip.is_global:
            raise ValueError("indicator must be a public IPv4 address")
        return str(ip)
    raise ValueError(f"unsupported indicator type: {kind}")


def _safe_reference_url(value: str | None) -> str | None:
    if not value:
        return None
    parts = urlsplit(value.strip())
    if parts.scheme.lower() != "https" or not parts.hostname or parts.username or parts.password:
        raise ValueError("reference_url must be a public HTTPS URL")
    host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    if host in {"localhost", "127.0.0.1"} or host.endswith((".local", ".internal", ".test", ".invalid")):
        raise ValueError("reference_url must use a public host")
    path = parts.path or "/"
    has_sensitive_path = re.search(r"(?i)(token|session|reset|auth|invite|otp|key)[=/_-]", path)
    has_sensitive_query = re.search(r"(?i)(token|session|reset|auth|invite|otp|key)\s*=", parts.query)
    if has_sensitive_path or has_sensitive_query:
        path = "/"
    return f"https://{host}{path[:256]}"


class ThreatIntelStore:
    """Local cache for permitted threat indicators. It never downloads feeds itself."""
    def __init__(self, db_path: str = ":memory:", *, commercial_mode: bool = True):
        self.db_path = db_path
        self.commercial_mode = commercial_mode
        self._policies: dict[str, FeedPolicy] = {}
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("""CREATE TABLE IF NOT EXISTS indicators (
            indicator_type TEXT NOT NULL, value TEXT NOT NULL, source_name TEXT NOT NULL,
            confidence REAL NOT NULL, observed_at TEXT NOT NULL, expires_at TEXT,
            labels_json TEXT NOT NULL, reference_url TEXT, include_subdomains INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(indicator_type,value,source_name))""")
        self.conn.execute("""CREATE TABLE IF NOT EXISTS feed_refresh (
            source_name TEXT PRIMARY KEY, last_success TEXT, last_attempt TEXT, last_error TEXT)""")
        self.conn.commit()

    def register_feed(self, policy: FeedPolicy) -> None:
        policy.validate(commercial_mode=self.commercial_mode)
        self._policies[policy.name] = policy

    def policy(self, source_name: str) -> FeedPolicy:
        try:
            return self._policies[source_name]
        except KeyError as exc:
            raise PermissionError(f"Feed {source_name!r} has no registered permission policy") from exc

    def upsert(self, record: IndicatorRecord) -> None:
        policy = self.policy(record.source_name)
        value = normalize_indicator(record.indicator_type, record.value)
        if not 0.0 <= record.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        now = datetime.now(timezone.utc).isoformat()
        observed = _parse_time(record.first_seen).isoformat() if _parse_time(record.first_seen) else now
        expiry_dt = _parse_time(record.valid_until) or (datetime.now(timezone.utc) + timedelta(hours=policy.freshness_ttl_hours))
        self.conn.execute("""INSERT INTO indicators
            (indicator_type,value,source_name,confidence,observed_at,expires_at,labels_json,reference_url,include_subdomains)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(indicator_type,value,source_name) DO UPDATE SET
            confidence=excluded.confidence, observed_at=excluded.observed_at,
            expires_at=excluded.expires_at, labels_json=excluded.labels_json,
            reference_url=excluded.reference_url, include_subdomains=excluded.include_subdomains""",
            (record.indicator_type.lower(), value, record.source_name, record.confidence, observed,
             expiry_dt.isoformat(), json.dumps(list(record.labels)), _safe_reference_url(record.reference_url), int(record.include_subdomains)))
        self.conn.commit()

    def import_records(self, records: Iterable[IndicatorRecord], source_name: str) -> int:
        """Validate a whole snapshot before committing any rows."""
        policy = self.policy(source_name)
        prepared = []
        for record in records:
            if record.source_name != source_name:
                raise ValueError("all imported records must match the registered feed")
            value = normalize_indicator(record.indicator_type, record.value)
            if not 0.0 <= record.confidence <= 1.0:
                raise ValueError("confidence must be between 0 and 1")
            observed_dt = _parse_time(record.first_seen) or datetime.now(timezone.utc)
            expiry_dt = _parse_time(record.valid_until) or (datetime.now(timezone.utc) + timedelta(hours=policy.freshness_ttl_hours))
            prepared.append((record.indicator_type.lower(), value, source_name, record.confidence,
                             observed_dt.isoformat(), expiry_dt.isoformat(), json.dumps(list(record.labels)),
                             _safe_reference_url(record.reference_url), int(record.include_subdomains)))
        try:
            self.conn.executemany("""INSERT INTO indicators
                (indicator_type,value,source_name,confidence,observed_at,expires_at,labels_json,reference_url,include_subdomains)
                VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(indicator_type,value,source_name) DO UPDATE SET
                confidence=excluded.confidence, observed_at=excluded.observed_at,
                expires_at=excluded.expires_at, labels_json=excluded.labels_json,
                reference_url=excluded.reference_url, include_subdomains=excluded.include_subdomains""", prepared)
            self.conn.commit()
        except Exception:
            self.conn.rollback()
            raise
        return len(prepared)

    def mark_refresh(self, source_name: str, *, success: bool, error: str | None = None) -> None:
        self.policy(source_name)
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute("""INSERT INTO feed_refresh(source_name,last_success,last_attempt,last_error)
            VALUES (?,?,?,?) ON CONFLICT(source_name) DO UPDATE SET
            last_success=CASE WHEN ? THEN excluded.last_attempt ELSE feed_refresh.last_success END,
            last_attempt=excluded.last_attempt,last_error=excluded.last_error""",
            (source_name, now if success else None, now, None if success else (error or "unknown"), int(success)))
        self.conn.commit()

    def refresh_due(self, source_name: str, *, now: datetime | None = None) -> bool:
        policy = self.policy(source_name)
        row = self.conn.execute("SELECT last_success FROM feed_refresh WHERE source_name=?", (source_name,)).fetchone()
        if not row or not row["last_success"]:
            return True
        last = _parse_time(row["last_success"])
        return not last or (now or datetime.now(timezone.utc)) - last >= timedelta(hours=policy.freshness_ttl_hours)

    def lookup_domain(self, domain: str, *, now: datetime | None = None) -> list[ThreatMatch]:
        normalized = normalize_indicator("domain", domain)
        current = now or datetime.now(timezone.utc)
        rows = self.conn.execute("SELECT * FROM indicators WHERE indicator_type='domain'").fetchall()
        found: list[ThreatMatch] = []
        for row in rows:
            candidate = row["value"]
            is_match = normalized == candidate or (bool(row["include_subdomains"]) and normalized.endswith("." + candidate))
            if not is_match:
                continue
            policy = self.policy(row["source_name"])
            expiry = _parse_time(row["expires_at"])
            if expiry and expiry < current:
                status = "expired"
            else:
                refresh_row = self.conn.execute("SELECT last_success FROM feed_refresh WHERE source_name=?", (row["source_name"],)).fetchone()
                last_success = _parse_time(refresh_row["last_success"]) if refresh_row and refresh_row["last_success"] else None
                stale = not last_success or current - last_success > timedelta(hours=policy.freshness_ttl_hours)
                status = "stale_feed" if stale else "active"
            limits = [policy.accuracy_note]
            if status != "active":
                limits.append("This indicator is not from a currently fresh feed snapshot; do not present it as a current confirmed threat match.")
            if not policy.display_allowed:
                limits.append("The provider does not permit direct display of this data; suppress provider details from the user interface.")
            found.append(ThreatMatch(
                indicator_type="domain", indicator=candidate, source_name=row["source_name"],
                source_group=policy.source_group, confidence=float(row["confidence"]), status=status,
                observed_at=row["observed_at"], expires_at=row["expires_at"],
                attribution=policy.attribution if policy.display_allowed else "Provider attribution retained internally",
                terms_url=policy.terms_url, reference_url=row["reference_url"], limitations=limits,
            ))
        return found

    def list_feeds(self) -> list[dict[str, Any]]:
        output = []
        for name, policy in sorted(self._policies.items()):
            row = self.conn.execute("SELECT * FROM feed_refresh WHERE source_name=?", (name,)).fetchone()
            output.append({
                "name": name, "source_group": policy.source_group,
                "commercial_use_allowed": policy.commercial_use_allowed,
                "permission_confirmed": policy.permission_confirmed,
                "display_allowed": policy.display_allowed,
                "attribution": policy.attribution,
                "freshness_ttl_hours": policy.freshness_ttl_hours,
                "last_success": row["last_success"] if row else None,
                "last_attempt": row["last_attempt"] if row else None,
                "last_error": row["last_error"] if row else None,
                "refresh_due": self.refresh_due(name),
            })
        return output

    def close(self) -> None:
        self.conn.close()


def parse_stix21_bundle(bundle: dict[str, Any], *, source_name: str) -> list[IndicatorRecord]:
    """Import the supported subset of STIX 2.1 indicator patterns (domain, URL, IPv4, SHA-256)."""
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("expected a STIX 2.1 bundle")
    output: list[IndicatorRecord] = []
    expressions = [
        ("domain", re.compile(r"domain-name:value\s*=\s*'([^']+)'", re.I)),
        ("url", re.compile(r"url:value\s*=\s*'([^']+)'", re.I)),
        ("ipv4", re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'", re.I)),
        ("sha256", re.compile(r"file:hashes\.'SHA-256'\s*=\s*'([a-f0-9]{64})'", re.I)),
    ]
    for obj in bundle["objects"]:
        if not isinstance(obj, dict) or obj.get("type") != "indicator" or obj.get("revoked"):
            continue
        pattern = obj.get("pattern", "")
        for kind, regex in expressions:
            for value in regex.findall(pattern):
                output.append(IndicatorRecord(
                    indicator_type=kind, value=value, source_name=source_name,
                    confidence=max(0, min(1, float(obj.get("confidence", 70)) / 100)),
                    first_seen=obj.get("valid_from"), valid_until=obj.get("valid_until"),
                    labels=tuple(str(x) for x in obj.get("labels", [])),
                    reference_url=None,
                ))
    return output


def default_feed_policies(*, phishtank_permission_confirmed: bool = False,
                          urlhaus_commercial_permission_confirmed: bool = False,
                          virustotal_premium_permission_confirmed: bool = False,
                          web_risk_permission_confirmed: bool = False,
                          urlscan_product_permission_confirmed: bool = False) -> list[FeedPolicy]:
    """Policies are opt-in: deployment owner must confirm current terms and permissions.

    URLhaus commercial access, VirusTotal Premium, Google Web Risk and urlscan
    product/volume use require a contract or provider confirmation from the deployer.
    """
    return [
        FeedPolicy(
            name="PhishTank", source_group="phishtank",
            terms_url="https://phishtank.org/terms.php", commercial_use_allowed=True,
            permission_confirmed=phishtank_permission_confirmed, display_allowed=True,
            attribution="PhishTank community data; accuracy is not warranted.", freshness_ttl_hours=6,
            accuracy_note="PhishTank data is community-contributed and not warranted for accuracy.",
        ),
        FeedPolicy(
            name="URLhaus", source_group="abuse.ch-urlhaus",
            terms_url="https://urlhaus.abuse.ch/api/", commercial_use_allowed=urlhaus_commercial_permission_confirmed,
            permission_confirmed=urlhaus_commercial_permission_confirmed, display_allowed=True,
            attribution="URLhaus / abuse.ch", freshness_ttl_hours=2,
            accuracy_note="URLhaus focuses on malware distribution, not general ecommerce fraud or all phishing.",
        ),
        FeedPolicy(
            name="VirusTotal Public API", source_group="virustotal-public",
            terms_url="https://docs.virustotal.com/reference/public-vs-premium-api",
            commercial_use_allowed=False, permission_confirmed=False, display_allowed=False,
            attribution="Internal policy guard only", freshness_ttl_hours=24,
            accuracy_note="VirusTotal Public API is not permitted in commercial products or services.",
        ),
        FeedPolicy(
            name="VirusTotal Premium", source_group="virustotal-premium",
            terms_url="https://docs.virustotal.com/reference/public-vs-premium-api",
            commercial_use_allowed=virustotal_premium_permission_confirmed,
            permission_confirmed=virustotal_premium_permission_confirmed, display_allowed=True,
            attribution="VirusTotal Premium; follow the active agreement.", freshness_ttl_hours=6,
            accuracy_note="Use and display only within the provider's contracted scope.",
        ),
        FeedPolicy(
            name="Google Safe Browsing", source_group="google-safe-browsing",
            terms_url="https://developers.google.com/safe-browsing/terms",
            commercial_use_allowed=False, permission_confirmed=False, display_allowed=False,
            attribution="Internal policy guard only", freshness_ttl_hours=1,
            accuracy_note="Safe Browsing is non-commercial absent a separate agreement; use Web Risk for commercial applications.",
        ),
        FeedPolicy(
            name="Google Web Risk", source_group="google-web-risk",
            terms_url="https://cloud.google.com/web-risk/docs/overview",
            commercial_use_allowed=web_risk_permission_confirmed,
            permission_confirmed=web_risk_permission_confirmed, display_allowed=True,
            attribution="Google Web Risk; follow current display and retention terms.", freshness_ttl_hours=1,
            accuracy_note="Use only under an active commercial configuration and applicable display/retention rules.",
        ),
        FeedPolicy(
            name="urlscan Product Integration", source_group="urlscan",
            terms_url="https://docs.urlscan.io/pages/faq",
            commercial_use_allowed=urlscan_product_permission_confirmed,
            permission_confirmed=urlscan_product_permission_confirmed, display_allowed=True,
            attribution="urlscan.io; follow attribution and privacy requirements.", freshness_ttl_hours=6,
            accuracy_note="Commercial workflow use is generally allowed; contact urlscan for high-volume or embedded product use.",
        ),
    ]


def refresh_feed(store: ThreatIntelStore, source_name: str, fetcher):
    """Refresh a registered feed using an injected fetcher; suitable for cron/worker jobs.

    fetcher() must return Iterable[IndicatorRecord]. Network access, authentication,
    rate limits and provider-specific terms remain the adapter's responsibility.
    Existing indicators are retained on failures; expiry is enforced at lookup.
    """
    if not store.refresh_due(source_name):
        return {"source_name": source_name, "status": "not_due", "imported": 0}
    try:
        records = list(fetcher())
        imported = store.import_records(records, source_name)
        store.mark_refresh(source_name, success=True)
        return {"source_name": source_name, "status": "refreshed", "imported": imported}
    except Exception as exc:
        store.mark_refresh(source_name, success=False, error=type(exc).__name__)
        return {"source_name": source_name, "status": "failed", "imported": 0,
                "error_type": type(exc).__name__,
                "note": "Existing feed data was retained; do not treat stale indicators as current matches."}
