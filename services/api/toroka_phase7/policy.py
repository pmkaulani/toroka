from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
from urllib.parse import urlsplit

@dataclass(frozen=True, slots=True)
class FeedPolicy:
    source_id: str
    provider_name: str
    endpoint_url: str
    terms_url: str
    allowed_hosts: tuple[str, ...]
    commercial_use_allowed: bool
    internal_check_allowed: bool
    display_allowed: bool
    redistribution_allowed: bool
    permission_confirmed: bool
    terms_reviewed_at: str | None = None
    terms_review_valid_days: int = 180
    attribution: str = ""
    poll_interval_seconds: int = 3600
    freshness_ttl_seconds: int = 86400
    max_response_bytes: int = 5_000_000
    max_indicators: int = 100_000
    max_failures_before_circuit: int = 5
    circuit_cooldown_seconds: int = 900

    def validate(self, *, commercial_mode: bool = True, now=None) -> None:
        if not self.source_id or len(self.source_id) > 64:
            raise ValueError("source_id must be 1-64 characters")
        if not self.provider_name.strip():
            raise ValueError("provider_name is required")
        if not self.terms_reviewed_at:
            raise PermissionError("provider terms must have a recorded review date")
        try:
            reviewed = datetime.fromisoformat(self.terms_reviewed_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("terms_reviewed_at must be ISO-8601") from exc
        if reviewed.tzinfo is None:
            raise ValueError("terms_reviewed_at must include a timezone")
        current = now or datetime.now(timezone.utc)
        if isinstance(current, str):
            current = datetime.fromisoformat(current.replace("Z", "+00:00"))
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        age_days = (current.astimezone(timezone.utc) - reviewed.astimezone(timezone.utc)).total_seconds() / 86400
        if not 1 <= self.terms_review_valid_days <= 365:
            raise ValueError("terms_review_valid_days must be between 1 and 365")
        if age_days < 0:
            raise ValueError("terms_reviewed_at cannot be in the future")
        if age_days > self.terms_review_valid_days:
            raise PermissionError("provider terms review has expired; re-review before enabling the feed")
        for field_name, value in (("endpoint_url", self.endpoint_url), ("terms_url", self.terms_url)):
            parts = urlsplit(value)
            if parts.scheme.lower() != "https" or not parts.hostname or parts.username or parts.password:
                raise ValueError(f"{field_name} must be a public HTTPS URL")
            if parts.fragment or (field_name == "endpoint_url" and parts.query):
                raise ValueError(f"{field_name} must not contain fragments or endpoint query parameters; keep API keys in headers")
            host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
            if host in {"localhost", "127.0.0.1"} or host.endswith((".local", ".internal", ".test", ".invalid")):
                raise ValueError(f"{field_name} must use a public host")
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                address = None  # hostname, not a literal IP address
            if address is not None and not address.is_global:
                raise ValueError(f"{field_name} must use a globally routable host")
        endpoint_host = urlsplit(self.endpoint_url).hostname.encode("idna").decode("ascii").lower().rstrip(".")
        allowed = {h.encode("idna").decode("ascii").lower().rstrip(".") for h in self.allowed_hosts}
        if endpoint_host not in allowed or not allowed:
            raise ValueError("endpoint host must exactly match an explicit allowed host")
        for allowed_host in allowed:
            if "*" in allowed_host or not allowed_host or allowed_host.endswith((".local", ".internal", ".test", ".invalid")):
                raise ValueError("allowed_hosts must contain exact public hosts; wildcards are not supported")
        if commercial_mode and not self.commercial_use_allowed:
            raise PermissionError("provider is not approved for commercial use")
        if not self.internal_check_allowed:
            raise PermissionError("internal indicator checking is not permitted")
        if not self.permission_confirmed:
            raise PermissionError("provider permission has not been confirmed")
        if self.poll_interval_seconds < 60 or self.freshness_ttl_seconds < self.poll_interval_seconds:
            raise ValueError("feed polling/freshness intervals are invalid")
        if not (1024 <= self.max_response_bytes <= 50_000_000):
            raise ValueError("max_response_bytes must be between 1KB and 50MB")
        if not (1 <= self.max_indicators <= 1_000_000):
            raise ValueError("max_indicators is out of range")
        if not (1 <= self.max_failures_before_circuit <= 20):
            raise ValueError("max_failures_before_circuit is out of range")
        if not (60 <= self.circuit_cooldown_seconds <= 86400):
            raise ValueError("circuit cooldown is out of range")


def reference_feed_catalog() -> list[dict]:
    """Reference entries only. All are disabled until live terms/permissions are reviewed."""
    return [
        {
            "provider_name": "PhishTank",
            "terms_url": "https://phishtank.org/terms.php",
            "commercial_use_allowed": None,
            "permission_confirmed": False,
            "reason": "FAQ says API use is permitted, but the current terms page points to Cisco's current EULA; re-review current terms and data display rights before enablement.",
        },
        {
            "provider_name": "OpenPhish Community Feed",
            "terms_url": "https://www.openphish.com/terms.html",
            "commercial_use_allowed": False,
            "permission_confirmed": False,
            "reason": "Terms restrict commercial operational use absent prior written permission.",
        },
        {
            "provider_name": "urlscan.io",
            "terms_url": "https://urlscan.io/terms/",
            "commercial_use_allowed": None,
            "permission_confirmed": False,
            "reason": "Respect plan-specific quotas, private-scan handling and product integration terms; no polling is enabled by default.",
        },
        {
            "provider_name": "URLhaus",
            "terms_url": "https://urlhaus.abuse.ch/api/",
            "commercial_use_allowed": None,
            "permission_confirmed": False,
            "reason": "Confirm current commercial/API terms for the exact feed before use.",
        },
        {
            "provider_name": "National KE-CIRT/CC curated advisories",
            "terms_url": "https://ke-cirt.go.ke/alerts-advisories/",
            "commercial_use_allowed": None,
            "permission_confirmed": False,
            "reason": "Official public advisory and quarterly-report sources; curated citation/summary workflow only. No automated indicator feed endpoint is assumed.",
        },
    ]
