from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit
import ipaddress
import re
import socket

BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".test", ".invalid", ".example")
STANDARD_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True, slots=True)
class TargetValidation:
    allowed: bool
    host: str | None
    scheme: str | None
    port: int | None
    reason: str
    warnings: tuple[str, ...] = ()


def _host_ascii(host: str) -> str:
    host = host.rstrip(".").lower()
    if not host:
        raise ValueError("missing hostname")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid internationalized hostname") from exc
    if len(ascii_host) > 253:
        raise ValueError("hostname exceeds DNS length limit")
    labels = ascii_host.split(".")
    if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        raise ValueError("hostname contains invalid DNS labels")
    return ascii_host


def _is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value.split("%", 1)[0])
    return ip.is_global and not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def validate_target_url(url: str, resolved_addresses: list[str] | tuple[str, ...] = ()) -> TargetValidation:
    """Validate a candidate URL before a separately sandboxed fetcher uses it.

    This function performs no DNS lookup and no network request. The caller must
    resolve once, pass every answer here, and pin the connection to those answers.
    """
    try:
        if not isinstance(url, str) or len(url) > 4096:
            raise ValueError("URL is missing or exceeds 4096 characters")
        parsed = urlsplit(url.strip())
        scheme = parsed.scheme.lower()
        if scheme not in {"https", "http"}:
            raise ValueError("only HTTP and HTTPS targets are permitted")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URLs containing credentials are rejected")
        host = _host_ascii(parsed.hostname or "")
        port = parsed.port or STANDARD_PORTS[scheme]
        if port != STANDARD_PORTS[scheme]:
            raise ValueError("non-standard ports are rejected")
        if host == "localhost" or host.endswith(BLOCKED_SUFFIXES):
            raise ValueError("local or reserved hostname is rejected")
        try:
            ipaddress.ip_address(host)
            if not _is_public_ip(host):
                raise ValueError("non-public IP target is rejected")
        except ValueError as exc:
            # A ValueError raised by _is_public_ip must not be mistaken for a domain.
            if "non-public IP" in str(exc):
                raise
        warnings = []
        if scheme == "http":
            warnings.append("Target uses unencrypted HTTP")
        if resolved_addresses:
            for address in resolved_addresses:
                if not _is_public_ip(address):
                    raise ValueError("DNS answer contains a non-public address")
        elif not _looks_like_ip(host):
            warnings.append("DNS answers have not been validated; do not fetch until they are resolved and pinned")
        return TargetValidation(True, host, scheme, port, "Target passed static validation", tuple(warnings))
    except (ValueError, TypeError) as exc:
        return TargetValidation(False, None, None, None, str(exc))


def _looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def validate_redirect_chain(urls: list[str], resolver_results: list[list[str]] | None = None) -> list[TargetValidation]:
    """Validate every redirect independently; callers must disable auto-follow."""
    resolver_results = resolver_results or [[] for _ in urls]
    if len(resolver_results) != len(urls):
        raise ValueError("one DNS result list is required per redirect target")
    return [validate_target_url(url, ips) for url, ips in zip(urls, resolver_results)]


def analyze_site_snapshot(snapshot: dict) -> list[dict]:
    """Convert a provider/isolated-fetcher snapshot into bounded observations.

    No outbound request is performed here. `snapshot` must be assembled by a
    dedicated SSRF-hardened service that validates DNS at connection time.
    """
    if not isinstance(snapshot, dict):
        raise ValueError("snapshot must be a dictionary")
    out = []
    cert_valid = snapshot.get("tls_certificate_valid")
    hostname_match = snapshot.get("tls_hostname_match")
    cert_days = snapshot.get("tls_days_remaining")
    if cert_valid is False or hostname_match is False:
        out.append({"category": "website_tls_validation_failed", "severity": "medium", "polarity": "risk", "confidence": 0.85,
                    "summary": "Website TLS validation failed", "explanation": "The supplied scan snapshot reports a certificate or hostname validation failure. This can indicate a security/configuration problem, but is not by itself proof of fraud."})
    elif isinstance(cert_days, int) and cert_days < 0:
        out.append({"category": "website_tls_certificate_expired", "severity": "low", "polarity": "context", "confidence": 0.8,
                    "summary": "Website certificate appears expired", "explanation": "The supplied scan reports an expired certificate. This is a connection-security concern, not a seller identity or fraud finding."})
    age = snapshot.get("domain_age_days")
    if isinstance(age, int) and 0 <= age <= 30:
        out.append({"category": "website_recent_domain_registration", "severity": "low", "polarity": "context", "confidence": 0.65,
                    "summary": "Domain registration is recent", "explanation": f"The provided registration observation reports an age of {age} days. New businesses also use new domains; treat this as context only."})
    redirects = snapshot.get("redirect_hosts", [])
    if isinstance(redirects, list) and len(set(str(h).lower() for h in redirects)) > 2:
        out.append({"category": "website_multi_host_redirect_chain", "severity": "low", "polarity": "context", "confidence": 0.55,
                    "summary": "Website uses a multi-host redirect chain", "explanation": "The supplied scan reports redirects across multiple hosts. Advertising, analytics and payment providers can cause this; inspect the destinations before drawing conclusions."})
    headers = snapshot.get("security_headers", {})
    if isinstance(headers, dict):
        important = {"strict-transport-security", "content-security-policy", "x-content-type-options"}
        missing = sorted(h for h in important if not any(k.lower() == h for k in headers))
        if len(missing) >= 2:
            out.append({"category": "website_security_headers_missing", "severity": "low", "polarity": "context", "confidence": 0.55,
                        "summary": "Some browser security headers are absent", "explanation": "The scan did not observe multiple recommended response headers. Their absence is a security-hardening gap, not evidence that a shop is fraudulent."})
    return out
