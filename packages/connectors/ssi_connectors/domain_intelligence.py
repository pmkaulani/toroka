"""Passive domain and network intelligence for Toroka Build 2.

This module performs bounded lookups against fixed public services only. It does
not crawl websites, port-scan hosts, submit URLs for scanning, or fetch user paths.
Every returned observation is context, not a fraud verdict or proof of ownership.

Providers:
- Google Public DNS JSON DoH for DNS records and resolver DNSSEC (AD) observations.
- IANA RDAP bootstrap registries to locate authoritative domain/IP RDAP services.
- Team Cymru's documented IP-to-origin-ASN DNS service, queried via DNS-over-HTTPS.
- SSLMate Cert Spotter CT Search API (API key required for production use).
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlencode, urlsplit

import httpx

DNS_JSON_URL = "https://dns.google/resolve"
IANA_RDAP_BOOTSTRAPS = {
    "dns": "https://data.iana.org/rdap/dns.json",
    "ipv4": "https://data.iana.org/rdap/ipv4.json",
    "ipv6": "https://data.iana.org/rdap/ipv6.json",
    "asn": "https://data.iana.org/rdap/asn.json",
}
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
TEAM_CYMRU_INFO_URL = "https://www.team-cymru.com/ip-asn-mapping"
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".test", ".invalid", ".example")
DNS_TYPES = ("A", "AAAA", "MX", "NS", "CAA", "TXT")
MAX_DNS_ANSWERS = 30
MAX_CT_RESULTS = 20
MAX_HTTP_BYTES = 2_000_000
_BOOTSTRAP_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_BOOTSTRAP_LOCK = threading.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_domain(value: Any) -> str | None:
    """Normalize a hostname/domain and reject URLs containing credentials or IPs."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw or len(raw) > 2048 or any(ch in raw for ch in "\r\n\x00"):
        return None
    try:
        if "://" in raw:
            parsed = urlsplit(raw)
            if parsed.scheme.lower() not in {"http", "https"} or parsed.username or parsed.password:
                return None
            host = parsed.hostname or ""
        else:
            # This is a hostname field, not a general URL field.
            if any(ch in raw for ch in "/\\?#@"):
                return None
            host = raw
        host = host.rstrip(".").lower()
        if not host or host == "localhost" or any(host.endswith(s) for s in BLOCKED_SUFFIXES):
            return None
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
        host = host.encode("idna").decode("ascii")
        if len(host) > 253:
            return None
        labels = host.split(".")
        if len(labels) < 2:
            return None
        if any(
            not label or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            return None
        if len(labels[-1]) < 2:
            return None
        return host
    except (ValueError, UnicodeError):
        return None


def _request_json(
    url: str,
    *,
    params: Any = None,
    headers: dict[str, str] | None = None,
    transport: httpx.BaseTransport | None = None,
    timeout: float = 4.0,
) -> tuple[dict[str, Any] | list[Any] | None, str | None, int | None]:
    """Fixed-host JSON request. Redirects are disabled and response bodies bounded."""
    try:
        with httpx.Client(transport=transport, timeout=timeout, follow_redirects=False) as client:
            response = client.get(url, params=params, headers=headers or {"Accept": "application/json"})
            status = response.status_code
            if status in {301, 302, 303, 307, 308}:
                return None, "redirect_rejected", status
            response.raise_for_status()
            if len(response.content) > MAX_HTTP_BYTES:
                return None, "response_too_large", status
            data = response.json()
            if not isinstance(data, (dict, list)):
                return None, "invalid_provider_response", status
            return data, None, status
    except httpx.HTTPStatusError as exc:
        return None, f"http_{exc.response.status_code}", exc.response.status_code
    except httpx.TimeoutException:
        return None, "timeout", None
    except (httpx.TransportError, ValueError, TypeError):
        return None, "network_or_invalid_response", None
    except Exception:
        return None, "provider_error", None


def _doh_txt_or_record(name: str, record_type: str, *, transport=None, timeout: float = 3.0) -> tuple[dict[str, Any] | None, str | None]:
    data, error, _ = _request_json(
        DNS_JSON_URL,
        params={"name": name, "type": record_type},
        headers={"Accept": "application/dns-json", "User-Agent": "Toroka-Domain-Intel/2.0"},
        transport=transport,
        timeout=timeout,
    )
    if error:
        return None, error
    if not isinstance(data, dict) or not isinstance(data.get("Status"), int):
        return None, "invalid_dns_response"
    return data, None


def _safe_dns_target(value: str) -> str | None:
    """DNS RDATA hostnames can have a trailing dot; validate after trimming it."""
    return normalize_domain(str(value or "").strip().rstrip("."))


def _summarize_txt(value: str, *, is_dmarc: bool = False) -> str:
    """Never return opaque verification, DKIM or arbitrary TXT tokens to the UI."""
    text = str(value or "").strip().strip('"')
    low = text.casefold()
    if low.startswith("v=spf1"):
        policy = re.search(r"(?:^|\s)([-~?+]all)(?:\s|$)", text, re.I)
        return "SPF policy published" + (f" ({policy.group(1)} ending)" if policy else "")
    if low.startswith("v=dmarc1") or is_dmarc:
        policy = re.search(r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)", text, re.I)
        return "DMARC policy published" + (f" (p={policy.group(1).lower()})" if policy else "")
    if "_domainkey" in low or "v=dkim1" in low:
        return "DKIM record published (key material withheld)"
    if any(marker in low for marker in ("google-site-verification", "facebook-domain-verification", "ms=", "apple-domain-verification")):
        return "Domain verification marker present (token withheld)"
    return "TXT record present (value withheld)"


def query_dns_records(
    domain: str,
    *,
    transport: httpx.BaseTransport | None = None,
    timeout: float = 3.0,
) -> dict[str, Any]:
    """Query a small set of public DNS RR types using DNS-over-HTTPS."""
    host = normalize_domain(domain)
    if not host:
        return {"status": "not_checked", "provider": "Google Public DNS (DoH)", "domain": None,
                "records": [], "addresses": [], "dnssec_validated": None, "failure_reason": "invalid_domain"}

    queries: list[tuple[str, str, bool]] = [(host, rr, False) for rr in DNS_TYPES]
    queries.append((f"_dmarc.{host}", "TXT", True))
    responses: list[tuple[str, str, bool, dict[str, Any] | None, str | None]] = []
    workers = min(6, len(queries))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_doh_txt_or_record, qname, rr, transport=transport, timeout=timeout): (qname, rr, is_dmarc)
            for qname, rr, is_dmarc in queries
        }
        for future in as_completed(futures):
            qname, rr, is_dmarc = futures[future]
            try:
                data, error = future.result()
            except Exception:
                data, error = None, "provider_error"
            responses.append((qname, rr, is_dmarc, data, error))

    records: list[dict[str, Any]] = []
    addresses: list[str] = []
    ad_flags: list[bool] = []
    failures: list[str] = []
    successful = 0
    valid_dns_responses = 0
    rcode_failures: list[int] = []
    nxdomain = False
    for qname, rr, is_dmarc, data, error in responses:
        if error:
            failures.append(error)
            continue
        successful += 1
        assert data is not None
        rcode = data.get("Status")
        if rcode in {0, 3}:
            valid_dns_responses += 1
        elif isinstance(rcode, int):
            rcode_failures.append(rcode)
        else:
            failures.append("invalid_dns_rcode")
            continue
        if rcode == 3:
            nxdomain = True
        if isinstance(data.get("AD"), bool):
            ad_flags.append(bool(data.get("AD")))
        answers = data.get("Answer") if isinstance(data.get("Answer"), list) else []
        for answer in answers[:MAX_DNS_ANSWERS]:
            if not isinstance(answer, dict):
                continue
            try:
                rr_type = int(answer.get("type"))
            except (TypeError, ValueError):
                continue
            # Google DNS RR type IDs: A=1, NS=2, CNAME=5, MX=15, TXT=16, AAAA=28, CAA=257.
            type_name = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 257: "CAA"}.get(rr_type, rr)
            raw_data = str(answer.get("data") or "").strip()
            if not raw_data:
                continue
            ttl = answer.get("TTL") if isinstance(answer.get("TTL"), int) else None
            record: dict[str, Any] = {"type": type_name, "ttl": ttl, "query_name": qname}
            if type_name in {"A", "AAAA"}:
                try:
                    ip = ipaddress.ip_address(raw_data)
                except ValueError:
                    continue
                record["value"] = str(ip)
                record["address_scope"] = "public" if ip.is_global else "non_public_or_special_use"
                if ip.is_global and str(ip) not in addresses:
                    addresses.append(str(ip))
            elif type_name in {"NS", "CNAME"}:
                name = _safe_dns_target(raw_data)
                if not name:
                    continue
                record["value"] = name
            elif type_name == "MX":
                match = re.match(r"^\s*(\d{1,5})\s+(.+?)\.?\s*$", raw_data)
                if not match:
                    continue
                exchange = _safe_dns_target(match.group(2))
                if not exchange:
                    continue
                record["priority"] = int(match.group(1))
                record["value"] = exchange
            elif type_name == "CAA":
                # CAA values identify issuance policy, not business ownership.
                record["value"] = raw_data[:240]
            elif type_name == "TXT":
                record["value"] = _summarize_txt(raw_data, is_dmarc=is_dmarc)
            records.append(record)
            if len(records) >= MAX_DNS_ANSWERS:
                break

    status = "checked" if valid_dns_responses else "failed"
    if valid_dns_responses and not records:
        status = "checked_no_records"
    return {
        "status": status,
        "provider": "Google Public DNS (DoH)",
        "domain": host,
        "records": records,
        "addresses": addresses[:8],
        "dnssec_validated": (all(ad_flags) if ad_flags and successful == len(ad_flags) else False) if successful else None,
        "nxdomain_observed": nxdomain,
        "queries_completed": successful,
        "queries_valid": valid_dns_responses,
        "queries_failed": len(failures) + len(rcode_failures),
        "failure_reason": (failures[0] if failures else (f"dns_rcode_{rcode_failures[0]}" if rcode_failures else None)) if not valid_dns_responses else None,
        "source_url": f"https://dns.google/resolve?{urlencode({'name': host, 'type': 'A'})}",
        "limitations": [
            "DNS records are a point-in-time observation and can change or be cached.",
            "DNSSEC validation is reported only when the resolver sets the authenticated-data (AD) flag.",
            "Private or special-use IP answers are not sent to ASN or IP-registration lookups.",
            "TXT record values that may contain verification tokens or key material are withheld.",
        ],
    }


class IanaRdapClient:
    """Minimal RDAP bootstrap client using IANA's authoritative service registry."""

    def __init__(self, *, transport: httpx.BaseTransport | None = None, timeout: float = 4.0):
        self.transport = transport
        self.timeout = timeout
        self._local_bootstrap: dict[str, dict[str, Any]] = {}

    def _bootstrap(self, kind: str) -> dict[str, Any]:
        if kind in self._local_bootstrap:
            return self._local_bootstrap[kind]
        # Tests using MockTransport get isolated bootstrap state. Real requests use a
        # short process cache; IANA publishes HTTP cache headers for this purpose.
        if self.transport is None:
            with _BOOTSTRAP_LOCK:
                cached = _BOOTSTRAP_CACHE.get(kind)
                if cached and cached[0] > time.monotonic():
                    self._local_bootstrap[kind] = cached[1]
                    return cached[1]
        data, error, _ = _request_json(
            IANA_RDAP_BOOTSTRAPS[kind],
            headers={"Accept": "application/rdap+json, application/json", "User-Agent": "Toroka-Domain-Intel/2.0"},
            transport=self.transport,
            timeout=self.timeout,
        )
        if error or not isinstance(data, dict) or not isinstance(data.get("services"), list):
            raise RuntimeError(error or "invalid_iana_bootstrap")
        self._local_bootstrap[kind] = data
        if self.transport is None:
            with _BOOTSTRAP_LOCK:
                _BOOTSTRAP_CACHE[kind] = (time.monotonic() + 3600, data)
        return data

    @staticmethod
    def _https_base(urls: Any) -> str | None:
        if not isinstance(urls, list):
            return None
        for raw in urls:
            try:
                parsed = urlsplit(str(raw))
                if (parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
                        and parsed.port in (None, 443) and not parsed.query and not parsed.fragment):
                    return str(raw).rstrip("/") + "/"
            except Exception:
                continue
        return None

    def domain_base(self, domain: str) -> str:
        host = normalize_domain(domain)
        if not host:
            raise ValueError("invalid_domain")
        data = self._bootstrap("dns")
        matches: list[tuple[int, str]] = []
        for service in data["services"]:
            if not isinstance(service, list) or len(service) != 2:
                continue
            suffixes, urls = service
            if not isinstance(suffixes, list):
                continue
            for suffix in suffixes:
                suffix = str(suffix).strip().lower().lstrip(".")
                if suffix and (host == suffix or host.endswith("." + suffix)):
                    base = self._https_base(urls)
                    if base:
                        matches.append((len(suffix.split(".")), base))
        if not matches:
            raise RuntimeError("no_authoritative_rdap_service")
        return max(matches, key=lambda x: x[0])[1]

    def ip_base(self, value: str) -> str:
        ip = ipaddress.ip_address(value)
        kind = "ipv4" if ip.version == 4 else "ipv6"
        data = self._bootstrap(kind)
        matches: list[tuple[int, str]] = []
        for service in data["services"]:
            if not isinstance(service, list) or len(service) != 2 or not isinstance(service[0], list):
                continue
            for prefix in service[0]:
                try:
                    net = ipaddress.ip_network(str(prefix), strict=False)
                except ValueError:
                    continue
                if ip in net:
                    base = self._https_base(service[1])
                    if base:
                        matches.append((net.prefixlen, base))
        if not matches:
            raise RuntimeError("no_authoritative_rdap_service")
        return max(matches, key=lambda x: x[0])[1]

    def asn_base(self, asn: int) -> str:
        if not 1 <= int(asn) <= 4_294_967_295:
            raise ValueError("invalid_asn")
        data = self._bootstrap("asn")
        matches: list[tuple[int, str]] = []
        for service in data["services"]:
            if not isinstance(service, list) or len(service) != 2 or not isinstance(service[0], list):
                continue
            for raw_range in service[0]:
                try:
                    parts = str(raw_range).split("-", 1)
                    low = int(parts[0]); high = int(parts[1]) if len(parts) > 1 else low
                except ValueError:
                    continue
                if low <= int(asn) <= high:
                    base = self._https_base(service[1])
                    if base:
                        matches.append((-(high - low), base))
        if not matches:
            raise RuntimeError("no_authoritative_rdap_service")
        return max(matches, key=lambda x: x[0])[1]

    def _get(self, url: str) -> dict[str, Any]:
        data, error, _ = _request_json(
            url,
            headers={"Accept": "application/rdap+json, application/json", "User-Agent": "Toroka-Domain-Intel/2.0"},
            transport=self.transport,
            timeout=self.timeout,
        )
        if error or not isinstance(data, dict):
            raise RuntimeError(error or "invalid_rdap_response")
        return data

    def domain(self, domain: str) -> dict[str, Any]:
        base = self.domain_base(domain)
        data = self._get(base + "domain/" + quote(normalize_domain(domain) or "", safe=""))
        events: dict[str, str] = {}
        for item in data.get("events", []) if isinstance(data.get("events"), list) else []:
            if not isinstance(item, dict):
                continue
            action = str(item.get("eventAction") or "").casefold()
            date = str(item.get("eventDate") or "")
            if action and date and action not in events:
                events[action] = date[:40]
        nameservers = []
        for ns in data.get("nameservers", []) if isinstance(data.get("nameservers"), list) else []:
            if isinstance(ns, dict):
                name = _safe_dns_target(ns.get("ldhName") or ns.get("unicodeName") or "")
                if name and name not in nameservers:
                    nameservers.append(name)
        registrar = None
        for entity in data.get("entities", []) if isinstance(data.get("entities"), list) else []:
            if not isinstance(entity, dict) or "registrar" not in (entity.get("roles") or []):
                continue
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                for field in vcard[1]:
                    if isinstance(field, list) and len(field) >= 4 and str(field[0]).casefold() in {"org", "fn"}:
                        registrar = str(field[3])[:160]
                        break
            if registrar:
                break
        return {
            "domain": normalize_domain(domain),
            "handle": str(data.get("handle") or "")[:120] or None,
            "ldh_name": str(data.get("ldhName") or data.get("unicodeName") or domain)[:253],
            "events": events,
            "nameservers": nameservers[:12],
            "statuses": [str(x)[:80] for x in data.get("status", [])[:20] if isinstance(x, str)] if isinstance(data.get("status"), list) else [],
            "registrar": registrar,
            "rdap_url": base + "domain/" + quote(normalize_domain(domain) or "", safe=""),
            "source": "Authoritative RDAP via IANA bootstrap",
        }

    def ip(self, value: str) -> dict[str, Any]:
        ip = ipaddress.ip_address(value)
        if not ip.is_global:
            raise ValueError("non_public_ip")
        base = self.ip_base(str(ip))
        data = self._get(base + "ip/" + quote(str(ip), safe=""))
        return {
            "ip": str(ip),
            "name": str(data.get("name") or "")[:180] or None,
            "handle": str(data.get("handle") or "")[:120] or None,
            "country": str(data.get("country") or "")[:2] or None,
            "start_address": str(data.get("startAddress") or "")[:64] or None,
            "end_address": str(data.get("endAddress") or "")[:64] or None,
            "network_type": str(data.get("type") or "")[:80] or None,
            "rdap_url": base + "ip/" + quote(str(ip), safe=""),
            "source": "Regional Internet Registry RDAP via IANA bootstrap",
        }

    def asn(self, asn: int) -> dict[str, Any]:
        base = self.asn_base(asn)
        data = self._get(base + "autnum/" + str(int(asn)))
        return {
            "asn": int(asn),
            "name": str(data.get("name") or "")[:180] or None,
            "handle": str(data.get("handle") or "")[:120] or None,
            "start_asn": data.get("startAutnum"),
            "end_asn": data.get("endAutnum"),
            "country": str(data.get("country") or "")[:2] or None,
            "rdap_url": base + "autnum/" + str(int(asn)),
            "source": "Regional Internet Registry RDAP via IANA bootstrap",
        }


def _reverse_ip_for_cymru(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if ip.version == 4:
        return ".".join(reversed(str(ip).split("."))) + ".origin.asn.cymru.com"
    nibbles = ip.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def lookup_origin_asn(
    value: str,
    *,
    transport: httpx.BaseTransport | None = None,
    timeout: float = 3.0,
) -> dict[str, Any]:
    """Look up BGP origin ASN/prefix; country is registry context, not geolocation."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return {"status": "not_checked", "provider": "Team Cymru IP-to-ASN", "failure_reason": "invalid_ip"}
    if not ip.is_global:
        return {"status": "not_checked", "provider": "Team Cymru IP-to-ASN", "failure_reason": "non_public_ip"}
    qname = _reverse_ip_for_cymru(ip)
    data, error = _doh_txt_or_record(qname, "TXT", transport=transport, timeout=timeout)
    if error:
        return {"status": "failed", "provider": "Team Cymru IP-to-ASN", "failure_reason": error,
                "detail": "The public BGP origin lookup could not be completed."}
    answers = data.get("Answer") if isinstance(data, dict) and isinstance(data.get("Answer"), list) else []
    if not answers:
        return {"status": "checked_no_match", "provider": "Team Cymru IP-to-ASN", "detail": "No origin ASN was returned for this public IP."}
    raw = str(answers[0].get("data") or "").strip().strip('"')
    parts = [p.strip() for p in raw.split("|")]
    if len(parts) < 4 or not parts[0].isdigit():
        return {"status": "failed", "provider": "Team Cymru IP-to-ASN", "failure_reason": "invalid_asn_response"}
    asn = int(parts[0])
    if not 1 <= asn <= 4_294_967_295:
        return {"status": "checked_no_match", "provider": "Team Cymru IP-to-ASN", "detail": "No routable public ASN was returned."}
    prefix = parts[1]
    try:
        network = ipaddress.ip_network(prefix, strict=False)
        if ip not in network:
            raise ValueError("ASN prefix does not contain the queried IP")
    except ValueError:
        return {"status": "failed", "provider": "Team Cymru IP-to-ASN", "failure_reason": "invalid_prefix"}
    return {
        "status": "checked", "provider": "Team Cymru IP-to-ASN", "ip": str(ip),
        "asn": asn, "prefix": str(network), "registry_country": parts[2][:2].upper(),
        "registry": parts[3][:24], "allocated": parts[4][:20] if len(parts) > 4 else None,
        "source_url": TEAM_CYMRU_INFO_URL,
        "detail": "BGP origin ASN and prefix observed. The registry country is not a physical server-location claim.",
    }


def search_certificate_transparency(
    domain: str,
    api_key: str,
    *,
    include_subdomains: bool = True,
    transport: httpx.BaseTransport | None = None,
    timeout: float = 5.0,
    max_results: int = MAX_CT_RESULTS,
) -> dict[str, Any]:
    """Search SSLMate Cert Spotter. Production lookups require an authenticated API key."""
    host = normalize_domain(domain)
    if not host:
        return {"status": "not_checked", "provider": "SSLMate Cert Spotter CT", "domain": None,
                "issuances": [], "failure_reason": "invalid_domain"}
    if not api_key:
        return {"status": "not_configured", "provider": "SSLMate Cert Spotter CT", "domain": host,
                "issuances": [], "detail": "CERTSPOTTER_API_KEY is not configured. CT lookup was not performed."}
    params = [
        ("domain", host),
        ("include_subdomains", "true" if include_subdomains else "false"),
        ("expand", "dns_names"),
        ("expand", "issuer"),
    ]
    data, error, status_code = _request_json(
        CERTSPOTTER_URL,
        params=params,
        headers={"Accept": "application/json", "Authorization": f"Bearer {api_key}", "User-Agent": "Toroka-Domain-Intel/2.0"},
        transport=transport,
        timeout=timeout,
    )
    if error:
        status = "rate_limited" if status_code == 429 else "failed"
        return {"status": status, "provider": "SSLMate Cert Spotter CT", "domain": host,
                "issuances": [], "failure_reason": error,
                "detail": "Certificate Transparency lookup failed; no conclusion was drawn from the missing result."}
    raw_items = data if isinstance(data, list) else []
    issuances = []
    seen_ids: set[str] = set()
    for item in raw_items[: max(1, min(int(max_results), MAX_CT_RESULTS))]:
        if not isinstance(item, dict):
            continue
        iid = str(item.get("id") or "")[:100]
        if not iid or iid in seen_ids:
            continue
        seen_ids.add(iid)
        names: list[str] = []
        for raw_name in item.get("dns_names", []) if isinstance(item.get("dns_names"), list) else []:
            name = str(raw_name or "").strip().lower()
            if name.startswith("*."):
                name = name[2:]
            clean = normalize_domain(name)
            if clean and (clean == host or clean.endswith("." + host)) and clean not in names:
                names.append(clean)
        if not names:
            continue
        issuer = item.get("issuer") if isinstance(item.get("issuer"), dict) else {}
        issuances.append({
            "id": iid,
            "dns_names": names[:20],
            "issuer": str(issuer.get("friendly_name") or "")[:160] or None,
            "not_before": str(item.get("not_before") or "")[:40] or None,
            "not_after": str(item.get("not_after") or "")[:40] or None,
            "revoked": item.get("revoked") if isinstance(item.get("revoked"), bool) else None,
            "cert_sha256": str(item.get("cert_sha256") or "")[:64] or None,
        })
    return {
        "status": "checked" if issuances else "checked_no_match",
        "provider": "SSLMate Cert Spotter CT", "domain": host,
        "include_subdomains": bool(include_subdomains),
        "issuances": issuances,
        "source_url": f"https://api.certspotter.com/v1/issuances?{urlencode({'domain': host, 'include_subdomains': str(bool(include_subdomains)).lower()})}",
        "detail": (f"Found {len(issuances)} certificate issuance record(s) whose logged DNS names match {host}."
                   if issuances else f"No matching Certificate Transparency issuance was returned for {host}."),
        "limitations": [
            "A CT record shows that a certificate name was logged; it does not prove the hostname is active, controlled by the seller, or malicious.",
            "The result is bounded by the provider plan, query limits and returned page; it is not an exhaustive certificate history.",
            "Wildcard names are shown as their base domain and are not treated as proof of every subdomain being active.",
        ],
    }


def _evidence_id(provider: str, domain: str, detail: str) -> str:
    return hashlib.sha256(f"toroka-build2|{provider}|{domain}|{detail}".encode("utf-8", "ignore")).hexdigest()[:24]


def _evidence_record(
    *, provider: str, source_type: str, domain: str, title: str, snippet: str,
    source_url: str | None, infrastructure_links: list[dict[str, str]] | None = None,
    claim_status: str = "automated_infrastructure_observation",
) -> dict[str, Any]:
    return {
        "evidence_id": _evidence_id(provider, domain, title + "|" + snippet),
        "provider": provider,
        "source_type": source_type,
        "evidence_type": "automated_infrastructure_observation",
        "claim_status": claim_status,
        "identity_match": "exact_domain_infrastructure_observation",
        "target_identifier": domain,
        "subject_domain": domain,
        "title": title[:180],
        "snippet": snippet[:1200],
        "url": source_url,
        "collected_at": now_iso(),
        "verified": False,
        "polarity": "context",
        "infrastructure_links": (infrastructure_links or [])[:30],
        "limitations": [
            "This is passive public infrastructure data, not proof of business identity, common ownership or fraud.",
        ],
    }


def investigate_domain_infrastructure(
    domain: str,
    *,
    ct_api_key: str = "",
    include_subdomains: bool = True,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Collect a bounded infrastructure bundle and turn it into sourced observations."""
    host = normalize_domain(domain)
    if not host:
        return {
            "domain": None, "status": "not_checked", "providers": [], "evidence": [],
            "detail": "No valid public domain was available for infrastructure intelligence.",
        }

    rdap_client = IanaRdapClient(transport=transport)
    results: dict[str, Any] = {}
    jobs = {
        "dns": lambda: query_dns_records(host, transport=transport),
        "rdap": lambda: rdap_client.domain(host),
        "ct": lambda: search_certificate_transparency(host, ct_api_key, include_subdomains=include_subdomains, transport=transport),
    }
    errors: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(fn): key for key, fn in jobs.items()}
        for future in as_completed(futures):
            key = futures[future]
            try:
                results[key] = future.result()
            except Exception as exc:
                errors[key] = type(exc).__name__

    dns = results.get("dns") or {"status": "failed", "provider": "Google Public DNS (DoH)", "records": [], "addresses": []}
    rdap = results.get("rdap") or None
    ct = results.get("ct") or {"status": "failed", "provider": "SSLMate Cert Spotter CT", "issuances": [], "failure_reason": errors.get("ct", "provider_error")}
    providers: list[dict[str, Any]] = [{
        "provider": dns.get("provider", "Google Public DNS (DoH)"), "operation": "dns_records",
        "status": dns.get("status", "failed"), "results_retrieved": len(dns.get("records") or []),
        "results_relevant": len(dns.get("records") or []), "failure_reason": dns.get("failure_reason"),
        "detail": (f"Queried A, AAAA, MX, NS, CAA and TXT records for {host}. "
                   f"Completed {dns.get('queries_completed', 0)} DNS queries."),
    }, {
        "provider": "Authoritative RDAP via IANA bootstrap", "operation": "domain_registration_and_nameservers",
        "status": "checked" if rdap else "failed", "results_retrieved": 1 if rdap else 0,
        "results_relevant": 1 if rdap else 0, "failure_reason": errors.get("rdap"),
        "detail": "Retrieved domain registration events, registrar (where published), statuses and nameservers." if rdap else "Authoritative RDAP registration lookup could not be completed.",
    }, {
        "provider": ct.get("provider", "SSLMate Cert Spotter CT"), "operation": "certificate_transparency_search",
        "status": ct.get("status", "failed"), "results_retrieved": len(ct.get("issuances") or []),
        "results_relevant": len(ct.get("issuances") or []), "failure_reason": ct.get("failure_reason"),
        "detail": ct.get("detail") or "Certificate Transparency lookup was not completed.",
    }]

    evidence: list[dict[str, Any]] = []
    links_dns: list[dict[str, str]] = []
    for record in dns.get("records", [])[:MAX_DNS_ANSWERS]:
        rtype = str(record.get("type") or "")
        value = str(record.get("value") or "")
        if rtype in {"A", "AAAA"} and record.get("address_scope") == "public":
            links_dns.append({"kind": "ip_address", "value": value, "relation": "resolves_to_ip", "basis": "public_dns_answer"})
        elif rtype == "NS":
            links_dns.append({"kind": "nameserver", "value": value, "relation": "uses_nameserver", "basis": "public_dns_answer"})
        elif rtype == "MX":
            links_dns.append({"kind": "mail_exchange", "value": value, "relation": "uses_mail_exchange", "basis": "public_dns_answer"})
    if dns.get("status") in {"checked", "checked_no_records"}:
        records_summary = "; ".join(f"{r.get('type')} {r.get('value')}" for r in dns.get("records", [])[:12]) or "No records returned for queried types"
        dnssec = "DNSSEC validation observed by resolver" if dns.get("dnssec_validated") else "DNSSEC validation not confirmed by resolver"
        evidence.append(_evidence_record(
            provider="Google Public DNS (DoH)", source_type="domain_dns_observation", domain=host,
            title=f"DNS observations for {host}", snippet=f"{records_summary}. {dnssec}.",
            source_url=dns.get("source_url"), infrastructure_links=links_dns,
        ))

    if rdap:
        ev = rdap.get("events") or {}
        registration = ev.get("registration")
        age_days = None
        if registration:
            try:
                dt = datetime.fromisoformat(registration.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                delta = datetime.now(timezone.utc) - dt
                age_days = delta.days if delta.total_seconds() >= 0 else None
            except (TypeError, ValueError):
                age_days = None
        summary_parts = []
        if registration:
            summary_parts.append(f"Registration event: {registration}")
        if age_days is not None:
            summary_parts.append(f"approximately {age_days} days old")
        if rdap.get("registrar"):
            summary_parts.append(f"Registrar: {rdap['registrar']}")
        if rdap.get("nameservers"):
            summary_parts.append("Nameservers: " + ", ".join(rdap["nameservers"][:8]))
        if rdap.get("statuses"):
            summary_parts.append("RDAP status: " + ", ".join(rdap["statuses"][:6]))
        summary = "; ".join(summary_parts) or "Authoritative RDAP returned a domain object but no registration event or registrar name."
        ns_links = [{"kind": "nameserver", "value": value, "relation": "uses_nameserver", "basis": "authoritative_rdap_nameserver_list"} for value in rdap.get("nameservers", [])[:12]]
        evidence.append(_evidence_record(
            provider="Authoritative RDAP via IANA bootstrap", source_type="domain_registration_observation", domain=host,
            title=f"Authoritative registration data for {host}", snippet=summary,
            source_url=rdap.get("rdap_url"), infrastructure_links=ns_links,
        ))

    addresses = [x for x in (dns.get("addresses") or []) if _is_global_ip(x)][:2]

    def inspect_public_ip(address: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        asn_result = lookup_origin_asn(address, transport=transport)
        ip_record: dict[str, Any] = {"ip": address, "asn_lookup": asn_result}
        generated_evidence: list[dict[str, Any]] = []
        if asn_result.get("status") == "checked":
            ip_record["infrastructure_links"] = [
                {"kind": "autonomous_system", "value": f"AS{asn_result['asn']}", "relation": "announced_by_asn", "basis": "team_cymru_bgp_origin"},
                {"kind": "network_prefix", "value": asn_result["prefix"], "relation": "announced_prefix", "basis": "team_cymru_bgp_origin"},
            ]
            try:
                ip_record["asn_rdap"] = rdap_client.asn(int(asn_result["asn"]))
            except Exception as exc:
                ip_record["asn_rdap"] = {"status": "failed", "failure_reason": type(exc).__name__}
        try:
            ip_record["rdap"] = rdap_client.ip(address)
        except Exception as exc:
            ip_record["rdap"] = {"status": "failed", "failure_reason": type(exc).__name__}

        if asn_result.get("status") == "checked":
            asn_name = (ip_record.get("asn_rdap") or {}).get("name")
            detail = f"{address} is announced in BGP prefix {asn_result['prefix']} by AS{asn_result['asn']}" + (f" ({asn_name})" if asn_name else "") + f". Registry country: {asn_result.get('registry_country') or 'not supplied'}."
            generated_evidence.append(_evidence_record(
                provider="Team Cymru IP-to-ASN", source_type="ip_asn_observation", domain=host,
                title=f"BGP routing observation for {address}", snippet=detail,
                source_url=asn_result.get("source_url"), infrastructure_links=[
                    {"kind": "ip_address", "value": address, "relation": "domain_address_observed", "basis": "dns_answer"},
                    *ip_record.get("infrastructure_links", []),
                ],
            ))
            asn_rdap = ip_record.get("asn_rdap") or {}
            if asn_rdap.get("rdap_url"):
                generated_evidence.append(_evidence_record(
                    provider="Regional Internet Registry RDAP", source_type="asn_allocation_observation", domain=host,
                    title=f"Autonomous system allocation for AS{asn_result['asn']}",
                    snippet=(f"Network name: {asn_rdap.get('name') or 'not supplied'}. "
                             f"Allocation country code: {asn_rdap.get('country') or 'not supplied'}. "
                             "This is registry allocation context, not a physical server-location claim."),
                    source_url=asn_rdap.get("rdap_url"), infrastructure_links=[
                        {"kind": "autonomous_system", "value": f"AS{asn_result['asn']}", "relation": "network_allocation_for", "basis": "rir_rdap_autnum_object"},
                    ],
                ))
        ip_rdap = ip_record.get("rdap")
        if isinstance(ip_rdap, dict) and ip_rdap.get("rdap_url"):
            alloc_summary = " ".join(x for x in [
                f"Network name: {ip_rdap.get('name')}" if ip_rdap.get("name") else "",
                f"Registered country code: {ip_rdap.get('country')}" if ip_rdap.get("country") else "",
                f"Address range: {ip_rdap.get('start_address')}–{ip_rdap.get('end_address')}" if ip_rdap.get("start_address") and ip_rdap.get("end_address") else "",
            ]).strip()
            if alloc_summary:
                generated_evidence.append(_evidence_record(
                    provider="Regional Internet Registry RDAP", source_type="ip_allocation_observation", domain=host,
                    title=f"IP allocation data for {address}", snippet=alloc_summary,
                    source_url=ip_rdap.get("rdap_url"), infrastructure_links=[
                        {"kind": "ip_address", "value": address, "relation": "network_allocation_for", "basis": "rir_rdap_network_object"},
                    ],
                ))
        return ip_record, generated_evidence

    ip_observations: list[dict[str, Any]] = []
    if addresses:
        with ThreadPoolExecutor(max_workers=min(2, len(addresses))) as pool:
            futures = {pool.submit(inspect_public_ip, address): address for address in addresses}
            for future in as_completed(futures):
                try:
                    observation, generated = future.result()
                    ip_observations.append(observation)
                    evidence.extend(generated)
                except Exception:
                    # Provider failure is reported below as not completed, not as a clean result.
                    ip_observations.append({"ip": futures[future], "asn_lookup": {"status": "failed", "failure_reason": "provider_error"},
                                            "rdap": {"status": "failed", "failure_reason": "provider_error"}})

    for observation in ip_observations:
        asn_result = observation.get("asn_lookup") or {}
        providers.append({
            "provider": asn_result.get("provider", "Team Cymru IP-to-ASN"),
            "operation": "bgp_origin_asn_lookup", "query_ip": observation.get("ip"),
            "status": asn_result.get("status", "failed"),
            "results_retrieved": 1 if asn_result.get("status") == "checked" else 0,
            "results_relevant": 1 if asn_result.get("status") == "checked" else 0,
            "failure_reason": asn_result.get("failure_reason"),
            "detail": asn_result.get("detail") or "BGP origin lookup status for this public IP.",
        })
        for field, operation in (("rdap", "ip_allocation_lookup"), ("asn_rdap", "asn_allocation_lookup")):
            record = observation.get(field) or {}
            if not record:
                continue
            providers.append({
                "provider": record.get("source", "Regional Internet Registry RDAP"),
                "operation": operation,
                "query_ip": observation.get("ip"),
                "status": "checked" if record.get("rdap_url") else record.get("status", "failed"),
                "results_retrieved": 1 if record.get("rdap_url") else 0,
                "results_relevant": 1 if record.get("rdap_url") else 0,
                "failure_reason": record.get("failure_reason"),
                "detail": "Public network allocation metadata; country codes are registry context, not physical location.",
            })

    ct_links: list[dict[str, str]] = []
    ct_names: list[str] = []
    for issue in ct.get("issuances", [])[:MAX_CT_RESULTS]:
        for cert_name in issue.get("dns_names", [])[:20]:
            if cert_name not in ct_names:
                ct_names.append(cert_name)
    for cert_name in ct_names[:25]:
        if cert_name != host:
            ct_links.append({"kind": "subdomain", "value": cert_name, "relation": "certificate_covers_hostname", "basis": "certificate_transparency_dns_name"})
    if ct.get("status") in {"checked", "checked_no_match"} and ct.get("issuances"):
        details = []
        for issue in ct.get("issuances", [])[:8]:
            names = ", ".join(issue.get("dns_names", [])[:6])
            details.append(f"{names} (valid {issue.get('not_before') or 'unknown'} to {issue.get('not_after') or 'unknown'}; revoked={issue.get('revoked')})")
        evidence.append(_evidence_record(
            provider="SSLMate Cert Spotter CT", source_type="certificate_transparency_observation", domain=host,
            title=f"Certificate Transparency names for {host}",
            snippet="Logged certificate names: " + "; ".join(details),
            source_url=ct.get("source_url"), infrastructure_links=ct_links,
        ))

    checked_count = sum(1 for p in providers if p.get("status") in {"checked", "checked_no_match", "checked_no_records"})
    status = "checked" if checked_count else ("not_configured" if all(p.get("status") == "not_configured" for p in providers) else "failed")
    return {
        "domain": host,
        "status": status,
        "providers": providers,
        "evidence": evidence[:20],
        "dns": dns,
        "rdap": rdap,
        "certificate_transparency": ct,
        "ip_observations": ip_observations,
        "checked_at": now_iso(),
        "interpretation_note": "Infrastructure links describe DNS, routing, registration and certificate observations. Shared infrastructure or certificate coverage does not prove common ownership or fraud.",
    }


def _is_global_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False
