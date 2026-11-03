"""Redirect checking without opening the page (OWASP SSRF guidance, blueprint 4.8).

- every hop is validated (scheme, port, credentials, literal IPs) and its DNS answers must ALL be public;
- the connection is pinned to the validated IP (Host header + SNI keep the original name), which defeats DNS rebinding;
- only response headers are read: the body is never downloaded, executed or rendered;
- hop count, timeout and total time are capped.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx
from ssi_rules.normalize import is_fetch_safe
from ssi_rules.vocabulary import CoverageStatus

Resolver = "Callable[[str], list[str]]"
UA = "SmartScamIdentifier-linkcheck/0.1 (+headers only)"


def default_resolver(host: str) -> list[str]:
    return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})


@dataclass
class RedirectResult:
    status: CoverageStatus
    final_url: str | None = None
    hops: int = 0
    chain: list[str] = field(default_factory=list)
    reason: str = ""


def _public_ip(addresses: list[str]) -> str | None:
    ips = []
    for a in addresses:
        ip = ipaddress.ip_address(a.split("%")[0])
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        if not ip.is_global:
            return None          # one private answer poisons the host: refuse
        ips.append(ip)
    return str(ips[0]) if ips else None


def _pin(current: str, resolver):
    """Validate one hop and pin it to a public IP. Returns (pinned_url, host, sni_ext, None) or (None, None, None, reason)."""
    ok, why = is_fetch_safe(current)
    if not ok:
        return None, None, None, f"blocked: {why}"
    parts = urlsplit(current)
    host = parts.hostname
    try:
        ip = str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        try:
            ip = _public_ip(resolver(host))
        except Exception:
            return None, None, None, "name did not resolve"
        if not ip:
            return None, None, None, "blocked: non-public address"
    netloc_ip = f"[{ip}]" if ":" in ip else ip
    pinned = parts._replace(netloc=netloc_ip + (f":{parts.port}" if parts.port else "")).geturl()
    return pinned, host, ({"sni_hostname": host} if parts.scheme == "https" else {}), None


def follow_redirects(url: str, *, transport: httpx.BaseTransport | None = None, resolver=default_resolver,
                     max_hops: int = 5, timeout: float = 4.0, total_budget: float = 12.0) -> RedirectResult:
    if "://" not in url:
        url = "http://" + url
    chain, started = [url], time.monotonic()
    current = url
    for hop in range(max_hops + 1):
        if time.monotonic() - started > total_budget:
            return RedirectResult(CoverageStatus.COULD_NOT_CHECK, None, hop, chain, "time budget exceeded")
        pinned, host, ext, bad = _pin(current, resolver)
        if bad:
            return RedirectResult(CoverageStatus.COULD_NOT_CHECK, None, hop, chain, bad)
        try:
            with httpx.Client(transport=transport, timeout=timeout, follow_redirects=False, verify=True) as c:
                with c.stream("GET", pinned, headers={"Host": host, "User-Agent": UA, "Accept": "*/*", "Range": "bytes=0-0"}, extensions=ext) as r:
                    code, loc = r.status_code, r.headers.get("location")
        except Exception:
            return RedirectResult(CoverageStatus.COULD_NOT_CHECK, None, hop, chain, "request failed")
        if code in (301, 302, 303, 307, 308) and loc:
            nxt = urljoin(current, loc)
            chain.append(nxt)
            current = nxt
            continue
        return RedirectResult(CoverageStatus.CHECKED, current, hop, chain, f"final status {code}")
    return RedirectResult(CoverageStatus.COULD_NOT_CHECK, None, max_hops, chain, "too many redirects")


@dataclass
class PageText:
    status: CoverageStatus
    final_url: str | None = None
    text: str = ""
    reason: str = ""


class _Visible(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts, self._skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript", "template"):
            self._skip += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript", "template") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip and data.strip():
            self.parts.append(data.strip())


def fetch_text(url: str, *, transport: httpx.BaseTransport | None = None, resolver=default_resolver, max_bytes: int = 1_000_000,
               max_hops: int = 3, timeout: float = 8.0) -> PageText:
    """Fetch an official page for change detection. Same SSRF protections; body capped, parsed as text only, never executed."""
    current = url
    for hop in range(max_hops + 1):
        pinned, host, ext, bad = _pin(current, resolver)
        if bad:
            return PageText(CoverageStatus.COULD_NOT_CHECK, None, "", bad)
        try:
            with httpx.Client(transport=transport, timeout=timeout, follow_redirects=False) as c:
                with c.stream("GET", pinned, headers={"Host": host, "User-Agent": UA, "Accept": "text/html,text/plain"}, extensions=ext) as r:
                    if r.status_code in (301, 302, 303, 307, 308) and r.headers.get("location"):
                        current = urljoin(current, r.headers["location"])
                        continue
                    if r.status_code >= 400:
                        return PageText(CoverageStatus.COULD_NOT_CHECK, current, "", f"status {r.status_code}")
                    body = b""
                    for chunk in r.iter_bytes():
                        body += chunk
                        if len(body) > max_bytes:
                            body = body[:max_bytes]
                            break
        except Exception:
            return PageText(CoverageStatus.COULD_NOT_CHECK, None, "", "request failed")
        v = _Visible()
        v.feed(body.decode("utf-8", "replace"))
        return PageText(CoverageStatus.CHECKED, current, re.sub(r"\s+", " ", " ".join(v.parts)).strip())
    return PageText(CoverageStatus.COULD_NOT_CHECK, None, "", "too many redirects")
