"""SSRF-hardened safe URL fetcher and webpage content extractor (OWASP SSRF guidance).

Guarantees:
- Scheme restricted to http and https only;
- Host validation and DNS pre-resolution against private/loopback/link-local/cloud metadata IPs;
- IP pinning on every hop to prevent DNS rebinding;
- Manual hop-by-hop redirect verification (max 5 hops);
- Strict response body cap (512 KB) and connection timeouts (4.0s);
- Content-type inspection: immediately aborts on executable/binary downloads;
- Safe HTML parsing: visible text and metadata only, never executes JavaScript;
- Extracts contact details, forms, payment lures, and credential harvesting signals.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable, Any
from urllib.parse import urljoin, urlsplit, quote

import httpx
from ssi_rules.normalize import is_fetch_safe, extract_phones, extract_payment_ids
from ssi_rules.vocabulary import CoverageStatus

Resolver = Callable[[str], list[str]]
UA = "Toroka-LinkScanner/1.0 (+https://toroka.co.ke; SSRF-protected)"

# Cloud metadata and private address blocklist
_BLOCKED_METADATA_IPS = {
    "169.254.169.254",  # AWS/GCP/Azure/OpenStack metadata
    "fd00:ec2::254",     # AWS IPv6 metadata
    "100.100.100.200",  # Alibaba Cloud metadata
}

_BINARY_CONTENT_TYPES = {
    "application/octet-stream",
    "application/x-msdownload",
    "application/exe",
    "application/x-exe",
    "application/dos-exe",
    "vms/exe",
    "application/x-winexe",
    "application/msdos-windows",
    "application/x-msdos-program",
    "application/pdf",
    "application/zip",
    "application/x-tar",
    "application/x-gzip",
    "application/x-bzip2",
    "application/x-7z-compressed",
    "application/vnd.android.package-archive",  # APK
    "application/x-apple-diskimage",           # DMG
    "application/x-iso9660-image",
}


def default_resolver(host: str) -> list[str]:
    """Resolve all IPv4 and IPv6 addresses for a hostname."""
    try:
        results = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return sorted({ai[4][0] for ai in results})
    except Exception:
        return []


def is_ip_allowed(ip_str: str) -> tuple[bool, str]:
    """Strictly verify if an IP is globally routable and not private/cloud-metadata."""
    try:
        clean_ip = ip_str.split("%")[0].strip("[]")
        ip = ipaddress.ip_address(clean_ip)
    except ValueError:
        return False, "invalid IP address representation"

    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped

    str_ip = str(ip)
    if str_ip in _BLOCKED_METADATA_IPS:
        return False, "blocked: cloud instance metadata IP (169.254.169.254)"

    if ip.is_loopback:
        return False, "blocked: loopback address (127.0.0.0/8 or ::1)"

    if ip.is_private:
        return False, "blocked: RFC1918 private network address"

    if ip.is_link_local:
        return False, "blocked: link-local address"

    if ip.is_reserved:
        return False, "blocked: IETF reserved address"

    if ip.is_multicast:
        return False, "blocked: multicast address"

    if ip.is_unspecified:
        return False, "blocked: unspecified address (0.0.0.0 or ::)"

    if not ip.is_global:
        return False, "blocked: non-globally routable address"

    return True, "ok"


def _public_ip(addresses: list[str]) -> tuple[str | None, str]:
    """Ensure ALL resolved DNS answers are globally routable. One private answer poisons the host."""
    if not addresses:
        return None, "DNS resolution returned no addresses"

    first_public = None
    for a in addresses:
        ok, reason = is_ip_allowed(a)
        if not ok:
            return None, reason
        if first_public is None:
            first_public = a.split("%")[0].strip("[]")

    return first_public, "ok"


def resolve_and_pin(url: str, resolver: Resolver = default_resolver) -> tuple[str | None, str | None, dict[str, Any], str | None]:
    """Validate one hop and pin it to a public IP.

    Returns (pinned_url, original_host, sni_ext, None) on success,
    or (None, None, {}, error_reason) on failure.
    """
    ok, why = is_fetch_safe(url)
    if not ok:
        return None, None, {}, f"URL validation failed: {why}"

    parts = urlsplit(url)
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        return None, None, {}, "URL missing hostname"

    # Direct literal IP check
    try:
        ip = str(ipaddress.ip_address(host.strip("[]")))
        is_literal = True
    except ValueError:
        is_literal = False

    if is_literal:
        allowed, reason = is_ip_allowed(ip)
        if not allowed:
            return None, None, {}, reason
        target_ip = ip
    else:
        try:
            answers = resolver(host)
        except Exception as e:
            return None, None, {}, f"DNS resolution failed: {e}"

        target_ip, reason = _public_ip(answers)
        if not target_ip:
            return None, None, {}, reason

    # Pin the connection target to the validated IP
    netloc_ip = f"[{target_ip}]" if ":" in target_ip else target_ip
    port_suffix = f":{parts.port}" if parts.port else ""
    pinned_url = parts._replace(netloc=f"{netloc_ip}{port_suffix}").geturl()

    sni_ext = {"sni_hostname": host} if parts.scheme == "https" else {}
    return pinned_url, host, sni_ext, None


class _HtmlContentExtractor(HTMLParser):
    """Safe streaming HTML parser that extracts text, meta tags, forms, and contact clues."""

    def __init__(self):
        super().__init__()
        self.title_parts: list[str] = []
        self.in_title = False
        self.meta_tags: dict[str, str] = {}
        self.visible_text_parts: list[str] = []
        self._skip_depth = 0
        self.has_password_field = False
        self.has_login_form = False
        self.form_actions: list[str] = []
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        tag_lower = tag.lower()
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag_lower in ("script", "style", "noscript", "template", "svg", "canvas"):
            self._skip_depth += 1
            return

        if tag_lower == "title":
            self.in_title = True
            return

        if tag_lower == "meta":
            name = (attr_dict.get("name") or attr_dict.get("property") or "").lower()
            content = attr_dict.get("content", "").strip()
            if name and content:
                self.meta_tags[name] = content

        if tag_lower == "form":
            action = attr_dict.get("action", "").strip()
            if action:
                self.form_actions.append(action)

        if tag_lower == "input":
            inp_type = attr_dict.get("type", "").lower()
            inp_name = attr_dict.get("name", "").lower()
            if inp_type == "password" or "password" in inp_name or "passcode" in inp_name or "pin" in inp_name:
                self.has_password_field = True
                self.has_login_form = True

        if tag_lower == "a":
            href = attr_dict.get("href", "").strip()
            if href:
                self.links.append(href)

    def handle_endtag(self, tag: str):
        tag_lower = tag.lower()
        if tag_lower in ("script", "style", "noscript", "template", "svg", "canvas") and self._skip_depth > 0:
            self._skip_depth -= 1
        elif tag_lower == "title":
            self.in_title = False

    def handle_data(self, data: str):
        cleaned = data.strip()
        if not cleaned:
            return

        if self.in_title:
            self.title_parts.append(cleaned)
        elif self._skip_depth == 0:
            self.visible_text_parts.append(cleaned)


@dataclass
class SafePageContent:
    status: CoverageStatus
    final_url: str | None = None
    status_code: int | None = None
    hops: int = 0
    redirect_chain: list[str] = field(default_factory=list)
    title: str = ""
    meta_description: str = ""
    meta_tags: dict[str, str] = field(default_factory=dict)
    visible_text: str = ""
    phones: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    whatsapp_links: list[str] = field(default_factory=list)
    payment_identifiers: list[str] = field(default_factory=list)
    has_login_form: bool = False
    has_password_field: bool = False
    form_actions: list[str] = field(default_factory=list)
    security_warnings: list[str] = field(default_factory=list)
    reason: str = ""
    fetch_time_ms: float = 0.0


_EMAIL_RX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")
_WHATSAPP_LINK_RX = re.compile(r"(?:https?://)?(?:wa\.me|api\.whatsapp\.com/send|chat\.whatsapp\.com)/[A-Za-z0-9_.-]+")
_URGENCY_KEYWORDS = [
    "account suspended", "urgent action required", "verify your account", "confirm pin",
    "enter m-pesa pin", "reversal pending", "claim your prize", "won 50,000", "free money",
    "limited time offer", "security alert", "immediate verification"
]


def safe_fetch_page(
    url: str,
    *,
    transport: httpx.BaseTransport | None = None,
    resolver: Resolver = default_resolver,
    max_hops: int = 5,
    timeout: float = 4.0,
    max_bytes: int = 524288,  # 512 KB
    total_budget: float = 10.0,
) -> SafePageContent:
    """Safely fetch a webpage over HTTP/HTTPS with complete SSRF shielding.

    - Every hop undergoes strict IP safety verification.
    - IP pinning prevents DNS rebinding.
    - Bodies are capped to max_bytes and parsed without script execution.
    - Executable/binary files are blocked before downloading.
    """
    if "://" not in url:
        url = "https://" + url

    t0 = time.monotonic()
    current = url
    chain = [current]
    security_warnings = []

    for hop in range(max_hops + 1):
        if time.monotonic() - t0 > total_budget:
            return SafePageContent(
                status=CoverageStatus.COULD_NOT_CHECK,
                final_url=current,
                hops=hop,
                redirect_chain=chain,
                reason="Time budget exceeded during safe fetch",
                fetch_time_ms=(time.monotonic() - t0) * 1000,
            )

        pinned_url, host, sni_ext, bad_reason = resolve_and_pin(current, resolver)
        if bad_reason:
            return SafePageContent(
                status=CoverageStatus.COULD_NOT_CHECK,
                final_url=current,
                hops=hop,
                redirect_chain=chain,
                reason=bad_reason,
                fetch_time_ms=(time.monotonic() - t0) * 1000,
            )

        headers = {
            "Host": host,
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.5",
            "Accept-Language": "en-US,en;q=0.9,sw;q=0.8",
        }

        try:
            with httpx.Client(transport=transport, timeout=timeout, follow_redirects=False, verify=True) as client:
                with client.stream("GET", pinned_url, headers=headers, extensions=sni_ext) as resp:
                    status_code = resp.status_code
                    resp_headers = resp.headers

                    # Check for redirects
                    if status_code in (301, 302, 303, 307, 308) and "location" in resp_headers:
                        loc = resp_headers["location"]
                        nxt = urljoin(current, loc)
                        chain.append(nxt)
                        current = nxt
                        continue

                    # Validate Content-Type
                    content_type = resp_headers.get("content-type", "").lower().split(";")[0].strip()
                    if content_type in _BINARY_CONTENT_TYPES or any(ext in current.lower() for ext in (".exe", ".apk", ".bin", ".dmg", ".iso", ".bat")):
                        return SafePageContent(
                            status=CoverageStatus.CHECKED,
                            final_url=current,
                            status_code=status_code,
                            hops=hop,
                            redirect_chain=chain,
                            security_warnings=["Executable or binary file detected. Download blocked for security."],
                            reason="Binary download blocked",
                            fetch_time_ms=(time.monotonic() - t0) * 1000,
                        )

                    # Read streamed bytes up to max_bytes
                    raw_body = b""
                    for chunk in resp.iter_bytes():
                        raw_body += chunk
                        if len(raw_body) >= max_bytes:
                            raw_body = raw_body[:max_bytes]
                            break

        except httpx.ConnectTimeout:
            return SafePageContent(
                status=CoverageStatus.COULD_NOT_CHECK,
                final_url=current,
                hops=hop,
                redirect_chain=chain,
                reason="Connection timed out",
                fetch_time_ms=(time.monotonic() - t0) * 1000,
            )
        except httpx.HTTPError as exc:
            return SafePageContent(
                status=CoverageStatus.COULD_NOT_CHECK,
                final_url=current,
                hops=hop,
                redirect_chain=chain,
                reason=f"HTTP request error: {type(exc).__name__}",
                fetch_time_ms=(time.monotonic() - t0) * 1000,
            )
        except Exception as exc:
            return SafePageContent(
                status=CoverageStatus.COULD_NOT_CHECK,
                final_url=current,
                hops=hop,
                redirect_chain=chain,
                reason=f"Fetch failed safely: {type(exc).__name__}",
                fetch_time_ms=(time.monotonic() - t0) * 1000,
            )

        # Successful HTTP response reached
        elapsed = (time.monotonic() - t0) * 1000
        html_str = raw_body.decode("utf-8", "replace")

        # Parse HTML safely
        parser = _HtmlContentExtractor()
        try:
            parser.feed(html_str)
        except Exception:
            pass

        title = " ".join(parser.title_parts).strip()[:200]
        meta_desc = parser.meta_tags.get("description", "") or parser.meta_tags.get("og:description", "")
        meta_desc = meta_desc.strip()[:300]
        visible_text = " ".join(parser.visible_text_parts)[:2500]

        # Extract contacts and identifiers from text and links
        combined_text = f"{title} {meta_desc} {visible_text} " + " ".join(parser.links)
        
        extracted_phones = [p.normalized for p in extract_phones(combined_text)[:4]]
        extracted_emails = sorted(set(_EMAIL_RX.findall(combined_text)))[:4]
        
        whatsapp_links = []
        for lk in parser.links:
            if _WHATSAPP_LINK_RX.search(lk):
                whatsapp_links.append(lk)
        whatsapp_links = list(dict.fromkeys(whatsapp_links))[:3]

        extracted_payments = [f"{pid.kind}:{pid.normalized}" for pid in extract_payment_ids(combined_text)[:4]]

        # Security checks on extracted content
        if parser.has_password_field:
            security_warnings.append("Page contains password or credential input fields.")
        
        low_text = visible_text.lower()
        for kw in _URGENCY_KEYWORDS:
            if kw in low_text:
                security_warnings.append(f"High-urgency promotional/fraud phrasing detected: '{kw}'")

        if len(chain) > 3:
            security_warnings.append(f"Multiple redirect hops detected ({len(chain) - 1} hops).")

        return SafePageContent(
            status=CoverageStatus.CHECKED,
            final_url=current,
            status_code=status_code,
            hops=hop,
            redirect_chain=chain,
            title=title,
            meta_description=meta_desc,
            meta_tags=parser.meta_tags,
            visible_text=visible_text,
            phones=extracted_phones,
            emails=extracted_emails,
            whatsapp_links=whatsapp_links,
            payment_identifiers=extracted_payments,
            has_login_form=parser.has_login_form,
            has_password_field=parser.has_password_field,
            form_actions=parser.form_actions[:3],
            security_warnings=security_warnings,
            reason=f"Fetched successfully with HTTP {status_code}",
            fetch_time_ms=elapsed,
        )

    return SafePageContent(
        status=CoverageStatus.COULD_NOT_CHECK,
        final_url=current,
        hops=max_hops,
        redirect_chain=chain,
        reason="Too many redirects",
        fetch_time_ms=(time.monotonic() - t0) * 1000,
    )
