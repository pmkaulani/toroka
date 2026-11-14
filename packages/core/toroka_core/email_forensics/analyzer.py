from __future__ import annotations

import hashlib
import ipaddress
import re
from difflib import SequenceMatcher
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

MAX_EMAIL_BYTES = 5 * 1024 * 1024
MAX_MIME_PARTS = 200
MAX_LINKS = 100
MAX_FINDINGS = 40

# A conservative, curated set of commonly impersonated brands. This is not an
# allow-list for every legitimate sender; it only helps explain a claim/domain mismatch.
BRAND_DOMAINS = {
    "microsoft": ("microsoft.com", "microsoftonline.com", "office.com", "live.com", "outlook.com"),
    "google": ("google.com", "googlemail.com", "gmail.com"),
    "apple": ("apple.com", "icloud.com"),
    "safaricom": ("safaricom.co.ke",),
    "m-pesa": ("safaricom.co.ke", "mpesa.co.ke"),
    "mpesa": ("safaricom.co.ke", "mpesa.co.ke"),
    "kcb": ("kcbgroup.com",),
    "equity": ("equitybankgroup.com", "equitygroupholdings.com"),
    "ncba": ("ncbagroup.com", "ncba.co.ke"),
    "paypal": ("paypal.com",),
    "dhl": ("dhl.com",),
    "kra": ("kra.go.ke",),
    "ecitizen": ("ecitizen.go.ke",),
    "huduma": ("hudumakenya.go.ke",),
}
SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "cutt.ly", "shorturl.at", "rb.gy", "rebrand.ly", "lnkd.in", "tiny.cc",
}
DANGEROUS_EXTENSIONS = {
    ".ade", ".adp", ".apk", ".app", ".bat", ".cmd", ".com", ".cpl", ".dll",
    ".dmg", ".exe", ".hta", ".img", ".iso", ".jar", ".js", ".jse", ".lnk",
    ".msi", ".msp", ".pif", ".ps1", ".reg", ".scr", ".sct", ".sh", ".sys",
    ".vb", ".vbe", ".vbs", ".wsf", ".wsh", ".docm", ".xlsm", ".pptm", ".xlam",
}
ARCHIVE_EXTENSIONS = {".7z", ".arj", ".cab", ".gz", ".iso", ".rar", ".tar", ".zip"}
MULTI_LABEL_SUFFIXES = {
    "co.ke", "or.ke", "go.ke", "ac.ke", "sc.ke", "me.ke", "ne.ke", "mobi.ke",
    "co.ug", "or.ug", "ac.ug", "co.tz", "or.tz", "ac.tz", "co.za", "org.za",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "org.nz", "com.ng", "com.gh", "com.sg", "com.my", "co.in",
}


def _decode_header(value: object) -> str:
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(str(value))))[:1000]
    except Exception:
        return str(value)[:1000]


def _domain(value: str) -> str:
    value = (value or "").strip().strip("<>[](){}.,;\"'").lower().rstrip(".")
    if not value or len(value) > 253 or "@" in value or "/" in value or " " in value:
        return ""
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    try:
        import idna
        value = idna.encode(value, uts46=True, std3_rules=True).decode("ascii").lower()
    except Exception:
        try:
            value = value.encode("idna").decode("ascii").lower()
        except Exception:
            return ""
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value):
        return ""
    return value


def _org_domain(host: str) -> str:
    host = _domain(host)
    if not host:
        return ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    suffix2 = ".".join(labels[-2:])
    if suffix2 in MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix2


def _addresses(values: list[str]) -> list[dict]:
    found = []
    for display, address in getaddresses(values):
        address = address.strip().strip("<>")
        if not address or "@" not in address:
            continue
        local, host = address.rsplit("@", 1)
        domain = _domain(host)
        found.append({"display_name": _decode_header(display), "address": address[:320], "domain": domain,
                      "internationalized_domain": bool(domain and ("xn--" in domain or any(ord(ch) > 127 for ch in host)))})
    return found[:8]


def _header_values(msg, name: str) -> list[str]:
    return [_decode_header(x) for x in (msg.get_all(name, []) or [])][:20]


def _header_domain(value: str) -> str:
    # Used only for Message-ID / Return-Path-style fields, not arbitrary prose.
    match = re.search(r"@([A-Za-z0-9._-]+)", value or "")
    return _domain(match.group(1)) if match else ""


def _registrable_host_from_url(url: str) -> tuple[str, str, list[str]]:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        ascii_host = _domain(host)
        if not ascii_host:
            return "", "", []
        labels = ascii_host.split(".")
        org = _org_domain(ascii_host)
        notes = []
        if any(label.startswith("xn--") for label in labels):
            notes.append("punycode_hostname")
        try:
            if host and any(ord(ch) > 127 for ch in host):
                notes.append("unicode_hostname")
        except Exception:
            pass
        if parsed.username or parsed.password:
            notes.append("url_contains_userinfo")
        try:
            ipaddress.ip_address(ascii_host)
            notes.append("ip_literal_destination")
        except ValueError:
            pass
        return ascii_host, org, notes
    except Exception:
        return "", "", []


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[dict] = []
        self._active: dict | None = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            attr = dict(attrs)
            href = (attr.get("href") or "").strip()
            if href and len(self.links) < MAX_LINKS:
                self._active = {"href": href[:2048], "text": ""}

    def handle_data(self, data):
        if self._active is not None and len(self._active["text"]) < 500:
            self._active["text"] += data[:500]

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._active is not None:
            self.links.append(self._active)
            self._active = None


def _extract_body_and_links(msg) -> tuple[list[str], list[dict], list[dict]]:
    text_parts: list[str] = []
    links: list[dict] = []
    attachments: list[dict] = []
    count = 0
    for part in msg.walk():
        count += 1
        if count > MAX_MIME_PARTS:
            break
        if part.is_multipart():
            continue
        filename = _decode_header(part.get_filename() or "")
        ctype = (part.get_content_type() or "application/octet-stream").lower()
        payload = part.get_payload(decode=True)
        if payload is None:
            raw_payload = part.get_payload()
            if isinstance(raw_payload, str):
                payload = raw_payload.encode("utf-8", errors="replace")
            else:
                payload = b""
        # The original message is capped at 5 MiB. Attachment bytes are hashed and
        # described only; Toroka never executes, extracts, previews, or stores them.
        if filename or part.get_content_disposition() == "attachment":
            ext = ("." + filename.rsplit(".", 1)[-1].lower()) if "." in filename else ""
            attachments.append({
                "filename": filename[:200] or "(unnamed attachment)",
                "content_type": ctype[:120],
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
                "extension": ext,
                "risk_note": ("active_or_executable_file_type" if ext in DANGEROUS_EXTENSIONS else
                              "archive_not_opened" if ext in ARCHIVE_EXTENSIONS else
                              "review_file_type" if ctype in {"text/html", "application/octet-stream"} else None),
            })
            continue
        if ctype not in {"text/plain", "text/html"}:
            continue
        try:
            charset = part.get_content_charset() or "utf-8"
            decoded = payload.decode(charset, errors="replace")[:500_000]
        except Exception:
            decoded = payload.decode("utf-8", errors="replace")[:500_000]
        if ctype == "text/html":
            parser = _LinkParser()
            try:
                parser.feed(decoded)
                links.extend(parser.links)
            except Exception:
                pass
            # Keep no raw HTML in the response. HTML text is used only for matching.
            text_parts.append(re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", decoded))
        else:
            text_parts.append(decoded)
            for raw_url in re.findall(r"(?:https?://|www\.)[^\s<>\"']+", decoded, flags=re.I):
                if raw_url.lower().startswith("www."):
                    raw_url = "https://" + raw_url
                links.append({"href": raw_url.rstrip(".,);]"), "text": ""})
        if len(links) >= MAX_LINKS:
            links = links[:MAX_LINKS]
            break
    return text_parts, links[:MAX_LINKS], attachments[:100]


def _authserv_trusted(authserv: str, trusted_ids: tuple[str, ...], newest_received: str) -> bool:
    authserv = (authserv or "").lower().rstrip(".")
    received = (newest_received or "").lower()
    if not authserv or not trusted_ids:
        return False
    matches = False
    for allowed in trusted_ids:
        allowed = allowed.strip().lower()
        if not allowed:
            continue
        if allowed.startswith("*."):
            suffix = allowed[1:]
            if authserv.endswith(suffix) and authserv != suffix[1:]:
                matches = True
                break
        elif authserv == allowed.rstrip("."):
            matches = True
            break
    # RFC 8601 trust boundary: require the authserv-id to appear on the newest
    # Received hop as well, so an older sender-inserted header is not accepted.
    return bool(matches and re.search(r"\bby\s+" + re.escape(authserv) + r"(?:\s|;|$)", received))


def _parse_auth_results(values: list[str], trusted_ids: tuple[str, ...], received: list[str]) -> tuple[list[dict], list[dict]]:
    trusted, untrusted = [], []
    newest_received = received[0] if received else ""
    for raw in values[:10]:
        first = raw.split(";", 1)[0].strip()
        authserv = first.split()[0] if first else ""
        results = {name.lower(): value.lower() for name, value in re.findall(
            r"\b(spf|dkim|dmarc)\s*=\s*([a-z0-9_-]+)", raw, flags=re.I
        )}
        details = {}
        for key in ("smtp.mailfrom", "header.d", "header.from", "smtp.helo"):
            match = re.search(r"\b" + re.escape(key) + r"\s*=\s*(?:<([^>]+)>|([^;\s]+))", raw, flags=re.I)
            if match:
                details[key] = (match.group(1) or match.group(2)).strip()[:255]
        record = {"authserv_id": authserv[:160], "results": results, "details": details}
        if _authserv_trusted(authserv, trusted_ids, newest_received) and not trusted:
            trusted.append(record)
        else:
            record["trust"] = "untrusted_header_claim"
            untrusted.append(record)
    return trusted, untrusted


def _received_summary(values: list[str]) -> list[dict]:
    rows = []
    for raw in values[:20]:
        by = re.search(r"\bby\s+([A-Za-z0-9._:-]+)", raw, flags=re.I)
        from_host = re.search(r"\bfrom\s+([A-Za-z0-9._:-]+)", raw, flags=re.I)
        date_match = re.search(r";\s*(.+)$", raw)
        rows.append({"from_host": (from_host.group(1) if from_host else None),
                     "by_host": (by.group(1) if by else None),
                     "date_text": (date_match.group(1).strip()[:120] if date_match else None)})
    return rows


def _brand_claims(display_name: str, from_domain: str) -> list[dict]:
    claims = []
    name = (display_name or "").casefold()
    host = _domain(from_domain)
    if not host:
        return claims
    org = _org_domain(host)
    labels = host.split(".")
    root_label = labels[-2] if len(labels) > 1 else labels[0]
    for brand, official_domains in BRAND_DOMAINS.items():
        normalized_brand = brand.strip()
        if normalized_brand not in name:
            continue
        exact = any(org == expected or org.endswith("." + expected) for expected in official_domains)
        if exact:
            continue
        expected_labels = [x.split(".")[0] for x in official_domains]
        similarity = max((SequenceMatcher(None, root_label, x).ratio() for x in expected_labels), default=0.0)
        brand_in_host = any(normalized_brand.replace("-", "") in label.replace("-", "") for label in labels)
        claims.append({"brand": normalized_brand, "official_domains": list(official_domains),
                       "domain": org, "similarity": round(similarity, 3),
                       "severity": "high" if brand_in_host or similarity >= 0.72 else "moderate"})
    return claims


def _dns_posture(domains: list[str]) -> dict:
    result = {"status": "not_checked", "domains": []}
    try:
        import dns.resolver
    except Exception:
        result["status"] = "dependency_not_installed"
        return result
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 1.5
    resolver.lifetime = 3.0
    for domain in list(dict.fromkeys([x for x in domains if x]))[:3]:
        row = {"domain": domain, "spf_record_count": 0, "spf_records": [], "dmarc_record_count": 0,
               "dmarc_policy": None, "dmarc_rua_configured": False, "status": "checked"}
        try:
            answers = resolver.resolve(domain, "TXT", lifetime=3.0)
            for answer in answers:
                raw = b"".join(answer.strings).decode("utf-8", errors="replace")
                if raw.lower().startswith("v=spf1"):
                    row["spf_record_count"] += 1
                    row["spf_records"].append(raw[:500])
        except Exception as exc:
            row["spf_lookup_note"] = type(exc).__name__
        try:
            answers = resolver.resolve("_dmarc." + domain, "TXT", lifetime=3.0)
            for answer in answers:
                raw = b"".join(answer.strings).decode("utf-8", errors="replace")
                if raw.lower().startswith("v=dmarc1"):
                    row["dmarc_record_count"] += 1
                    policy_match = re.search(r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)", raw, flags=re.I)
                    row["dmarc_policy"] = policy_match.group(1).lower() if policy_match else "unspecified"
                    row["dmarc_rua_configured"] = bool(re.search(r"(?:^|;)\s*rua\s*=", raw, flags=re.I))
        except Exception as exc:
            row["dmarc_lookup_note"] = type(exc).__name__
        row["multiple_spf_records"] = row["spf_record_count"] > 1
        row["multiple_dmarc_records"] = row["dmarc_record_count"] > 1
        result["domains"].append(row)
    result["status"] = "checked" if result["domains"] else "no_domains"
    return result


def _dkim_verify(raw: bytes, signature_count: int) -> dict:
    if signature_count == 0:
        return {"status": "no_signature", "signatures": []}
    try:
        import dkim
    except Exception:
        return {"status": "dependency_not_installed", "signatures": [],
                "note": "Install the optional dkimpy dependency to verify DKIM signatures locally."}
    signatures = []
    for idx in range(min(signature_count, 5)):
        try:
            valid = bool(dkim.DKIM(raw).verify(idx=idx, timeout=4))
            signatures.append({"index": idx, "status": "pass" if valid else "fail"})
        except Exception as exc:
            signatures.append({"index": idx, "status": "error", "error_type": type(exc).__name__})
    statuses = {x["status"] for x in signatures}
    overall = "pass" if "pass" in statuses else "fail" if statuses == {"fail"} else "error"
    return {"status": overall, "signatures": signatures,
            "note": "DKIM verifies a domain signature, not the sender's intent or the safety of message content."}


def analyze_email(raw: bytes, *, trusted_authserv_ids: tuple[str, ...] = (), allow_dns_checks: bool = False) -> dict:
    """Analyze an uploaded RFC 5322 message without retaining or returning the raw content."""
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        raise ValueError("The email is empty.")
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError("The email exceeds the 5 MB limit.")
    try:
        msg = BytesParser(policy=policy.default).parsebytes(bytes(raw))
    except Exception as exc:
        raise ValueError("Toroka could not parse this email file.") from exc

    findings: list[dict] = []
    def add(code: str, severity: str, title: str, detail: str, limitation: str | None = None):
        if len(findings) >= MAX_FINDINGS:
            return
        record = {"code": code, "severity": severity, "title": title, "detail": detail}
        if limitation:
            record["limitation"] = limitation
        if code not in {x["code"] for x in findings}:
            findings.append(record)

    from_headers = _header_values(msg, "From")
    sender_headers = _header_values(msg, "Sender")
    reply_headers = _header_values(msg, "Reply-To")
    return_path_headers = _header_values(msg, "Return-Path")
    message_id_headers = _header_values(msg, "Message-ID")
    received_headers = _header_values(msg, "Received")
    auth_headers = _header_values(msg, "Authentication-Results")
    arc_auth_headers = _header_values(msg, "ARC-Authentication-Results")
    dkim_headers = _header_values(msg, "DKIM-Signature")

    from_addresses = _addresses(from_headers)
    sender_addresses = _addresses(sender_headers)
    reply_addresses = _addresses(reply_headers)
    return_domains = [_header_domain(x) for x in return_path_headers]
    return_domains = [x for x in return_domains if x]
    from_domain = from_addresses[0]["domain"] if from_addresses else ""
    from_display = from_addresses[0]["display_name"] if from_addresses else ""
    if from_addresses and from_addresses[0].get("internationalized_domain"):
        add("SENDER_INTERNATIONALIZED_DOMAIN", "moderate", "Sender uses an internationalized domain",
            f"The sender domain is represented in IDNA/Punycode as {from_domain}. Internationalized domains can be legitimate, but visually similar characters can imitate trusted brands.")
    reply_domain = reply_addresses[0]["domain"] if reply_addresses else ""
    return_domain = return_domains[0] if return_domains else ""

    if not from_headers:
        add("MISSING_FROM_HEADER", "high", "The message has no From header", "The submitted message does not contain a valid From header.")
    elif len(from_addresses) != 1:
        add("MULTIPLE_OR_INVALID_FROM", "high", "The From header is ambiguous", "Toroka found multiple From addresses or could not parse exactly one valid sender.")
    if len(reply_headers) > 1:
        add("DUPLICATE_REPLY_TO", "moderate", "Multiple Reply-To headers", "More than one Reply-To header is present. This can create ambiguity about where replies go.")
    if len(return_path_headers) > 1:
        add("DUPLICATE_RETURN_PATH", "moderate", "Multiple Return-Path headers", "More than one Return-Path header is present in the submitted message.")
    if len(auth_headers) > 1:
        add("MULTIPLE_AUTH_RESULTS", "informational", "Multiple Authentication-Results headers", "Only one configured, trusted result at the newest receiving hop can be considered. Other copies are treated as untrusted claims.")
    if len(received_headers) == 0:
        add("NO_RECEIVED_TRACE", "informational", "No Received trace headers", "No Received headers were found. A screenshot or copied header set may be incomplete; routing could not be reconstructed.")

    if reply_domain and from_domain and _org_domain(reply_domain) != _org_domain(from_domain):
        add("FROM_REPLY_TO_DOMAIN_MISMATCH", "high", "Reply address uses a different organization domain",
            f"The visible From domain is {from_domain}, while Reply-To uses {reply_domain}. Replies may go to a different organization.",
            "Some legitimate mailing platforms use separate reply domains. Verify the relationship independently.")
    if return_domain and from_domain and _org_domain(return_domain) != _org_domain(from_domain):
        add("FROM_RETURN_PATH_DOMAIN_DIFFERENCE", "informational", "Return-Path differs from visible sender domain",
            f"From uses {from_domain}; Return-Path uses {return_domain}.",
            "Bulk mail providers and forwarding systems commonly use separate envelope-sender domains. This is a lead, not proof of spoofing.")
    if sender_addresses and from_addresses and sender_addresses[0]["domain"] and from_domain and _org_domain(sender_addresses[0]["domain"]) != _org_domain(from_domain):
        add("SENDER_FROM_DOMAIN_DIFFERENCE", "moderate", "Sender and From domains differ",
            f"Sender uses {sender_addresses[0]['domain']}, while From uses {from_domain}.",
            "Some delegated mail systems use a separate Sender field. Verify the sending arrangement.")

    from_local_part = from_addresses[0]["address"].rsplit("@", 1)[0] if from_addresses else ""
    brand_claims = _brand_claims(from_display + " " + from_local_part, from_domain)
    for claim in brand_claims:
        add("DISPLAY_NAME_BRAND_DOMAIN_MISMATCH", claim["severity"],
            f"Display name claims {claim['brand']} but sender domain differs",
            f"The display name includes {claim['brand']}, but the sender domain is {claim['domain']}. Expected official domains include: {', '.join(claim['official_domains'])}.",
            "Display names are user-controlled. An exact official domain match still does not guarantee the message or account is safe.")

    # Extract MIME parts, but never execute, unpack, or persist attachments.
    _, raw_links, attachments = _extract_body_and_links(msg)
    links = []
    link_warnings = 0
    for link in raw_links[:MAX_LINKS]:
        href = unquote((link.get("href") or "").strip())
        if not href:
            continue
        if href.startswith("//"):
            href = "https:" + href
        if not re.match(r"(?i)^https?://", href):
            try:
                non_http_scheme = urlsplit(href).scheme.lower()
            except Exception:
                non_http_scheme = ""
            if non_http_scheme in {"javascript", "data", "vbscript", "file"}:
                add("NON_HTTP_ACTIVE_LINK_SCHEME", "high", "Message contains an active or local-file link scheme",
                    f"An HTML link uses the {non_http_scheme}: scheme instead of a normal web URL. Toroka did not execute or open it.")
            continue
        host, org, host_notes = _registrable_host_from_url(href)
        try:
            parsed = urlsplit(href)
            scheme = parsed.scheme.lower()
            display = re.sub(r"\s+", " ", (link.get("text") or "")).strip()[:180]
        except Exception:
            continue
        warning_codes = list(host_notes)
        label_url = display if display.lower().startswith(("http://", "https://")) else "https://" + display
        label_host, label_org, _ = _registrable_host_from_url(label_url) if re.match(r"(?i)^(?:https?://)?[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/|$)", display) else ("", "", [])
        if label_org and org and label_org != org:
            warning_codes.append("visible_link_destination_mismatch")
        if org in SHORTENER_DOMAINS:
            warning_codes.append("url_shortener")
        if warning_codes:
            link_warnings += 1
        if "visible_link_destination_mismatch" in warning_codes:
            add("LINK_TEXT_DESTINATION_MISMATCH", "high", "Visible link text does not match its destination",
                f"A link labelled {display[:100]!r} points to {host or 'an unrecognized host'}.",
                "Some links legitimately display descriptive text instead of their destination. The actual destination should be checked before opening.")
        if "url_contains_userinfo" in warning_codes:
            add("URL_CONTAINS_USERINFO", "high", "A link contains embedded user information", "The URL includes a username or password component before its host, which can disguise the actual destination.")
        if "ip_literal_destination" in warning_codes:
            add("URL_IP_LITERAL_DESTINATION", "moderate", "A link points directly to an IP address", f"A message link uses an IP address instead of a conventional domain ({host}). This is unusual but not conclusive.")
        if "punycode_hostname" in warning_codes or "unicode_hostname" in warning_codes:
            add("URL_INTERNATIONALIZED_HOST", "moderate", "A link uses an internationalized hostname", f"A link points to {host}. Internationalized domains can be legitimate, but visually similar characters can impersonate another domain.")
        if "url_shortener" in warning_codes:
            add("URL_SHORTENER_PRESENT", "moderate", "A link uses a URL-shortening service", f"A message link uses {org}. The final destination is not expanded by this local analysis.")
        links.append({"destination_host": host or None, "destination_domain": org or None,
                      "display_text": display or None, "scheme": scheme,
                      "warning_codes": warning_codes})

    if attachments:
        dangerous = [a for a in attachments if a.get("risk_note") == "active_or_executable_file_type"]
        archives = [a for a in attachments if a.get("risk_note") == "archive_not_opened"]
        if dangerous:
            add("ACTIVE_ATTACHMENT_TYPE", "high", "Potentially active attachment type",
                "The message includes attachment types that can execute code or contain active macros: " + ", ".join(a["filename"] for a in dangerous[:8]) + ".",
                "Toroka only inspected attachment names, declared MIME types, sizes and hashes. It did not open or execute files.")
        if archives:
            add("ARCHIVE_ATTACHMENT_NOT_OPENED", "informational", "Archive attachments were not opened",
                "One or more archive attachments were identified. Toroka did not extract them, to avoid executing or unpacking untrusted content.")

    trusted_auth, untrusted_auth = _parse_auth_results(auth_headers, trusted_authserv_ids, received_headers)
    if auth_headers and not trusted_auth:
        add("AUTH_RESULTS_NOT_TRUSTED", "moderate", "Authentication results could not be trusted",
            "The email contains Authentication-Results headers, but none matched the configured receiving-server trust boundary and newest Received hop. Toroka did not use those claims as verified results.")
    for result in trusted_auth:
        for method in ("spf", "dkim", "dmarc"):
            value = result.get("results", {}).get(method)
            if value == "fail":
                severity = "high" if method == "dmarc" else "moderate"
                add("TRUSTED_" + method.upper() + "_FAIL", severity, f"Trusted receiving server reports {method.upper()} failure",
                    f"The configured receiving server ({result['authserv_id']}) reports {method.upper()} authentication as fail.",
                    "Forwarding, gateways and message modifications can affect authentication. Interpret alongside DKIM, DMARC alignment and ARC.")
            elif value == "pass":
                add("TRUSTED_" + method.upper() + "_PASS", "positive", f"Trusted receiving server reports {method.upper()} pass",
                    f"The configured receiving server ({result['authserv_id']}) reports {method.upper()} as pass.",
                    "A pass authenticates a domain or sending path; it does not prove the content is harmless or that an account was not compromised.")
            elif value in {"softfail", "temperror", "permerror", "none", "neutral", "policy"}:
                add("TRUSTED_" + method.upper() + "_" + value.upper(), "informational", f"Trusted receiving server reports {method.upper()} {value}",
                    f"The configured receiving server ({result['authserv_id']}) reports {method.upper()} as {value}.")

    dkim_verification = {"status": "not_requested", "signatures": []}
    dns_posture = {"status": "not_requested", "domains": []}
    if allow_dns_checks:
        dkim_verification = _dkim_verify(bytes(raw), len(dkim_headers))
        domains = [from_domain]
        domains.extend(x["domain"] for x in sender_addresses if x.get("domain"))
        dns_posture = _dns_posture(domains)
        if dkim_verification["status"] == "fail":
            add("DKIM_CRYPTOGRAPHIC_VERIFICATION_FAILED", "high", "DKIM signature verification failed",
                "The DKIM signature could not be cryptographically validated against the current public DNS key.",
                "Key rotation, DNS changes, forwarding or message modification can cause verification failure. A failure is not by itself proof of malicious intent.")
        elif dkim_verification["status"] == "pass":
            add("DKIM_CRYPTOGRAPHIC_VERIFICATION_PASSED", "positive", "A DKIM signature verified cryptographically",
                "At least one signature verified against the current public DNS key.",
                "This authenticates a signing domain, not the sender's intent. Check whether the signing domain aligns with From.")
    elif dkim_headers:
        dkim_verification = {"status": "signature_present_not_verified", "signatures": [],
                             "note": "DNS verification was not requested. The presence of a DKIM-Signature header is not proof that it is valid."}

    dkim_signature_details = []
    for raw_sig in dkim_headers[:5]:
        tags = {}
        for part in raw_sig.split(";"):
            if "=" in part:
                key, value = part.split("=", 1)
                tags[key.strip().lower()] = value.strip()[:255]
        signing_domain = _domain(tags.get("d", ""))
        aligned = bool(signing_domain and from_domain and _org_domain(signing_domain) == _org_domain(from_domain))
        dkim_signature_details.append({"signing_domain": signing_domain or None,
                                       "selector": tags.get("s"), "algorithm": tags.get("a"),
                                       "canonicalization": tags.get("c"), "aligned_with_from": aligned})
        if signing_domain and from_domain and not aligned:
            add("DKIM_SIGNING_DOMAIN_NOT_ALIGNED", "informational", "DKIM signing domain differs from the visible sender domain",
                f"The DKIM signature uses {signing_domain}; the visible From domain is {from_domain}.",
                "Third-party mail platforms can sign with their own domains. DMARC alignment depends on the receiver's evaluation and policy.")

    arc_headers = _header_values(msg, "ARC-Seal")
    if arc_headers:
        add("ARC_CHAIN_PRESENT_NOT_VERIFIED", "informational", "ARC headers are present but not validated",
            f"The message contains {len(arc_headers)} ARC-Seal header(s). Toroka did not validate the ARC chain in this analysis.")

    message_id_domain = _header_domain(message_id_headers[0]) if message_id_headers else ""
    if message_id_domain and from_domain and _org_domain(message_id_domain) != _org_domain(from_domain):
        add("MESSAGE_ID_DOMAIN_DIFFERENCE", "informational", "Message-ID domain differs from From domain",
            f"Message-ID uses {message_id_domain}; From uses {from_domain}.",
            "Email providers and gateways often generate Message-IDs on their own infrastructure. This is context only.")

    mime_parts = sum(1 for _ in msg.walk())
    if mime_parts > MAX_MIME_PARTS:
        add("MIME_PART_LIMIT_REACHED", "informational", "MIME inspection limit reached", f"The message contains more than {MAX_MIME_PARTS} MIME parts. Remaining parts were not inspected.")

    strong = sum(1 for f in findings if f["severity"] == "high")
    moderate = sum(1 for f in findings if f["severity"] == "moderate")
    if strong:
        attention = "high_attention"
        summary = "Toroka found one or more high-priority email identity or content indicators that should be checked before acting."
    elif moderate >= 2:
        attention = "review_recommended"
        summary = "Toroka found multiple email indicators that deserve review. They do not independently prove impersonation."
    elif moderate == 1:
        attention = "some_indicators"
        summary = "Toroka found an email indicator worth checking. More independent evidence is needed for a conclusion."
    elif not from_addresses:
        attention = "insufficient_email_identity_data"
        summary = "Toroka could not identify a valid sender address from the supplied message."
    else:
        attention = "no_major_spoofing_indicator_observed"
        summary = "Toroka did not observe major spoofing indicators in the fields it could inspect. This does not mean the email is safe."

    return {
        "schema_version": "email-forensics.v1",
        "status": "analysis_complete",
        "attention_level": attention,
        "summary": summary,
        "sender_identity": {
            "from": from_addresses[:3], "sender": sender_addresses[:3], "reply_to": reply_addresses[:3],
            "return_path_domain": return_domain or None,
            "from_domain": from_domain or None,
            "message_id_domain": message_id_domain or None,
            "from_header_count": len(from_headers), "reply_to_header_count": len(reply_headers),
        },
        "authentication": {
            "trusted_receiver_results": trusted_auth,
            "untrusted_header_claims": untrusted_auth[:5],
            "dkim_signature_count": len(dkim_headers),
            "dkim_signatures": dkim_signature_details,
            "dkim_verification": dkim_verification,
            "dns_posture": dns_posture,
            "arc_seal_count": len(arc_headers),
        },
        "routing": {"received_hop_count": len(received_headers), "hops": _received_summary(received_headers)},
        "links": {"count": len(links), "warning_count": link_warnings, "items": links[:30]},
        "attachments": {"count": len(attachments), "items": attachments[:30],
                        "content_opened": False, "executed": False},
        "findings": findings,
        "limitations": [
            "Toroka analyzed the submitted message locally and did not retain or return its raw body or attachment contents.",
            "Authentication-Results is trusted only when its authserv-id is configured and matches the newest Received hop. Other copies are untrusted claims.",
            "SPF cannot be reliably recalculated from an uploaded email alone because the original SMTP connection IP and envelope context may not be trustworthy in the file.",
            "DKIM DNS verification and sender-domain DNS posture checks run only when the user explicitly enables DNS checks. These lookups disclose queried domains/selectors to DNS resolvers, not the message body.",
            "A valid SPF, DKIM or DMARC result does not prove an account is uncompromised or message content is safe.",
            "A failed authentication check can result from forwarding, gateways or message modifications. Review ARC and delivery context.",
            "Links are inspected but not opened or fetched. Attachments are hashed and described but never extracted or executed.",
            "A screenshot alone cannot establish original message headers or authentication results. Use a downloaded .eml file when possible.",
        ],
        "privacy": {"raw_email_stored": False, "raw_email_returned": False,
                    "attachment_content_stored": False, "external_dns_queries_performed": bool(allow_dns_checks)},
    }
