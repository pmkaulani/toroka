"""Flags links built to look like a brand they are not. Pure string logic: works offline, so a missing API key can never switch it off."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

TWO_PART = {"co.ke", "or.ke", "go.ke", "ac.ke", "ne.ke", "sc.ke", "me.ke", "com.ng", "co.ug", "co.tz", "com.gh", "com.eg", "co.uk", "com.au", "co.za"}  # approximate; use tldextract if you have it


@dataclass(frozen=True)
class LinkFlag:
    code: str
    severity: str          # critical | major
    text: str


def registered_domain(host: str) -> str:
    p = host.lower().strip(".").split(".")
    return ".".join(p[-3:]) if len(p) >= 3 and ".".join(p[-2:]) in TWO_PART else ".".join(p[-2:]) if len(p) >= 2 else host


def _core(host: str) -> str:                       # "jumia-kenya-deals" from "www.jumia-kenya-deals.com"
    return registered_domain(host).split(".")[0]


def within_one(a: str, b: str) -> bool:           # one typo apart: substitution, insertion, deletion or swapped neighbours
    if a == b: return True
    if abs(len(a) - len(b)) > 1: return False
    if len(a) == len(b):
        d = [i for i in range(len(a)) if a[i] != b[i]]
        return len(d) == 1 or (len(d) == 2 and d[1] == d[0] + 1 and a[d[0]] == b[d[1]] and a[d[1]] == b[d[0]])
    s, l = (a, b) if len(a) < len(b) else (b, a)
    return any(l[:i] + l[i + 1:] == s for i in range(len(l)))


def deceptive_link_flags(url: str, brands: dict[str, set[str]]) -> list[LinkFlag]:
    """brands: {"Jumia": {"jumia.co.ke", "jumia.com.ng", ...}} using REGISTERED domains the brand really owns."""
    raw = url.strip() if "://" in url else "https://" + url.strip()
    try:
        sp = urlsplit(raw); host = (sp.hostname or "").lower().rstrip(".")
    except ValueError:
        return []
    if not host: return []
    flags, reg = [], registered_domain(host)
    if sp.username is not None:
        shown = sp.username
        flags.append(LinkFlag("userinfo_trick", "critical", f"The link starts with \u201c{shown}\u201d to look like a trusted address, but it really goes to {host}." if "." in shown else f"The link hides its real destination ({host}) behind a username."))
    if any(l.startswith("xn--") for l in host.split(".")) or any(ord(c) > 127 for c in host):
        flags.append(LinkFlag("lookalike_characters", "major", "The address uses look-alike characters that can imitate a real brand."))
    for brand, official in brands.items():
        official = {d.lower() for d in official}
        if reg in official:
            continue                                                         # the real thing: exact registered domain
        b = re.sub(r"[^a-z0-9]", "", brand.lower())
        for d in official:
            if f".{d}." in f".{host}." and reg != d:
                flags.append(LinkFlag("embedded_official_domain", "critical", f"The address contains {d} but actually belongs to {reg}. Only {d} is {brand}'s website.")); break
        else:
            subs = host[: -len(reg)].strip(".").split(".") if host.endswith(reg) else []
            core_tokens = set(re.split(r"[-_]", _core(host))) | {_core(host)}
            if b in subs or any(b == s.replace("-", "") for s in subs):
                flags.append(LinkFlag("brand_in_subdomain", "critical", f"The address puts \u201c{brand}\u201d in front of {reg}, which is not {brand}'s website."))
            elif b in core_tokens or (len(b) >= 5 and any(t.startswith(b) or t.endswith(b) for t in core_tokens if len(t) <= len(b) + 10)):
                flags.append(LinkFlag("brand_in_domain", "major", f"The address uses the name \u201c{brand}\u201d but {reg} is not {brand}'s website."))
            elif len(b) >= 5 and any(t != b and within_one(t, b) for t in core_tokens):
                flags.append(LinkFlag("misspelled_brand", "major", f"The address looks like a misspelling of \u201c{brand}\u201d. {reg} is not {brand}'s website."))
    seen, out = set(), []
    for f in flags:                                                          # one flag per code, worst first
        if f.code not in seen: seen.add(f.code); out.append(f)
    return sorted(out, key=lambda f: f.severity != "critical")
