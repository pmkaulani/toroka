"""Central URL Investigation Pipeline for Toroka (Section 2 & 4).

Coordinates:
1. URL Parsing & Normalisation (social platforms, internationalised domains, shortener expansion);
2. Internal Toroka Intelligence (Indicators, Reports, Verified Records, Opportunities);
3. Threat Feed Lookups (OpenPhish, Blackbook, URLhaus audit & status tracking, Google Web Risk);
4. SSRF-Safe Web Fetch (via ssi_connectors.url_fetcher with IP pinning & 512KB cap);
5. Live Public Search (via Tavily when configured);
6. Grounded Gemini AI Synthesis (when configured; LLM never overrides policy);
7. Platform-Specific Profile Inspection (Instagram vs TikTok vs Facebook isolated identity);
8. Policy-based Evidence Synthesis (Risk Band, Strongest Points, Contradictions, Sources, Checklist);
9. Caching & In-flight request deduplication.
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, quote_plus, urljoin

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from ssi_rules import normalize as nz
from ssi_rules.registry import load_registry as load_official_registry
from ssi_rules.vocabulary import CoverageStatus, EvidenceType, Strength
from ssi_connectors.url_fetcher import safe_fetch_page, SafePageContent

from . import db as m
from .config import Settings
from .public_search import public_search, manual_search_url, evaluate_search_relevance, filter_public_search_results
from .security import Crypto

logger = logging.getLogger("toroka.url_pipeline")

CS = CoverageStatus

_REVIEWER_PLACEHOLDERS = {"", "unreviewed", "pending", "system", "automatic", "auto", "none", "null"}


def verified_record_review_state(record: Any, today=None) -> tuple[bool, str]:
    """Explain why a registry record is or is not current enough to verify an identity."""
    from datetime import date
    today = today or date.today()
    if getattr(record, "status", "") != "active":
        return False, "the registry record is not active"
    reviewer = str(getattr(record, "reviewer", "") or "").strip().casefold()
    if reviewer in _REVIEWER_PLACEHOLDERS:
        return False, "it has no completed human review"
    try:
        last_verified = date.fromisoformat(str(getattr(record, "last_verified_at", ""))[:10])
        review_due = date.fromisoformat(str(getattr(record, "review_due", ""))[:10])
    except (TypeError, ValueError):
        return False, "its review dates are missing or invalid"
    if last_verified > today:
        return False, "its recorded verification date is in the future"
    if review_due < today:
        return False, f"its review expired on {review_due.isoformat()}"
    source_url = str(getattr(record, "source_url", "") or "")
    try:
        source_parts = urlsplit(source_url)
        if source_parts.scheme != "https" or not source_parts.hostname or source_parts.username or source_parts.password:
            return False, "its source is not a valid HTTPS reference"
    except ValueError:
        return False, "its source URL is invalid"
    domains = getattr(record, "domains", None) or []
    handles = getattr(record, "handles", None) or []
    if not (domains or handles):
        return False, "it contains no domain or platform identifier"
    return True, "current human-reviewed record"


def is_verified_record_current(record: Any, today=None) -> bool:
    """A record is an official identity assertion only after a dated human review."""
    return verified_record_review_state(record, today)[0]


def host_matches_verified_record(host: str, record: Any) -> bool:
    """Match exact hosts plus www; allow deeper subdomains only when explicitly reviewed."""
    candidate = (host or "").strip().lower().rstrip(".")
    if not candidate:
        return False
    for raw_domain in (getattr(record, "domains", None) or []):
        trusted = str(raw_domain or "").strip().lower().rstrip(".")
        if not trusted:
            continue
        if candidate == trusted or candidate == f"www.{trusted}":
            return True
        if bool(getattr(record, "include_subdomains", False)) and candidate.endswith("." + trusted):
            return True
    return False


def invalidate_url_cache(target_url: str | None = None) -> None:
    """Invalidate stale URL/domain assessments after an admin registry change."""
    cache = URLInvestigationCache.get_instance()
    with cache._cache_lock:
        if target_url:
            norm = target_url.strip()
            if not norm.startswith(("http://", "https://")):
                norm = "https://" + norm
            cache._url_cache.pop(norm, None)
            try:
                host = urlsplit(norm).hostname or ""
            except ValueError:
                host = ""
            cache._domain_cache.pop(host.lower().rstrip("."), None)
        else:
            cache._url_cache.clear()
            cache._domain_cache.clear()

# ---------------------------------------------------------------------------
# Threat Feed Management (Section 2.C)
# ---------------------------------------------------------------------------

@dataclass
class ThreatFeedStatus:
    name: str
    url: str
    http_status: int | None = None
    item_count: int = 0
    last_checked: str | None = None
    error: str | None = None
    available: bool = False
    notes: str = ""


class ThreatFeedManager:
    """Manages OpenPhish, Blackbook, and URLhaus threat feeds with caching and status audits."""

    _instance: ThreatFeedManager | None = None
    _lock = threading.Lock()

    def __init__(self):
        self.malicious_urls: set[str] = set()
        self.malicious_domains: set[str] = set()
        self.statuses: dict[str, ThreatFeedStatus] = {
            "openphish": ThreatFeedStatus(
                name="OpenPhish Community Feed",
                url="https://openphish.com/feed.txt",
                notes="Active community phishing feed (HTTP 200 verified)",
            ),
            "blackbook": ThreatFeedStatus(
                name="Stamparm Blackbook",
                url="https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt",
                notes="Curated open threat intelligence malicious domain list",
            ),
            "urlhaus": ThreatFeedStatus(
                name="abuse.ch URLhaus",
                url="https://urlhaus.abuse.ch/downloads/json_recent/",
                notes="Audited endpoint status (API requires Auth-Key or returns 410 on retired download URL)",
            ),
        }
        self.last_refresh: float = 0.0
        self._refresh_lock = threading.Lock()
        self._refresh_state_lock = threading.Lock()
        self._refresh_running = False
        self._load_local_seeds()

    @classmethod
    def get_instance(cls) -> "ThreatFeedManager":
        with cls._lock:
            if cls._instance is None:
                cls._instance = ThreatFeedManager()
            return cls._instance

    def _load_local_seeds(self):
        """Seed initial threat indicators from local bundled source data if present."""
        base_dir = os.path.dirname(os.path.abspath(__file__))
        data_paths = [
            os.path.join(base_dir, "..", "..", "..", "packages", "rules", "ssi_rules", "ml", "data", "sources", "phishing_threats.json"),
            os.path.join(base_dir, "static", "threat_seeds.json"),
        ]
        for p in data_paths:
            if os.path.exists(p):
                try:
                    import json
                    with open(p, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if isinstance(data, list):
                        for entry in data:
                            if isinstance(entry, dict):
                                text = entry.get("lure_text", "")
                                for u_match in re.findall(r"https?://[^\s]+", text):
                                    u_clean = u_match.rstrip(".,;:!?'\")").lower()
                                    self.malicious_urls.add(u_clean)
                                    try:
                                        d = urlsplit(u_clean).netloc.split(":")[0].lower()
                                        if d:
                                            self.malicious_domains.add(d)
                                    except Exception:
                                        pass
                    elif isinstance(data, dict):
                        for item in data.get("indicators", []):
                            val = item.get("value", "").strip().lower()
                            if val.startswith("http"):
                                self.malicious_urls.add(val)
                                try:
                                    d = urlsplit(val).netloc.split(":")[0].lower()
                                    if d:
                                        self.malicious_domains.add(d)
                                except Exception:
                                    pass
                            elif val:
                                self.malicious_domains.add(val)
                except Exception as e:
                    logger.debug("Local threat seed error from %s: %s", p, e)

    def refresh_feeds(self, force: bool = False, max_age_seconds: float = 3600.0, background: bool = True) -> None:
        """Fetch live feeds with status recording, deduplicating background refreshes."""
        with self._refresh_state_lock:
            now = time.monotonic()
            if self._refresh_running:
                return
            if not force and (now - self.last_refresh < max_age_seconds):
                return
            self._refresh_running = True

        if background:
            try:
                threading.Thread(target=self._do_refresh, daemon=True).start()
            except Exception:
                with self._refresh_state_lock:
                    self._refresh_running = False
                raise
        else:
            self._do_refresh()

    def _do_refresh(self) -> None:
        try:
            self._refresh_feeds_locked()
        finally:
            with self._refresh_state_lock:
                self._refresh_running = False

    def _refresh_feeds_locked(self) -> None:
        with self._refresh_lock:
            t_iso = datetime.now(timezone.utc).isoformat()

            # 1. OpenPhish
            try:
                with httpx.Client(timeout=4.0, follow_redirects=True) as client:
                    resp = client.get("https://openphish.com/feed.txt", headers={"User-Agent": "Toroka-FeedAudit/1.0"})
                    st = self.statuses["openphish"]
                    st.http_status = resp.status_code
                    st.last_checked = t_iso
                    if resp.status_code == 200:
                        lines = [l.strip().lower() for l in resp.text.splitlines() if l.strip() and not l.startswith("#")]
                        for url in lines:
                            self.malicious_urls.add(url)
                            try:
                                host = urlsplit(url).netloc.split(":")[0].lower()
                                if host:
                                    self.malicious_domains.add(host)
                            except Exception:
                                pass
                        st.item_count = len(lines)
                        st.available = True
                        st.error = None
                    else:
                        st.available = False
                        st.error = f"HTTP {resp.status_code}"
            except Exception as e:
                st = self.statuses["openphish"]
                st.last_checked = t_iso
                st.available = False
                st.error = f"{type(e).__name__}: {str(e)[:80]}"

            # 2. Blackbook
            try:
                with httpx.Client(timeout=6.0, follow_redirects=True) as client:
                    resp = client.get("https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt", headers={"User-Agent": "Toroka-FeedAudit/1.0"})
                    st = self.statuses["blackbook"]
                    st.http_status = resp.status_code
                    st.last_checked = t_iso
                    if resp.status_code == 200:
                        lines = [l.strip().lower() for l in resp.text.splitlines() if l.strip() and not l.startswith("#")]
                        for dom in lines:
                            self.malicious_domains.add(dom)
                        st.item_count = len(lines)
                        st.available = True
                        st.error = None
                    else:
                        st.available = False
                        st.error = f"HTTP {resp.status_code}"
            except Exception as e:
                st = self.statuses["blackbook"]
                st.last_checked = t_iso
                st.available = False
                st.error = f"{type(e).__name__}: {str(e)[:80]}"

            # 3. URLhaus Endpoint Status Audit (Audits active API / retired download URL)
            try:
                with httpx.Client(timeout=4.0, follow_redirects=False) as client:
                    resp = client.get("https://urlhaus.abuse.ch/downloads/json_recent/", headers={"User-Agent": "Toroka-FeedAudit/1.0"})
                    st = self.statuses["urlhaus"]
                    st.http_status = resp.status_code
                    st.last_checked = t_iso
                    if resp.status_code == 410:
                        st.available = False
                        st.error = "HTTP 410 Gone (Endpoint retired by upstream abuse.ch; migrated to API)"
                    elif resp.status_code == 200:
                        st.available = True
                        st.error = None
                    else:
                        st.available = False
                        st.error = f"HTTP {resp.status_code}"
            except Exception as e:
                st = self.statuses["urlhaus"]
                st.last_checked = t_iso
                st.available = False
                st.error = f"{type(e).__name__}: {str(e)[:80]}"

            self.last_refresh = time.monotonic()

    def check(self, url: str, domain: str) -> dict[str, Any] | None:
        """Check if URL or domain is present in known threat feeds."""
        u_norm = url.strip().lower().rstrip("/")
        d_norm = domain.strip().lower()

        # Check exact URL
        if u_norm in self.malicious_urls or (u_norm + "/") in self.malicious_urls:
            return {
                "matched": True,
                "feed": "OpenPhish / Global Threat Intel",
                "match_type": "exact_url",
                "detail": f"Exact URL '{url}' is catalogued in OpenPhish / Global Threat Intel feeds as a known malicious lure.",
                "source_url": "https://openphish.com",
            }

        # Check domain
        if d_norm in self.malicious_domains:
            return {
                "matched": True,
                "feed": "Stamparm Blackbook / Verified Threat Feeds",
                "match_type": "domain",
                "detail": f"Domain '{domain}' is listed on verified malicious host blocklists.",
                "source_url": "https://github.com/stamparm/blackbook",
            }

        # Check subdomains
        parts = d_norm.split(".")
        if len(parts) > 2:
            reg_dom = ".".join(parts[-2:])
            if reg_dom in self.malicious_domains:
                return {
                    "matched": True,
                    "feed": "Verified Threat Feeds",
                    "match_type": "registered_domain",
                    "detail": f"Parent domain '{reg_dom}' is listed on verified malicious host blocklists.",
                    "source_url": "https://github.com/stamparm/blackbook",
                }

        return None


# ---------------------------------------------------------------------------
# Caching & Deduplication (Section 4)
# ---------------------------------------------------------------------------

class URLInvestigationCache:
    """In-memory cache for URL investigations and domain reputation, with in-flight request deduplication."""

    _instance: URLInvestigationCache | None = None
    _lock = threading.Lock()

    def __init__(self):
        self._url_cache: dict[str, tuple[dict[str, Any], float]] = {}  # url -> (result, expires_at)
        self._domain_cache: dict[str, tuple[dict[str, Any], float]] = {}  # domain -> (reputation, expires_at)
        self._in_flight: dict[str, threading.Event] = {}
        self._in_flight_results: dict[str, dict[str, Any]] = {}
        self._cache_lock = threading.RLock()

    @classmethod
    def get_instance(cls) -> "URLInvestigationCache":
        with cls._lock:
            if cls._instance is None:
                cls._instance = URLInvestigationCache()
            return cls._instance

    def _get_url_unlocked(self, url: str) -> dict[str, Any] | None:
        entry = self._url_cache.get(url)
        if entry and entry[1] > time.monotonic():
            return entry[0]
        if entry:
            self._url_cache.pop(url, None)
        return None

    def get_url(self, url: str) -> dict[str, Any] | None:
        with self._cache_lock:
            return self._get_url_unlocked(url)

    def put_url(self, url: str, result: dict[str, Any], ttl_seconds: float = 900.0) -> None:  # 15 min TTL
        with self._cache_lock:
            self._url_cache[url] = (result, time.monotonic() + ttl_seconds)

    def get_domain(self, domain: str) -> dict[str, Any] | None:
        with self._cache_lock:
            entry = self._domain_cache.get(domain)
            if entry and entry[1] > time.monotonic():
                return entry[0]
            if entry:
                self._domain_cache.pop(domain, None)
            return None

    def put_domain(self, domain: str, reputation: dict[str, Any], ttl_seconds: float = 86400.0) -> None:  # 24h TTL
        with self._cache_lock:
            self._domain_cache[domain] = (reputation, time.monotonic() + ttl_seconds)

    def start_or_wait(self, url: str) -> tuple[bool, dict[str, Any] | None]:
        """Deduplicate in-flight requests. Returns (is_primary_worker, cached_result_if_waited)."""
        with self._cache_lock:
            cached = self._get_url_unlocked(url)
            if cached:
                return False, cached
            if url in self._in_flight:
                ev = self._in_flight[url]
            else:
                ev = threading.Event()
                self._in_flight[url] = ev
                return True, None

        # Wait for the primary worker to complete
        ev.wait(timeout=10.0)
        with self._cache_lock:
            return False, self._in_flight_results.get(url) or self._get_url_unlocked(url)

    def complete_in_flight(self, url: str, result: dict[str, Any]) -> None:
        with self._cache_lock:
            self._in_flight_results[url] = result
            ev = self._in_flight.pop(url, None)
            if ev:
                ev.set()

    def clear(self) -> None:
        """Clear all cached entries and pending locks (primarily for test resets)."""
        with self._cache_lock:
            self._url_cache.clear()
            self._domain_cache.clear()
            self._in_flight.clear()
            self._in_flight_results.clear()


# ---------------------------------------------------------------------------
# Platform-Specific Profile Parsing (Section 2.A & 2.G)
# ---------------------------------------------------------------------------

@dataclass
class PlatformProfile:
    is_profile: bool
    platform: str  # instagram, tiktok, facebook, whatsapp, x, or web
    handle: str | None = None
    identifier: str | None = None  # e.g. "instagram:shop_ke"
    is_official_impersonation_risk: bool = False
    impersonated_brand: str | None = None
    canonical_url: str | None = None
    clean_handle: str | None = None
    tracking_params: dict[str, str] = field(default_factory=dict)


_RESERVED_HANDLES = {
    "p", "reel", "reels", "stories", "explore", "accounts", "login",
    "about", "share", "intent", "hashtag", "search", "direct", "terms", "privacy", "help"
}

_KENYA_OFFICIAL_BRANDS = {
    "safaricom": ["safaricom", "safaricomplc", "safaricom_care", "mpesa"],
    "kcb": ["kcbgroup", "kcbbank", "kcbkenya"],
    "equity": ["keequitybank", "equitybank", "equitygroup"],
    "ecitizen": ["ecitizen", "ecitizenkenya", "hudumakenya"],
    "kra": ["kra_customs", "kra_kenya", "kenyarevenueauthority"],
    "kplc": ["kenyapower", "kplc", "kenyapower_care"],
    "airtel": ["airtel_ke", "airtelkenya"],
    "ncba": ["ncbagroup", "ncbabank"],
    "coop": ["coopbankenya", "cooperativebank"],
}

_BRAND_DISPLAY_NAMES = {
    "safaricom": "Safaricom",
    "kcb": "KCB Bank",
    "equity": "Equity Bank",
    "ecitizen": "eCitizen",
    "kra": "Kenya Revenue Authority",
    "kplc": "Kenya Power",
    "airtel": "Airtel",
    "ncba": "NCBA Bank",
    "coop": "Co-operative Bank",
}


def _matches_domain_claimed_by_official_registry(host: str) -> bool:
    """Avoid false impersonation warnings for exact domains listed in the source registry.

    The registry may still be unreviewed, so this only suppresses a lookalike warning;
    it does NOT mark the domain as verified_official.
    """
    candidate = (host or "").strip().lower().rstrip(".")
    if not candidate:
        return False
    try:
        reg = load_official_registry()
        for org in reg.organisations.values():
            for raw in org.official_domains:
                official = str(raw).strip().lower().rstrip(".")
                if candidate == official or candidate == "www." + official:
                    return True
    except Exception:
        logger.warning("Official-domain source registry unavailable for comparison")
    return False


def parse_platform_profile(url_or_handle: str, platform_hint: str | None = None) -> PlatformProfile:
    """Classify platform-specific profile URLs and handles without cross-platform identity merging.

    Strips unnecessary tracking parameters (e.g. ?xtok=..., ?igsh=..., utm_*) to build a clean
    canonical URL and distinct platform identifier (e.g. instagram:base_menswear).
    """
    raw = (url_or_handle or "").strip()
    if not raw:
        return PlatformProfile(False, "web", None, None, False, None)

    tracking_params: dict[str, str] = {}
    if "?" in raw:
        base_part, query_part = raw.split("?", 1)
        from urllib.parse import parse_qsl
        for k, v in parse_qsl(query_part, keep_blank_values=True):
            tracking_params[k] = v
        raw = base_part.rstrip("/")
    else:
        raw = raw.rstrip("/")

    if "#" in raw:
        raw = raw.split("#", 1)[0]

    # 1. Instagram Profile
    m_ig = re.search(r"(?i)(?:https?://)?(?:www\.)?instagram\.com/@?([a-zA-Z0-9_.-]{2,50})$", raw)
    if m_ig and m_ig.group(1).lower() not in _RESERVED_HANDLES:
        h_val = m_ig.group(1).lower().rstrip(".")
        brand = _check_impersonation(h_val, "instagram")
        can_url = f"https://www.instagram.com/{h_val}"
        return PlatformProfile(True, "instagram", h_val, f"instagram:{h_val}", bool(brand), brand, canonical_url=can_url, clean_handle=h_val, tracking_params=tracking_params)

    # 2. TikTok Profile
    m_tt = re.search(r"(?i)(?:https?://)?(?:www\.)?tiktok\.com/@([a-zA-Z0-9_.-]{2,50})$", raw)
    if m_tt and m_tt.group(1).lower() not in _RESERVED_HANDLES:
        h_val = m_tt.group(1).lower().rstrip(".")
        brand = _check_impersonation(h_val, "tiktok")
        can_url = f"https://www.tiktok.com/@{h_val}"
        return PlatformProfile(True, "tiktok", h_val, f"tiktok:{h_val}", bool(brand), brand, canonical_url=can_url, clean_handle=h_val, tracking_params=tracking_params)

    # 3. Facebook Profile / Page / Marketplace
    m_fb = re.search(r"(?i)(?:https?://)?(?:www\.)?facebook\.com/(?:pages/[^/]+/)?@?([a-zA-Z0-9_.-]{2,50})$", raw)
    if m_fb and m_fb.group(1).lower() not in _RESERVED_HANDLES and not m_fb.group(1).lower().startswith("marketplace"):
        h_val = m_fb.group(1).lower().rstrip(".")
        brand = _check_impersonation(h_val, "facebook")
        can_url = f"https://www.facebook.com/{h_val}"
        return PlatformProfile(True, "facebook", h_val, f"facebook:{h_val}", bool(brand), brand, canonical_url=can_url, clean_handle=h_val, tracking_params=tracking_params)

    # 4. WhatsApp Links
    m_wa = re.search(r"(?i)(?:https?://)?chat\.whatsapp\.com/([a-zA-Z0-9_-]{5,50})", raw)
    if m_wa:
        code = m_wa.group(1)
        return PlatformProfile(True, "whatsapp", code, f"whatsapp:{code}", False, None, canonical_url=f"https://chat.whatsapp.com/{code}", clean_handle=code, tracking_params=tracking_params)
    m_wame = re.search(r"(?i)(?:https?://)?(?:wa\.me|api\.whatsapp\.com/send\?phone=)(\+?[0-9]{8,15})", raw)
    if m_wame:
        ph = m_wame.group(1)
        return PlatformProfile(True, "whatsapp", ph, f"whatsapp:{ph}", False, None, canonical_url=f"https://wa.me/{ph}", clean_handle=ph, tracking_params=tracking_params)
    if re.search(r"(?i)(?:https?://)?(?:chat\.whatsapp\.com|wa\.me|api\.whatsapp\.com)/", raw):
        return PlatformProfile(True, "whatsapp", None, f"whatsapp:{raw}", False, None, canonical_url=raw, tracking_params=tracking_params)

    # 5. X / Twitter Profile
    m_x = re.search(r"(?i)(?:https?://)?(?:www\.)?(?:x\.com|twitter\.com)/@?([a-zA-Z0-9_.-]{2,50})$", raw)
    if m_x and m_x.group(1).lower() not in _RESERVED_HANDLES:
        h_val = m_x.group(1).lower().rstrip(".")
        brand = _check_impersonation(h_val, "x")
        can_url = f"https://x.com/{h_val}"
        return PlatformProfile(True, "x", h_val, f"x:{h_val}", bool(brand), brand, canonical_url=can_url, clean_handle=h_val, tracking_params=tracking_params)

    # 6. Prefixed handle e.g. "instagram:shop_ke"
    m_pref = re.match(r"(?i)^(instagram|tiktok|facebook|x|whatsapp):@?([a-zA-Z0-9_.-]{2,50})$", raw)
    if m_pref:
        plat, h_val = m_pref.group(1).lower(), m_pref.group(2).lower().rstrip(".")
        brand = _check_impersonation(h_val, plat)
        can_url = f"https://www.instagram.com/{h_val}" if plat == "instagram" else (f"https://www.tiktok.com/@{h_val}" if plat == "tiktok" else (f"https://www.facebook.com/{h_val}" if plat == "facebook" else (f"https://x.com/{h_val}" if plat == "x" else None)))
        return PlatformProfile(True, plat, h_val, f"{plat}:{h_val}", bool(brand), brand, canonical_url=can_url, clean_handle=h_val, tracking_params=tracking_params)

    # 7. Bare handle with platform hint or @handle
    if raw.startswith("@") and len(raw) >= 3:
        h_val = raw[1:].lower().rstrip(".")
        if h_val not in _RESERVED_HANDLES:
            plat = (platform_hint or "").lower()
            if plat in ("instagram", "tiktok", "facebook", "x", "twitter"):
                plat = "x" if plat == "twitter" else plat
                can_url = f"https://www.instagram.com/{h_val}" if plat == "instagram" else (f"https://www.tiktok.com/@{h_val}" if plat == "tiktok" else (f"https://www.facebook.com/{h_val}" if plat == "facebook" else f"https://x.com/{h_val}"))
                brand = _check_impersonation(h_val, plat)
                return PlatformProfile(True, plat, h_val, f"{plat}:{h_val}", bool(brand), brand, canonical_url=can_url, clean_handle=h_val, tracking_params=tracking_params)
            else:
                return PlatformProfile(True, "social", h_val, f"social:{h_val}", False, None, canonical_url=None, clean_handle=h_val, tracking_params=tracking_params)

    return PlatformProfile(False, "web", None, None, False, None, canonical_url=None, clean_handle=None, tracking_params=tracking_params)


def _check_impersonation(handle: str, platform: str) -> str | None:
    """Conservatively detect brand tokens/known aliases without substring false positives."""
    raw = (handle or "").strip().lower().lstrip("@")
    if not raw:
        return None
    safe_handles = {re.sub(r"[^a-z0-9]", "", h.lower()) for values in _KENYA_OFFICIAL_BRANDS.values() for h in values}
    compact = re.sub(r"[^a-z0-9]", "", raw)
    if compact in safe_handles:
        return None

    tokens = [t for t in re.split(r"[^a-z0-9]+", raw) if t]
    suspicious_suffixes = ("deals", "deal", "promo", "promos", "bonus", "jobs", "job", "care", "support", "official", "verify", "verification", "security", "help", "offers", "offer", "rewards", "refund", "claim", "accounts", "account", "kenya")
    for brand, legit_handles in _KENYA_OFFICIAL_BRANDS.items():
        aliases = {re.sub(r"[^a-z0-9]", "", brand)}
        aliases.update(re.sub(r"[^a-z0-9]", "", h.lower()) for h in legit_handles)
        # Only full tokens and known-brand-plus-suspicious-suffix combinations count.
        for token in tokens:
            if token in aliases:
                return _BRAND_DISPLAY_NAMES.get(brand, brand.capitalize())
            for alias in aliases:
                if token.startswith(alias) and token != alias:
                    suffix = token[len(alias):]
                    if any(suffix.startswith(s) for s in suspicious_suffixes):
                        return _BRAND_DISPLAY_NAMES.get(brand, brand.capitalize())
    return None


# ---------------------------------------------------------------------------
# Investigation Result Structure
# ---------------------------------------------------------------------------

@dataclass
class URLFinding:
    code: str
    plain_text: str
    why_it_matters: str
    strength: str  # strong, supporting, weak
    evidence_type: str = "observed_data"
    source_url: str | None = None


@dataclass
class URLCoverageCheck:
    id: str
    name: str
    status: str  # not_configured, not_checked, failed, checked_no_match, checked_match (or checked, not_found, could_not_check)
    detail: str
    blocking: bool = False
    source_url: str | None = None
    provider: str | None = None
    query: str | None = None
    results_retrieved: int = 0
    results_relevant: int = 0
    sources_inspected: int = 0
    retrieval_timestamp: str | None = None
    failure_reason: str | None = None


@dataclass
class URLSourceRef:
    id: str
    statement: str
    source_url: str | None = None
    reviewer: str = "Toroka System"
    last_verified_at: str | None = None
    relevance: str | None = None
    relevance_reason: str | None = None
    claim_signal: bool | None = None


@dataclass
class URLInvestigationResult:
    target_url: str
    normalized_url: str
    domain: str
    platform_profile: PlatformProfile
    risk_band: str  # high_risk, suspicious_verify_first, verified_official, no_known_threats_found, inconclusive
    summary: str
    findings: list[URLFinding] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    sources: list[URLSourceRef] = field(default_factory=list)
    coverage: list[URLCoverageCheck] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    next_steps: list[str] = field(default_factory=list)
    page_data: dict[str, Any] = field(default_factory=dict)
    steps_taken: list[dict[str, str]] = field(default_factory=list)
    ai_conversational_reply: str | None = None


def _dict_to_result(cached: dict[str, Any]) -> URLInvestigationResult:
    p_data = cached.get("platform_profile")
    if isinstance(p_data, dict):
        p_prof = PlatformProfile(**p_data)
    elif isinstance(p_data, PlatformProfile):
        p_prof = p_data
    else:
        p_prof = PlatformProfile(False, "web")

    findings = [
        URLFinding(**f) if isinstance(f, dict) else f
        for f in cached.get("findings", [])
    ]
    sources = [
        URLSourceRef(**s) if isinstance(s, dict) else s
        for s in cached.get("sources", [])
    ]
    coverage = [
        URLCoverageCheck(**c) if isinstance(c, dict) else c
        for c in cached.get("coverage", [])
    ]
    return URLInvestigationResult(
        target_url=cached.get("target_url", ""),
        normalized_url=cached.get("normalized_url", ""),
        domain=cached.get("domain", ""),
        platform_profile=p_prof,
        risk_band=cached.get("risk_band", "inconclusive"),
        summary=cached.get("summary", ""),
        findings=findings,
        contradictions=cached.get("contradictions", []),
        sources=sources,
        coverage=coverage,
        limitations=cached.get("limitations", []),
        next_steps=cached.get("next_steps", []),
        page_data=cached.get("page_data", {}),
        steps_taken=cached.get("steps_taken", []),
        ai_conversational_reply=cached.get("ai_conversational_reply"),
    )


# ---------------------------------------------------------------------------
# Central URL Investigation Engine
# ---------------------------------------------------------------------------

def _safe_log_host(url: str) -> str:
    """Return host-only logging value to avoid leaking tokens/query parameters."""
    try:
        return (urlsplit(url).hostname or "invalid-host")[:120]
    except ValueError:
        return "invalid-url"


def _sanitised_url_for_ai(url: str) -> str:
    """Remove userinfo, query and fragment before sending URLs to an external LLM."""
    try:
        p = urlsplit(url)
        if p.scheme not in {"http", "https"} or not p.hostname:
            return "[URL omitted: invalid or unsupported URL]"
        host = p.hostname.encode("idna").decode("ascii").lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{p.port}" if p.port and not ((p.scheme == "https" and p.port == 443) or (p.scheme == "http" and p.port == 80)) else ""
        path = p.path[:300]
        return f"{p.scheme}://{host}{port}{path}"
    except (ValueError, UnicodeError):
        return "[URL omitted: invalid or unsupported URL]"


def _sanitise_url_in_text(text: str) -> str:
    """Redact URL userinfo, query strings and fragments in context before external AI calls."""
    pattern = re.compile(r"(?i)(?:https?://|www\.)[^\s<>\"']+")
    def replace(match):
        raw = match.group(0)
        trailing = ""
        while raw and raw[-1] in ".,;:!?)]}":
            trailing = raw[-1] + trailing
            raw = raw[:-1]
        url = raw if raw.startswith("http") else "https://" + raw
        return _sanitised_url_for_ai(url) + trailing
    return pattern.sub(replace, text or "")

def _sanitised_url_for_display(url: str) -> str:
    """Return a display-safe URL without credentials, query tokens or fragments."""
    safe = _sanitised_url_for_ai(url)
    return safe

def _canonical_profile_url(url: str) -> str:
    """Drop tracking query parameters from supported profile URLs and canonicalise hosts."""
    profile = parse_platform_profile(url)
    if not profile.is_profile:
        return url
    handle = profile.handle
    if profile.platform == "instagram" and handle:
        return f"https://www.instagram.com/{handle}/"
    if profile.platform == "tiktok" and handle:
        return f"https://www.tiktok.com/@{handle}"
    if profile.platform == "facebook" and handle:
        return f"https://www.facebook.com/{handle}"
    if profile.platform == "x" and handle:
        return f"https://x.com/{handle}"
    if profile.platform == "whatsapp" and handle:
        if re.fullmatch(r"[A-Za-z0-9_-]{5,50}", handle):
            return f"https://chat.whatsapp.com/{handle}"
        if handle.startswith("+") or handle.isdigit():
            return f"https://wa.me/{handle.lstrip('+')}"
    return url


def _url_cache_key(norm_url: str, settings: Settings) -> str:
    """Cache evidence by canonical URL and available provider capabilities."""
    return (
        norm_url + "|tavily=" + str(bool(settings.tavily_api_key))
        + "|webrisk=" + str(bool(settings.webrisk_api_key))
        + "|fetch=" + str(bool(settings.enable_link_fetch))
    )

_cache_key = _url_cache_key


def _cache_payload(result: URLInvestigationResult) -> dict[str, Any]:
    """Cache public, target-scoped evidence only; never cache a contextual AI reply."""
    payload = asdict(result)
    payload["ai_conversational_reply"] = None
    return payload


def _synthesise_url_reply_for_request(
    result: URLInvestigationResult,
    settings: Settings,
    user_context: str,
    language: str,
) -> str | None:
    """Generate a fresh, request-scoped explanation from cached evidence without cross-user leakage."""
    if not (settings.gemini_api_key or settings.openai_api_key):
        return None
    evidence_summary = (
        f"URL: {result.normalized_url}\nDomain: {result.domain}\nRisk Band: {result.risk_band}\n"
        f"Summary: {result.summary}\nFindings: {[f.plain_text for f in result.findings]}\n"
        f"Contradictions: {result.contradictions}\n"
        f"Page Title: {result.page_data.get('title')}\n"
        f"Page Text Excerpt: {result.page_data.get('visible_text_excerpt', '')[:400]}\n"
        f"User Question/Context: {user_context}"
    )
    try:
        from .ai_agent import investigate_with_ai
        ai_data = investigate_with_ai(
            evidence_summary,
            language=language,
            settings=settings,
            public_sources=[asdict(source) for source in result.sources],
        )
        reply = ai_data.get("conversational_reply") if isinstance(ai_data, dict) else None
        return str(reply) if reply else None
    except Exception as exc:
        logger.debug("Cached URL response synthesis failed safely: %s", type(exc).__name__)
        return None


def investigate_single_url(
    target_url: str,
    db: Session,
    crypto: Crypto,
    settings: Settings,
    *,
    user_context: str = "",
    language: str = "en",
    skip_cache: bool = False,
) -> URLInvestigationResult:
    """Execute the full 8-step URL investigation pipeline."""
    cache = URLInvestigationCache.get_instance()
    norm_url = target_url.strip()
    if not norm_url.startswith(("http://", "https://")):
        norm_url = "https://" + norm_url
    norm_url = _canonical_profile_url(norm_url)
    cache_key = _url_cache_key(norm_url, settings)

    # Check cache
    if not skip_cache:
        cached = cache.get_url(cache_key) or cache.get_url(norm_url)
        if cached:
            result = _dict_to_result(cached)
            result.ai_conversational_reply = _synthesise_url_reply_for_request(result, settings, user_context, language)
            return result

    is_primary, waited_result = cache.start_or_wait(cache_key)
    if not is_primary and waited_result:
        result = _dict_to_result(waited_result)
        result.ai_conversational_reply = _synthesise_url_reply_for_request(result, settings, user_context, language)
        return result

    try:
        res = _execute_pipeline_steps(norm_url, db, crypto, settings, user_context=user_context, language=language)
        res.target_url = _sanitised_url_for_display(target_url.strip())
        res.normalized_url = _sanitised_url_for_display(norm_url)
        if res.page_data.get("final_url"):
            res.page_data["final_url"] = _sanitised_url_for_display(res.page_data["final_url"])
        if res.page_data.get("redirect_chain"):
            res.page_data["redirect_chain"] = [_sanitised_url_for_display(u) for u in res.page_data["redirect_chain"]]
        # Never expose query tokens or URL credentials through source, finding, or coverage links.
        for source in res.sources:
            if source.source_url:
                source.source_url = _sanitised_url_for_display(source.source_url)
        for finding in res.findings:
            if finding.source_url:
                finding.source_url = _sanitised_url_for_display(finding.source_url)
        for check in res.coverage:
            if check.source_url:
                check.source_url = _sanitised_url_for_display(check.source_url)
        cache_payload = _cache_payload(res)
        cache.put_url(cache_key, cache_payload, ttl_seconds=900.0)
        cache.put_url(norm_url, cache_payload, ttl_seconds=900.0)
        cache.complete_in_flight(cache_key, cache_payload)
        return res
    except Exception as exc:
        logger.error("URL investigation pipeline error for host=%s error=%s", _safe_log_host(norm_url), type(exc).__name__)
        fallback = _build_error_fallback(norm_url, type(exc).__name__, language)
        cache.complete_in_flight(cache_key, _cache_payload(fallback))
        return fallback


def _execute_pipeline_steps(
    url: str,
    db: Session,
    crypto: Crypto,
    settings: Settings,
    *,
    user_context: str = "",
    language: str = "en",
) -> URLInvestigationResult:
    t_start = time.monotonic()
    steps_taken: list[dict[str, str]] = []
    findings: list[URLFinding] = []
    contradictions: list[str] = []
    sources: list[URLSourceRef] = []
    coverage: list[URLCoverageCheck] = []
    limitations: list[str] = []
    next_steps: list[str] = []
    now_iso = datetime.now(timezone.utc).isoformat()

    # ---------------------------------------------------------
    # Step A: Parse and Normalise
    # ---------------------------------------------------------
    steps_taken.append({"name": "Normalising link and identifying platform", "status": "running"})
    parsed = nz.parse_url(url)
    if not parsed:
        domain = urlsplit(url).netloc.split(":")[0].lower()
    else:
        domain = parsed.registered_domain or parsed.host

    profile = parse_platform_profile(url)
    steps_taken[-1]["status"] = "done"

    # ---------------------------------------------------------
    # Step B: Check Existing Toroka Intelligence First
    # ---------------------------------------------------------
    steps_taken.append({"name": "Checking Toroka verified registry and reports", "status": "running"})
    toroka_match = None
    is_verified_official = False
    verified_name = None
    stale_registry_match: tuple[Any, str, str] | None = None

    # 1. Verified official registry. Match identity first, then evaluate review freshness.
    # An expired/unreviewed match is surfaced as stale context rather than silently dropped
    # or treated as current verification. A valid current record always takes precedence.
    registry_records = db.execute(
        select(m.VerifiedRecord).where(m.VerifiedRecord.status == "active")
    ).scalars().all()
    matching_records = []
    for v_rec in registry_records:
        v_handles = [str(h).lower() for h in (v_rec.handles or [])]
        domain_match = bool(parsed and host_matches_verified_record(parsed.host, v_rec))
        handle_match = bool(profile.identifier and profile.identifier.lower() in v_handles)
        if domain_match or handle_match:
            is_current, review_reason = verified_record_review_state(v_rec)
            if is_current:
                matching_records.append((v_rec, domain_match, handle_match))
            elif stale_registry_match is None:
                stale_registry_match = (v_rec, review_reason, "domain" if domain_match else "handle")

    if matching_records:
        v_rec, domain_match, handle_match = matching_records[0]
        is_verified_official = True
        verified_name = v_rec.name
        identity_kind = "Official verified record" if domain_match else "Official verified account"
        identity_detail = v_rec.name if domain_match else f"{v_rec.name} ({profile.identifier})"
        sources.append(URLSourceRef(
            id=f"toroka-verified-{v_rec.id}",
            statement=f"{identity_kind}: {identity_detail} ({v_rec.basis})",
            source_url=v_rec.source_url,
            reviewer=v_rec.reviewer or "Toroka Registry Moderator",
            last_verified_at=v_rec.last_verified_at,
        ))

    if not is_verified_official and stale_registry_match:
        stale_record, review_reason, match_kind = stale_registry_match
        stale_date = str(getattr(stale_record, "review_due", "") or "not recorded")
        stale_name = str(getattr(stale_record, "name", "the organisation or shop") or "the organisation or shop")
        stale_detail = (
            f"A prior Toroka registry entry matches this {match_kind}, but it is not treated as current verification because {review_reason}. "
            "This does not prove fraud; it means the previous verification cannot establish the identity today."
        )
        coverage.append(URLCoverageCheck(
            id="verified_registry_review",
            name="Previous registry record",
            status="not_checked",
            detail=f"{stale_name}: {review_reason}. Review due: {stale_date}. Not counted as current verification.",
            source_url=str(getattr(stale_record, "source_url", "") or "") or None,
        ))
        limitations.append(stale_detail)
        sources.append(URLSourceRef(
            id=f"toroka-stale-registry-{stale_record.id}",
            statement=f"Prior registry entry for {stale_name}; not current verification ({review_reason}).",
            source_url=str(getattr(stale_record, "source_url", "") or "") or None,
            reviewer="Toroka registry (review expired or incomplete)",
            last_verified_at=str(getattr(stale_record, "last_verified_at", "") or "") or None,
        ))

    # 2. Database Indicators (Published community reports)
    db_report_hits = 0
    candidate_keys = []
    social_roots = {"instagram.com", "tiktok.com", "facebook.com", "x.com", "twitter.com", "threads.net"}
    if not (profile.is_profile or domain in social_roots):
        candidate_keys.append(("domain", domain))
    if profile.identifier:
        candidate_keys.append(("handle", profile.identifier))

    for k_type, k_val in candidate_keys:
        h_digest = crypto.lookup(k_type, k_val)
        row = db.execute(
            select(m.Indicator, m.Subject)
            .join(m.Subject, m.Subject.id == m.Indicator.subject_id)
            .where(
                m.Subject.subject_type == k_type,
                m.Subject.lookup_hmac == h_digest,
                m.Indicator.status == "published",
            )
        ).first()
        if row:
            ind, subj = row
            db_report_hits += (ind.independent_reports or 1)
            toroka_match = {
                "identifier": subj.display_masked,
                "reports": ind.independent_reports,
                "status": ind.status,
                "basis": ind.basis,
            }
            sources.append(URLSourceRef(
                id=f"toroka-indicator-{ind.id}",
                statement=f"Published community indicator for {subj.display_masked}: {ind.independent_reports} independent report(s), status {ind.status}, basis {ind.basis}.",
                source_url=None,
                reviewer="Toroka Community Review",
                last_verified_at=ind.last_reported,
            ))

    coverage.append(URLCoverageCheck(
        id="toroka_intel",
        name="Toroka Internal Intelligence",
        status="checked",
        detail="Queried official verified registry and moderated scam incident database.",
    ))

    # 3. Documented Threat & Campaign Intelligence (Historical threat associations, Scam Archive, MalwareTips)
    from .campaign_intelligence import lookup_campaign
    campaign_hit = lookup_campaign(domain, url)
    if campaign_hit:
        finding_code = "RECRUITMENT_DOMAIN_PHISHING_HISTORY" if campaign_hit.campaign_type == "recruitment_phishing" else "DOCUMENTED_CAMPAIGN_MATCH"
        findings.append(URLFinding(
            code=finding_code,
            plain_text=campaign_hit.headline,
            why_it_matters="; ".join(campaign_hit.detailed_findings),
            strength="strong",
            evidence_type="threat_intelligence",
            source_url=campaign_hit.source_url,
        ))
        sources.append(URLSourceRef(
            id=f"campaign-{campaign_hit.campaign_id}",
            statement=f"{campaign_hit.source_name} ({campaign_hit.report_date}): {campaign_hit.headline}. " + " ".join(campaign_hit.detailed_findings),
            source_url=campaign_hit.source_url,
            reviewer=f"{campaign_hit.source_name} (Documented Threat Record)",
            last_verified_at=campaign_hit.report_date,
        ))
        for sf in campaign_hit.scanner_findings:
            findings.append(URLFinding(
                code="DOMAIN_REPUTATION_HIGH_RISK",
                plain_text=f"{sf.name}: {sf.rating}",
                why_it_matters=sf.detail,
                strength="supporting",
                evidence_type="threat_intelligence",
                source_url=sf.source_url,
            ))
            sources.append(URLSourceRef(
                id=f"scanner-{len(sources) + 1}",
                statement=f"{sf.name} ({sf.scan_date}): {sf.rating}. {sf.detail}",
                source_url=sf.source_url,
                reviewer=sf.name,
                last_verified_at=sf.scan_date,
            ))
        for rc in campaign_hit.reputation_contradictions:
            contradictions.append(rc)
        if campaign_hit.path_correlation_caveat:
            limitations.append(campaign_hit.path_correlation_caveat)
        coverage.append(URLCoverageCheck(
            id="threat_archive",
            name="Scam Archive & Campaign Intelligence",
            status="checked_match",
            detail=f"Matched campaign: {campaign_hit.headline} reported by {campaign_hit.source_name} ({campaign_hit.report_date}).",
            source_url=campaign_hit.source_url,
        ))

    steps_taken[-1]["status"] = "done"

    # ---------------------------------------------------------
    # Step C: Query Threat Feeds (OpenPhish, Blackbook, URLhaus, WebRisk)
    # ---------------------------------------------------------
    steps_taken.append({"name": "Querying global threat intelligence feeds", "status": "running"})
    feed_mgr = ThreatFeedManager.get_instance()
    feed_mgr.refresh_feeds(force=False)
    threat_hit = feed_mgr.check(url, domain)

    if threat_hit:
        findings.append(URLFinding(
            code="THREAT_FEED_MATCH",
            plain_text=f"Flagged in {threat_hit['feed']}",
            why_it_matters=threat_hit["detail"],
            strength="strong",
            evidence_type="threat_intelligence",
            source_url=threat_hit["source_url"],
        ))
        sources.append(URLSourceRef(
            id="threat-feed-hit",
            statement=threat_hit["detail"],
            source_url=threat_hit["source_url"],
            reviewer="Global Open Source Threat Intel",
            last_verified_at=now_iso,
        ))

    # Record Threat Feed Coverage
    feed_statuses = [f"{st.name}: {st.http_status or st.error or 'ok'} ({st.item_count} entries)" for st in feed_mgr.statuses.values()]
    coverage.append(URLCoverageCheck(
        id="threat_feeds",
        name="Global Threat Feeds (OpenPhish, Blackbook, URLhaus)",
        status="checked" if any(st.available for st in feed_mgr.statuses.values()) else "could_not_check",
        detail="; ".join(feed_statuses),
    ))

    # Google Web Risk / Safe Browsing (Supports both Commercial Web Risk and 100% Free Safe Browsing)
    if settings.webrisk_api_key:
        checked_google = False
        try:
            wr_url = f"https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE&uri={quote_plus(url)}"
            with httpx.Client(timeout=4.0) as client:
                wr_resp = client.get(wr_url, headers={"x-goog-api-key": settings.webrisk_api_key})
                if wr_resp.status_code == 200:
                    wr_data = wr_resp.json()
                    if wr_data.get("threat"):
                        threat_types = wr_data["threat"].get("threatTypes", [])
                        findings.append(URLFinding(
                            code="WEBRISK_THREAT_DETECTED",
                            plain_text="Google Web Risk Flagged Unsafe Resource",
                            why_it_matters=f"Google Web Risk classified this link as {', '.join(threat_types)}.",
                            strength="strong",
                            evidence_type="threat_intelligence",
                        ))
                    coverage.append(URLCoverageCheck(
                        id="google_webrisk",
                        name="Google Web Risk API",
                        status="checked",
                        detail="Checked against Google Web Risk lists.",
                    ))
                    checked_google = True
                elif wr_resp.status_code == 403:
                    # Fallback to 100% Free Google Safe Browsing API v4 (No billing required)
                    sb_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
                    sb_body = {
                        "client": {"clientId": "toroka-safety", "clientVersion": "1.0"},
                        "threatInfo": {
                            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                            "platformTypes": ["ANY_PLATFORM"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [{"url": url}],
                        },
                    }
                    sb_resp = client.post(sb_url, json=sb_body, headers={"x-goog-api-key": settings.webrisk_api_key})
                    if sb_resp.status_code == 200:
                        sb_data = sb_resp.json()
                        matches = sb_data.get("matches", [])
                        if matches:
                            threat_types = list({m.get("threatType", "THREAT") for m in matches})
                            findings.append(URLFinding(
                                code="SAFEBROWSING_THREAT_DETECTED",
                                plain_text="Google Safe Browsing Flagged Unsafe Link",
                                why_it_matters=f"Google Safe Browsing classified this link as {', '.join(threat_types)}.",
                                strength="strong",
                                evidence_type="threat_intelligence",
                            ))
                        coverage.append(URLCoverageCheck(
                            id="google_webrisk",
                            name="Google Safe Browsing API (Free)",
                            status="checked",
                            detail="Checked against Google Safe Browsing list (no billing required).",
                        ))
                        checked_google = True
        except Exception as e:
            pass

        if not checked_google:
            coverage.append(URLCoverageCheck(
                id="google_webrisk",
                name="Google Security API",
                status="could_not_check",
                detail="Google Web Risk requires Cloud billing; or enable Free Safe Browsing API in Google Cloud Console.",
            ))
    else:
        coverage.append(URLCoverageCheck(
            id="google_webrisk",
            name="Google Web Risk / Safe Browsing",
            status="not_checked",
            detail="Google threat checking not configured. Toroka uses OpenPhish, Blackbook & local intelligence.",
        ))
        limitations.append("Google Web Risk feed is not configured in this environment.")
    steps_taken[-1]["status"] = "done"

    # ---------------------------------------------------------
    # Step D: Safe Web Fetch (SSRF-shielded, 512KB cap, no JS execution)
    # ---------------------------------------------------------
    steps_taken.append({"name": "Fetching safe page preview (SSRF-protected)", "status": "running"})
    page_data: dict[str, Any] = {}
    
    # Fetch only when explicitly enabled in the environment. The SSRF-hardened
    # fetcher must still be deployed behind egress restrictions. Social platforms
    # may block direct automated inspection, so do not imply their profiles were read.
    is_social = profile.is_profile and profile.platform in {"instagram", "tiktok", "facebook", "whatsapp", "x"}
    should_fetch = bool(settings.enable_link_fetch) and (not is_social or profile.platform == "web")

    if should_fetch:
        fetch_res: SafePageContent = safe_fetch_page(
            url,
            max_hops=5,
            timeout=4.0,
            max_bytes=524288,
            total_budget=8.0,
        )
        page_data = {
            "status": fetch_res.status.value,
            "final_url": fetch_res.final_url,
            "status_code": fetch_res.status_code,
            "title": fetch_res.title,
            "description": fetch_res.meta_description,
            "visible_text_excerpt": fetch_res.visible_text[:800],
            "phones": fetch_res.phones,
            "emails": fetch_res.emails,
            "whatsapp_links": fetch_res.whatsapp_links,
            "payment_identifiers": fetch_res.payment_identifiers,
            "has_login_form": fetch_res.has_login_form,
            "has_password_field": fetch_res.has_password_field,
            "security_warnings": fetch_res.security_warnings,
            "redirect_chain": fetch_res.redirect_chain,
            "reason": fetch_res.reason,
            "fetch_time_ms": round(fetch_res.fetch_time_ms, 1),
        }

        cov_status = "checked" if fetch_res.status == CS.CHECKED else ("could_not_check" if fetch_res.status == CS.COULD_NOT_CHECK else "not_checked")
        coverage.append(URLCoverageCheck(
            id="safe_web_fetch",
            name="Safe Web Content Inspection",
            status=cov_status,
            detail=fetch_res.reason,
        ))

        # A security control blocking a destination is not evidence that the target is a scam.
        if fetch_res.reason and (fetch_res.reason.startswith("blocked:") or "validation failed" in fetch_res.reason.lower() or "unusual port" in fetch_res.reason.lower() or "internal hostname" in fetch_res.reason.lower() or "binary download blocked" in fetch_res.reason.lower()):
            limitations.append("Direct page inspection was blocked by Toroka's safe-fetch policy. This is a security limitation, not evidence that the destination is fraudulent.")

        # A login form is normal on many legitimate websites. Treat it as context, not proof.
        if fetch_res.has_password_field:
            findings.append(URLFinding(
                code="LOGIN_FORM_PRESENT",
                plain_text="A login or password field is present",
                why_it_matters="Login forms are common on legitimate services and are not proof of phishing. Verify the exact domain and look for independent threat indicators or impersonation evidence.",
                strength="weak",
                evidence_type="observed_data",
            ))

        # Check for multiple redirect hops or shortener masking
        if len(fetch_res.redirect_chain) > 2:
            findings.append(URLFinding(
                code="MULTIPLE_REDIRECT_CHAIN",
                plain_text=f"Redirected through {len(fetch_res.redirect_chain) - 1} hops",
                why_it_matters=f"The link redirects across multiple destinations ({' -> '.join(_sanitised_url_for_display(u) for u in fetch_res.redirect_chain[:3])}), which can make the final destination less obvious. Redirects are not proof of fraud by themselves.",
                strength="supporting",
                evidence_type="observed_data",
            ))

        for warn in fetch_res.security_warnings:
            findings.append(URLFinding(
                code="CONTENT_SECURITY_ALERT",
                plain_text=warn,
                why_it_matters="Observed phrasing or file type in page source matches high-risk scam patterns.",
                strength="supporting",
                evidence_type="observed_data",
            ))
    else:
        if is_social:
            coverage.append(URLCoverageCheck(
                id="safe_web_fetch",
                name="Direct Social Profile Inspection",
                status="not_checked",
                detail=(
                    f"Toroka did not directly inspect the {profile.platform.capitalize()} profile because the "
                    "platform blocks or restricts automated public fetching. Search leads and local records do not "
                    "substitute for a full profile inspection."
                ),
            ))
            limitations.append(f"Toroka did not directly inspect the {profile.platform.capitalize()} profile.")
        elif not settings.enable_link_fetch:
            coverage.append(URLCoverageCheck(
                id="safe_web_fetch",
                name="Safe Web Content Inspection",
                status="not_checked",
                detail="Direct page fetching is disabled in this environment. Threat feeds, existing records and public search may still be checked.",
            ))
            limitations.append("Direct website content inspection is not enabled.")
        else:
            coverage.append(URLCoverageCheck(
                id="safe_web_fetch",
                name="Safe Web Content Inspection",
                status="not_checked",
                detail=f"Direct fetch bypassed for platform-specific {profile.platform.capitalize()} profile; the platform could restrict access.",
            ))
            limitations.append(f"The {profile.platform.capitalize()} profile was not directly fetched.")
    steps_taken[-1]["status"] = "done"

    # ---------------------------------------------------------
    # Step E: Live Web Search (Tavily)
    # ---------------------------------------------------------
    steps_taken.append({"name": "Searching public records and reputation", "status": "running"})
    tavily_search_result = None
    manual_search_link = None
    query_target = f'"{domain}" reviews complaints scam Kenya'
    if profile.is_profile and profile.handle:
        query_target = f'"{profile.handle}" {profile.platform} reviews scam Kenya'

    manual_search_link = manual_search_url(query_target)
    retrieved_results: list[dict[str, str]] = []

    if settings.tavily_api_key:
        tavily_res = public_search(query_target, settings.tavily_api_key, max_results=5)
        tavily_search_result = tavily_res
        retrieved_results = tavily_res.get("results", [])

        ranked = filter_public_search_results(
            retrieved_results,
            identifier=profile.handle if profile.handle else domain,
            kind="handle" if profile.handle else "domain",
            platform=profile.platform if profile.handle else None,
            target_url=url,
        )

        for item in ranked["relevant_results"]:
            title = str(item.get("title") or item.get("url") or "Public search result")[:180]
            snippet = str(item.get("snippet", "") or "")[:300]
            claim_signal = bool(item.get("claim_signal"))
            if item.get("relevance") == "entity_mention" and not claim_signal:
                statement = (
                    f"Public search indexed a result that mentions @{profile.handle}: {title}. "
                    "This is an entity reference, not a complaint or proof of wrongdoing. " + snippet
                )
            elif claim_signal:
                statement = (
                    f"Unverified public-search lead mentioning the target and claim-related wording: {title}. "
                    "The source must be inspected before treating the claim as evidence. " + snippet
                )
            else:
                statement = f"Public-search lead related to the exact target: {title}. {snippet}"
            sources.append(URLSourceRef(
                id=f"tavily-lead-{len(sources) + 1}",
                statement=statement,
                source_url=item.get("url"),
                reviewer="Tavily Web Search (unverified, relevance-filtered lead)",
                last_verified_at=now_iso,
                relevance=str(item.get("relevance") or "unknown"),
                relevance_reason=str(item.get("relevance_reason") or ""),
                claim_signal=claim_signal,
            ))

        # Determine authoritative search coverage status
        if tavily_res.get("status") == "failed":
            cov_status = "failed"
            cov_detail = tavily_res.get("detail", "The public search service could not be reached.")
            limitations.append("Public search was unavailable during this check.")
        elif ranked["relevant_count"]:
            cov_status = "checked_match"
            cov_detail = (
                f"Search retrieved {ranked['raw_result_count']} result(s): "
                f"{ranked['relevant_count']} relevant to the exact target, "
                f"{ranked['background_count']} general background result(s), and "
                f"{ranked['irrelevant_count']} unrelated result(s) excluded. "
                "Relevant results are leads; an exact mention is not proof of fraud."
            )
        else:
            cov_status = "checked_no_match"
            if profile.is_profile:
                cov_detail = (
                    f"Search retrieved {ranked['raw_result_count']} result(s), but none could be reliably tied to "
                    f"the exact target. {ranked['background_count']} general background result(s) and "
                    f"{ranked['irrelevant_count']} unrelated result(s) were excluded. "
                    f"No independent reports matching @{profile.handle} on {profile.platform.capitalize()} were identified in these results; this is not proof of safety."
                )
            else:
                cov_detail = (
                    f"Search retrieved {ranked['raw_result_count']} result(s), but none could be reliably tied to "
                    f"the exact target. {ranked['background_count']} general background result(s) and "
                    f"{ranked['irrelevant_count']} unrelated result(s) were excluded. "
                    f"No relevant independent reports or complaints matching {domain} were identified in these results."
                )

        coverage.append(URLCoverageCheck(
            id="tavily_search",
            name="Tavily Live Web Search",
            status=cov_status,
            detail=cov_detail,
            source_url=manual_search_link,
            provider="Tavily",
            query=query_target,
            results_retrieved=ranked["raw_result_count"],
            results_relevant=ranked["relevant_count"],
            sources_inspected=0,
            retrieval_timestamp=tavily_res.get("checked_at") or now_iso,
            failure_reason=tavily_res.get("failure_reason"),
        ))
    else:
        coverage.append(URLCoverageCheck(
            id="tavily_search",
            name="Tavily Live Web Search",
            status="not_configured",
            detail="Live search not run because TAVILY_API_KEY is not configured.",
            source_url=manual_search_link,
            provider="Tavily",
            query=query_target,
            results_retrieved=0,
            results_relevant=0,
            sources_inspected=0,
            retrieval_timestamp=now_iso,
        ))
        limitations.append("Tavily live search is not configured. 1-click manual search link provided.")
    steps_taken[-1]["status"] = "done"

    # ---------------------------------------------------------
    # Step F & G: Platform-Specific Profile Inspection & Impersonation
    # ---------------------------------------------------------
    steps_taken.append({"name": "Verifying platform identity and impersonation signals", "status": "running"})
    if profile.is_official_impersonation_risk and not is_verified_official:
        contradictions.append(
            f"The handle @{profile.handle} on {profile.platform.capitalize()} resembles the {profile.impersonated_brand or 'claimed organisation'} identity, but it did not match a currently reviewed official handle. This is a reason to verify the account, not proof by itself."
        )
        findings.append(URLFinding(
            code="POSSIBLE_BRAND_IMPERSONATION",
            plain_text=f"Possible {profile.impersonated_brand} impersonation pattern",
            why_it_matters="The handle combines a recognised brand term with a non-matching account name. Check the exact account against contact details obtained independently from the organisation.",
            strength="supporting",
            evidence_type="identity_contradiction",
        ))

    if toroka_match:
        findings.append(URLFinding(
            code="REPORTED_COMMUNITY_INCIDENT",
            plain_text=f"Published Toroka community indicator ({toroka_match['reports']} reports)",
            why_it_matters="A published community indicator matches this exact identifier. Review its evidence and basis; a report count alone does not prove every associated offer is fraudulent.",
            strength="supporting",
            evidence_type="community_reports",
        ))

    # Domain / Brand Contradiction (for domains, not social platforms)
    if not profile.is_profile and not is_verified_official and not _matches_domain_claimed_by_official_registry(parsed.host if parsed else domain):
        host_labels = [label for label in (parsed.host.lower().split(".") if parsed else domain.lower().split(".")) if label]
        suspicious_brand_suffixes = ("deals", "deal", "jobs", "job", "offers", "offer", "bonus", "promo", "promos", "support", "care", "verify", "secure", "login", "claim", "shop", "line", "reactivate", "reactivation", "account", "update", "reset", "reward", "rewards", "customer", "help", "gift", "free", "airtime", "prize", "win", "winner")
        for brand, official_handles in _KENYA_OFFICIAL_BRANDS.items():
            aliases = {re.sub(r"[^a-z0-9]", "", brand)}
            aliases.update(re.sub(r"[^a-z0-9]", "", h.lower()) for h in official_handles)
            matched_alias = None
            for label in host_labels:
                compact_label = re.sub(r"[^a-z0-9]", "", label)
                for alias in sorted(aliases, key=len, reverse=True):
                    if compact_label == alias:
                        matched_alias = alias
                        break
                    if compact_label.startswith(alias):
                        suffix = compact_label[len(alias):]
                        if any(suffix.startswith(term) for term in suspicious_brand_suffixes):
                            matched_alias = alias
                            break
                    label_tokens = [re.sub(r"[^a-z0-9]", "", part) for part in re.split(r"[^a-z0-9]+", label.lower()) if part]
                    try:
                        alias_index = label_tokens.index(alias)
                    except ValueError:
                        alias_index = -1
                    if alias_index >= 0 and any(tok in suspicious_brand_suffixes for tok in label_tokens[alias_index + 1:]):
                        matched_alias = alias
                        break
                if matched_alias:
                    break
            if matched_alias:
                contradictions.append(
                    f"The hostname appears to combine a recognised { _BRAND_DISPLAY_NAMES.get(brand, brand.capitalize()) } brand term with an unreviewed domain. This warrants verification but is not proof of impersonation on its own."
                )
                findings.append(URLFinding(
                    code="DOMAIN_BRAND_MISMATCH",
                    plain_text=f"Possible { _BRAND_DISPLAY_NAMES.get(brand, brand.capitalize()) } impersonation domain",
                    why_it_matters="The hostname contains a recognised brand term but did not match the source registry's exact official-domain list. Verify the address independently before entering credentials or sending money.",
                    strength="supporting",
                    evidence_type="identity_contradiction",
                ))
                break

    # Adapt coverage strictly for social shop investigations
    if profile.is_profile:
        search_cov = next((c for c in coverage if c.id == "tavily_search"), None)
        social_coverage = [
            URLCoverageCheck(
                id="profile_identity",
                name="Platform Profile Identity",
                status="checked_match",
                detail=f"Target account @{profile.handle} on {profile.platform.capitalize()} ({profile.canonical_url or url}). Unnecessary tracking parameters removed.",
                provider=profile.platform.capitalize(),
                query=f"@{profile.handle}",
                results_retrieved=1,
                results_relevant=1,
                sources_inspected=1,
                retrieval_timestamp=now_iso,
            ),
            URLCoverageCheck(
                id="toroka_intel",
                name="Toroka Records & Verified Registry",
                status="checked_match" if toroka_match or is_verified_official else "checked_no_match",
                detail=f"Moderated incident records match {profile.identifier} ({toroka_match['reports']} report(s))." if toroka_match else (f"Matches active verified record for {verified_name}." if is_verified_official else f"No verified registry records or moderated scam reports on file for {profile.identifier}."),
                provider="Toroka Incident Database",
                query=profile.identifier,
                results_retrieved=db_report_hits,
                results_relevant=db_report_hits,
                sources_inspected=1,
                retrieval_timestamp=now_iso,
            ),
        ]
        if search_cov:
            social_coverage.append(search_cov)
        social_coverage.extend([
            URLCoverageCheck(
                id="business_links",
                name="Public Business Website & Official Links",
                status="not_checked",
                detail="No external business domain or official website was provided for this profile.",
                provider="Web Link Audit",
            ),
            URLCoverageCheck(
                id="safe_web_fetch",
                name="Direct Profile Inspection",
                status="not_checked",
                detail=(
                    f"Toroka did not directly inspect the {profile.platform.capitalize()} profile because the "
                    "platform blocks or restricts automated public fetching. Search leads and local records do not "
                    "substitute for inspecting the live storefront, products, or reviews."
                ),
                provider=f"{profile.platform.capitalize()} Web",
                failure_reason="Platform access policy / authentication required",
            ),
            URLCoverageCheck(
                id="payment_evidence",
                name="Payment Recipient & Delivery Terms",
                status="not_checked",
                detail="No M-PESA Till/Paybill number, recipient name, or delivery terms were submitted for verification.",
                provider="Transaction Evidence",
            ),
        ])
        coverage = social_coverage

    steps_taken[-1]["status"] = "done"

    # ---------------------------------------------------------
    # Step H: Deterministic Risk Synthesis
    # ---------------------------------------------------------
    steps_taken.append({"name": "Synthesising evidence-based safety assessment", "status": "running"})

    authoritative_threat_codes = {
        "THREAT_FEED_MATCH",
        "WEBRISK_THREAT_DETECTED",
        "SAFEBROWSING_THREAT_DETECTED",
        "DOCUMENTED_CAMPAIGN_MATCH",
        "RECRUITMENT_DOMAIN_PHISHING_HISTORY",
    }
    has_verified_community_threat = bool(toroka_match and toroka_match.get("basis") == "verified_by_source")
    has_authoritative_threat = any(f.code in authoritative_threat_codes for f in findings) or has_verified_community_threat
    has_supporting_threat = any(f.strength in {"supporting", "strong"} for f in findings) or bool(toroka_match)
    page_fetch_checked = any(c.id == "safe_web_fetch" and c.status == "checked" for c in coverage)
    search_checked = any(c.id == "tavily_search" and c.status in {"checked", "checked_match", "not_found"} for c in coverage)
    feed_checked = any(c.id == "threat_feeds" and c.status == "checked" for c in coverage)
    known_check_completed = page_fetch_checked or search_checked or feed_checked or bool(threat_hit) or bool(campaign_hit)

    if profile.is_profile:
        if has_authoritative_threat:
            risk_band = "high_risk"
            lead = next((f for f in findings if f.code in authoritative_threat_codes), None)
            if lead:
                summary = f"High risk: a confirmed threat-intelligence source flagged this account. {lead.why_it_matters}"
            else:
                summary = f"High risk: reviewed source-backed community reports flag @{profile.handle} on {profile.platform.capitalize()}."
            next_steps = [
                f"Do not send money or share personal details with @{profile.handle}.",
                "Check the verified incident reports and indicators below.",
                "Report this account if you have experienced fraud.",
            ]
        elif has_supporting_threat:
            risk_band = "suspicious_verify_first"
            summary = f"Caution: suspicious signals or lookalike indicators detected for @{profile.handle} on {profile.platform.capitalize()}. Verify independently before transacting."
            next_steps = [
                "Confirm the seller's identity through independent channels before making payments.",
                "Verify whether an official business Till or Paybill is registered in the same business name.",
                "Do not pay full amount upfront without buyer protection or inspectable delivery terms.",
            ]
        elif is_verified_official:
            risk_band = "verified_official"
            summary = f"The account @{profile.handle} on {profile.platform.capitalize()} matches a current human-reviewed verified record for {verified_name}."
            next_steps = [
                f"This account identity is verified for {verified_name}.",
                "Always verify payment recipients and never disclose your M-PESA PIN or OTP.",
            ]
        else:
            # Evidence-backed assessment: unfamiliarity, lack of storefront, lack of Till,
            # or an inaccessible profile cannot be escalated to fraud without evidence.
            risk_band = "inconclusive"
            summary = (
                f"The {profile.platform.capitalize()} profile @{profile.handle or 'unknown'} was identified, "
                "but direct profile inspection was unavailable and no strong, entity-specific threat evidence was found. "
                "This is not a finding that the account is safe or fraudulent."
            )
            limitations.append(f"Direct inspection of the @{profile.handle} {profile.platform.capitalize()} profile was unavailable due to platform restrictions.")
            limitations.append("Public search returned no verified reports or complaints clearly tied to this exact account.")
            next_steps = [
                "Share the specific product post, conversation, or payment request for a more targeted assessment.",
                "Verify the seller and payment recipient through independently obtained contact details before paying.",
                "Keep the advertised price, delivery terms, refund policy, and any payment request in writing.",
                "Never share your M-PESA PIN, bank password, or one-time password (OTP).",
            ]
    elif has_authoritative_threat:
        risk_band = "high_risk"
        lead = next((f for f in findings if f.code in authoritative_threat_codes), None)
        if campaign_hit and campaign_hit.campaign_type == "recruitment_phishing":
            summary = (
                f"High risk: domain linked to a documented overseas recruitment-phishing campaign. "
                f"{campaign_hit.detailed_findings[0]}"
            )
            next_steps = [
                "Do not enter your Gmail address, password, M-PESA PIN, or OTP on this website.",
                "Never pay application, registration, processing, or medical fees to the advertiser.",
                "Verify the recruitment agency's name and foreign employment licence via the State Department for Diaspora Affairs (diaspora.go.ke/verify).",
                "US temporary employment requires an authorized employer to file an approved petition with USCIS (uscis.gov) before a visa can be issued; a Form Four certificate alone does not confer work authorization.",
                "If you have already entered your Gmail password on this website, change it immediately in your Google Account Security settings, sign out of all active sessions, and turn on 2-Step Verification.",
            ]
        elif campaign_hit and campaign_hit.campaign_type == "brand_impersonation":
            summary = (
                f"High risk: domain linked to a documented brand impersonation campaign. "
                f"{campaign_hit.detailed_findings[0]}"
            )
            next_steps = list(campaign_hit.verification_guidance) + list(campaign_hit.credential_recovery_advice)
        elif lead:
            summary = f"High risk: a configured threat-intelligence source flagged this exact URL or domain. {lead.why_it_matters}"
            next_steps = [
                "Do not enter credentials, PINs, OTPs or payment details on this URL.",
                "If you already entered credentials, change them using the official website or app and secure the affected account.",
                "Preserve the message and report the suspicious link through the relevant service provider if needed.",
            ]
        else:
            summary = "High risk: a reviewed source-backed community indicator matches this exact identifier. Check the source and incident scope below."
            next_steps = [
                "Do not enter credentials, PINs, OTPs or payment details on this URL.",
                "If you already entered credentials, change them using the official website or app and secure the affected account.",
                "Preserve the message and report the suspicious link through the relevant service provider if needed.",
            ]
    elif has_supporting_threat:
        risk_band = "suspicious_verify_first"
        summary = "Toroka found an indicator that warrants verification, but the available evidence does not by itself confirm fraud. Review the specific findings and sources below."
        next_steps = [
            "Confirm the exact domain or account independently before entering sensitive information or sending money.",
            "Check the intended recipient, transaction terms and available buyer protection; payment in advance alone is not proof of fraud.",
            "If the link claims to represent an organisation, contact it through details obtained independently of the message.",
        ]
    elif is_verified_official:
        risk_band = "verified_official"
        summary = f"The exact site identity matches a current, human-reviewed record for {verified_name or domain}. This does not verify every offer or message on the site."
        next_steps = [
            f"The website identity matches a reviewed record for '{verified_name or domain}'.",
            "Verify the specific offer, requested action and payment recipient separately.",
            "Never share your PIN, password or OTP, even if a page appears official.",
        ]
    elif known_check_completed:
        risk_band = "no_known_threats_found"
        summary = "No known threat indicator was found by the checks that completed. This is not a guarantee that the site or offer is legitimate."
        next_steps = [
            "Review the checks and source links listed below.",
            "Verify the seller and payment recipient independently before making a consequential payment.",
            "Avoid sharing passwords, PINs, OTPs or unnecessary identity details.",
        ]
    else:
        risk_band = "inconclusive"
        summary = "Toroka could not complete enough independent checks to reach a reliable conclusion."
        next_steps = [
            "Do not interpret missing checks or missing reports as proof of safety or fraud.",
            "Try again when the relevant search or reputation services are available, or provide additional context.",
            "Verify the identity and payment recipient independently before sending money or credentials.",
        ]

    # Contextual AI Synthesis via Gemini (Grounded explanation)
    ai_reply = None
    if settings.gemini_api_key or settings.openai_api_key:
        try:
            from .ai_agent import investigate_with_ai
            evidence_summary = (
                f"URL: {_sanitised_url_for_ai(url)}\nDomain: {domain}\nRisk Band: {risk_band}\n"
                f"Findings: {[f.plain_text for f in findings]}\n"
                f"Contradictions: {contradictions}\n"
                f"Page Title: {page_data.get('title')}\n"
                f"Page Text Excerpt: {page_data.get('visible_text_excerpt', '')[:400]}\n"
                f"User Question/Context: {_sanitise_url_in_text(user_context)}"
            )
            ai_data = investigate_with_ai(
                evidence_summary,
                language=language,
                settings=settings,
                public_sources=[asdict(s) for s in sources],
            )
            if ai_data and ai_data.get("conversational_reply"):
                ai_reply = ai_data["conversational_reply"]
        except Exception as e:
            logger.debug("AI synthesis failed safely: %s", e)

    steps_taken[-1]["status"] = "done"

    return URLInvestigationResult(
        target_url=url,
        normalized_url=url,
        domain=domain,
        platform_profile=profile,
        risk_band=risk_band,
        summary=summary,
        findings=findings,
        contradictions=contradictions,
        sources=sources,
        coverage=coverage,
        limitations=limitations,
        next_steps=next_steps,
        page_data=page_data,
        steps_taken=steps_taken,
        ai_conversational_reply=ai_reply,
    )


def _build_error_fallback(url: str, err_msg: str, language: str) -> URLInvestigationResult:
    is_sw = language == "sw"
    return URLInvestigationResult(
        target_url=_sanitised_url_for_display(url),
        normalized_url=_sanitised_url_for_display(url),
        domain=_safe_log_host(url),
        platform_profile=PlatformProfile(False, "web"),
        risk_band="inconclusive",
        summary="Uchunguzi haukukamilika kutokana na hitilafu ya mtandao." if is_sw else "Investigation could not complete due to a network or resolution issue.",
        limitations=["A required check failed. No verdict was inferred from this failure."],
        next_steps=[
            "Thibitisha anwani hii kupitia vyanzo rasmi kabla ya kuingiza taarifa zozote." if is_sw else "Verify this link directly through official channels before entering any sensitive details."
        ],
        steps_taken=[{"name": "Investigating link", "status": "failed"}],
    )
