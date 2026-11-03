"""Historical urlscan.io search adapter.

This adapter searches previously collected scans only. It does not submit a user's
URL to a third party, avoiding accidental disclosure of private query parameters,
invite links, tracking tokens or private pages. Search results are historical
observations and must not be treated as a current, definitive verdict.
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

import httpx

URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"


def normalize_domain(value: str) -> str | None:
    raw = str(value or "").strip()
    if not raw or len(raw) > 255 or any(ch in raw for ch in "@?#"):
        return None
    try:
        host = urlsplit(raw if "://" in raw else "https://" + raw).hostname
        if not host:
            return None
        host = host.encode("idna").decode("ascii").lower().rstrip(".")
        if len(host) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", host):
            return None
        return host
    except Exception:
        return None


def _host_matches(candidate: str, requested: str) -> bool:
    return candidate == requested or candidate.endswith("." + requested)


def search_historical_domain(
    api_key: str,
    domain: str,
    *,
    transport: httpx.BaseTransport | None = None,
    timeout: float = 5.0,
    size: int = 5,
) -> dict[str, Any]:
    """Look up up to five historical scan records for the requested domain."""
    host = normalize_domain(domain)
    if not api_key:
        return {
            "status": "not_configured", "provider": "urlscan.io",
            "detail": "URLSCAN_API_KEY is not configured; historical website scans were not searched.",
            "results": [], "results_retrieved": 0,
        }
    if not host:
        return {
            "status": "not_checked", "provider": "urlscan.io",
            "detail": "No valid public domain was available for a historical scan search.",
            "results": [], "results_retrieved": 0,
        }
    try:
        with httpx.Client(transport=transport, timeout=timeout) as client:
            response = client.get(
                URLSCAN_SEARCH_URL,
                headers={"api-key": api_key},
                params={"q": f"task.domain:{host}", "size": max(1, min(int(size), 5)), "datasource": "scans"},
            )
            response.raise_for_status()
            payload = response.json()
        raw_results = payload.get("results") if isinstance(payload, dict) else []
        results = []
        for item in raw_results if isinstance(raw_results, list) else []:
            if not isinstance(item, dict):
                continue
            task = item.get("task") if isinstance(item.get("task"), dict) else {}
            page = item.get("page") if isinstance(item.get("page"), dict) else {}
            actual_host = str(task.get("domain") or "").lower().rstrip(".")
            if not actual_host:
                target_url = str(task.get("url") or "")
                try:
                    actual_host = (urlsplit(target_url).hostname or "").lower().rstrip(".")
                except Exception:
                    actual_host = ""
            if not actual_host or not _host_matches(actual_host, host):
                continue
            uuid = str(task.get("uuid") or item.get("_id") or "")[:80]
            if not uuid:
                continue
            verdicts = item.get("verdicts") if isinstance(item.get("verdicts"), dict) else {}
            urlscan_verdict = verdicts.get("urlscan") if isinstance(verdicts.get("urlscan"), dict) else {}
            engines_verdict = verdicts.get("engines") if isinstance(verdicts.get("engines"), dict) else {}
            malicious = verdicts.get("malicious")
            if malicious is None:
                malicious = urlscan_verdict.get("malicious")
            if malicious is None:
                malicious = engines_verdict.get("malicious")
            score = verdicts.get("score")
            if score is None:
                score = engines_verdict.get("score")
            results.append({
                "scan_id": uuid,
                "domain": actual_host,
                "scan_date": str(item.get("sort") or item.get("date") or task.get("time") or "")[:80],
                "page_title": str(page.get("title") or "")[:180],
                "page_url": str(page.get("url") or "")[:1000],
                "malicious_verdict": malicious if isinstance(malicious, bool) else None,
                "verdict_score": score if isinstance(score, (int, float)) else None,
                "redirected": str(page.get("redirected") or "")[:50],
                "visibility": str(task.get("visibility") or "unknown")[:20],
                "result_url": f"https://urlscan.io/result/{uuid}/",
            })
        limited_days = payload.get("search_date_limit_days") if isinstance(payload, dict) else None
        total = payload.get("total", len(raw_results) if isinstance(raw_results, list) else 0) if isinstance(payload, dict) else 0
        detail = (
            f"urlscan.io returned {len(results)} exact-domain historical scan record(s) for {host}. "
            "A malicious verdict is a historical scanner signal, not proof that the site is malicious now."
            if results else
            f"No historical urlscan.io records matched {host} within the searchable history. This is not a clean bill of health."
        )
        if isinstance(limited_days, int):
            detail += f" Search history for this account may be limited to the last {limited_days} days."
        return {
            "status": "checked" if results else "checked_no_match",
            "provider": "urlscan.io", "detail": detail,
            "results": results[:5], "results_retrieved": int(total or 0),
            "results_relevant": len(results), "domain": host,
            "search_date_limit_days": limited_days,
        }
    except httpx.HTTPStatusError as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        return {
            "status": "failed", "provider": "urlscan.io",
            "detail": f"urlscan.io historical search failed (HTTP {status_code or 'error'}). No risk conclusion was drawn from this failure.",
            "failure_reason": f"http_{status_code}" if status_code else "http_error",
            "results": [], "results_retrieved": 0, "domain": host,
        }
    except Exception as exc:
        return {
            "status": "failed", "provider": "urlscan.io",
            "detail": f"urlscan.io historical search failed ({type(exc).__name__}). No risk conclusion was drawn from this failure.",
            "failure_reason": type(exc).__name__,
            "results": [], "results_retrieved": 0, "domain": host,
        }
