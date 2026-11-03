"""Build a bounded, per-investigation graph from source-attributed evidence.

The graph is an explanation structure, not a global accusation database. It is
rebuilt from the current case, carries evidence provenance on every relationship,
and intentionally excludes phone numbers, payment identifiers and private narratives.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlsplit


def _stable_id(prefix: str, value: str) -> str:
    digest = hashlib.sha256(str(value).casefold().encode("utf-8", "ignore")).hexdigest()[:16]
    return f"{prefix}_{digest}"


def _safe_url(value: Any) -> str | None:
    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            return None
        if re.search(r"(?i)(?:token|secret|password|session|auth|credential)=", parsed.query):
            return None
        return raw[:1000]
    except Exception:
        return None


def _domain(value: Any) -> str | None:
    safe = _safe_url(value)
    if not safe:
        return None
    try:
        host = (urlsplit(safe).hostname or "").lower().rstrip(".")
        return host[4:] if host.startswith("www.") else host
    except Exception:
        return None


def build_evidence_graph(
    targets: list[dict[str, Any]] | None,
    evidence: list[dict[str, Any]] | None,
    *,
    shop_discovery: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return graph nodes/edges whose edges point back to source evidence IDs."""
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    edge_keys: set[tuple[str, str, str, str]] = set()
    target_ids: list[str] = []
    evidence_ids: set[str] = set()
    evidence_node_by_id: dict[str, str] = {}

    def add_node(node_id: str, node_type: str, label: str, **extra: Any) -> str:
        if node_id not in nodes:
            nodes[node_id] = {"id": node_id, "type": node_type, "label": str(label or "")[:180], **extra}
        return node_id

    def add_edge(source: str, target: str, relation: str, evidence_id: str | None, basis: str, strength: str = "context") -> None:
        key = (source, target, relation, str(evidence_id or ""))
        if key in edge_keys or source == target:
            return
        edge_keys.add(key)
        edges.append({
            "id": _stable_id("edge", "|".join(key)),
            "from": source,
            "to": target,
            "relation": relation,
            "evidence_id": evidence_id,
            "basis": basis,
            "strength": strength,
        })

    for raw in (targets or [])[:3]:
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get("kind") or "entity")[:24]
        platform = str(raw.get("platform") or "")[:24]
        identifier = str(raw.get("identifier") or "").strip()[:120]
        if not identifier:
            continue
        tkey = f"{kind}|{platform}|{identifier.casefold()}"
        tid = add_node(_stable_id("target", tkey), kind, identifier, platform=platform or None)
        target_ids.append(tid)

    target_lookup = []
    for raw in (targets or [])[:3]:
        if isinstance(raw, dict) and raw.get("identifier"):
            tkey = f"{raw.get('kind')}|{raw.get('platform') or ''}|{str(raw.get('identifier')).casefold()}"
            target_lookup.append((_stable_id("target", tkey), str(raw.get("identifier") or "").casefold().lstrip("@")))

    for item in (evidence or [])[:30]:
        if not isinstance(item, dict):
            continue
        eid = str(item.get("evidence_id") or "")[:80]
        if not eid:
            continue
        evidence_ids.add(eid)
        title = str(item.get("title") or item.get("provider") or "Public evidence")[:180]
        source_url = _safe_url(item.get("url"))
        e_node = add_node(
            _stable_id("evidence", eid), "evidence", title,
            evidence_id=eid,
            provider=str(item.get("provider") or "Public source")[:80],
            source_type=str(item.get("source_type") or "unknown")[:60],
            claim_status=str(item.get("claim_status") or "unverified")[:60],
            source_url=source_url,
            collected_at=str(item.get("collected_at") or "")[:50],
        )
        evidence_node_by_id[eid] = e_node
        identity_match = str(item.get("identity_match") or "")
        strong_identity = identity_match in {
            "exact_domain_url_match", "exact_domain_text_match", "exact_social_profile_match",
            "exact_social_profile_post_match", "exact_domain_historical_scan_match",
        } or identity_match.startswith("content_from_exact_") or identity_match.startswith("comment_on_exact_")
        item_identifier = str(item.get("target_identifier") or "").casefold().lstrip("@")
        for tid, ident in target_lookup:
            hay = f"{item.get('title') or ''} {item.get('snippet') or ''}".casefold()
            identifier_matches = bool(ident and item_identifier and item_identifier == ident)
            text_mentions_target = bool(ident and ident in hay)
            if identifier_matches or text_mentions_target:
                strong_for_target = bool(strong_identity and identifier_matches)
                add_edge(tid, e_node, "supported_by_source" if strong_for_target else "mentioned_in_source", eid,
                         "exact_target_profile_or_domain_match" if strong_for_target else "name_or_handle_mention",
                         "strong" if strong_for_target else "context")
        host = _domain(source_url)
        if host:
            d_node = add_node(_stable_id("domain", host), "domain", host)
            add_edge(e_node, d_node, "published_at", eid, "source_url_host", "context")

        location_claims = item.get("location_claims") if isinstance(item.get("location_claims"), list) else []
        for claim in location_claims[:8]:
            if not isinstance(claim, dict):
                continue
            value = " ".join(str(claim.get("value") or "").split())[:180]
            if len(value) < 3:
                continue
            loc_key = f"{claim.get('kind') or 'location'}|{value.casefold()}"
            loc_node = add_node(_stable_id("location", loc_key), "location_claim", value,
                                location_kind=str(claim.get("kind") or "profile_location"),
                                verification_status="unverified_claim")
            controlled = str(item.get("source_type") or "") in {
                "social_profile_observation", "social_public_profile_observation", "social_public_profile_post",
                "inspected_public_web_page",
            }
            add_edge(e_node, loc_node, "seller_published_location_claim" if controlled else "third_party_location_mention",
                     eid, "source_text_or_profile_field", "unverified")

        outbound = item.get("outbound_links") if isinstance(item.get("outbound_links"), list) else []
        for link in outbound[:5]:
            out_host = _domain(link)
            if not out_host:
                continue
            out_node = add_node(_stable_id("domain", out_host), "domain", out_host)
            add_edge(e_node, out_node, "profile_links_to", eid, "explicit_outbound_profile_link", "context")

    # Preserve the provenance chain when a social profile explicitly links a domain
    # that urlscan.io has seen before. This is a contextual relationship, not proof
    # that the profile and domain share an owner or that the historical scan is current.
    for item in (evidence or [])[:30]:
        if not isinstance(item, dict) or item.get("source_type") != "urlscan_historical_scan":
            continue
        eid = str(item.get("evidence_id") or "")[:80]
        scan_node = evidence_node_by_id.get(eid)
        if not scan_node:
            continue
        parent_eid = str(item.get("linked_from_evidence_id") or "")[:80]
        parent_node = evidence_node_by_id.get(parent_eid)
        if parent_node:
            add_edge(parent_node, scan_node, "linked_domain_has_historical_scan", eid,
                     "seller_profile_published_external_link", "context")
        related_domain = str(item.get("related_domain") or "").strip().lower().rstrip(".")
        if related_domain and re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", related_domain):
            domain_node = add_node(_stable_id("domain", related_domain), "domain", related_domain)
            add_edge(scan_node, domain_node, "historical_scan_of_domain", eid,
                     "urlscan_historical_scan_record", "context")

    # A Places match is deliberately modelled as a candidate, not an identity join.
    places = (shop_discovery or {}).get("map_candidates") if isinstance(shop_discovery, dict) else []
    for place in (places or [])[:5]:
        if not isinstance(place, dict):
            continue
        place_key = str(place.get("place_id") or place.get("name") or "")
        if not place_key:
            continue
        pid = add_node(_stable_id("place", place_key), "map_listing_candidate", str(place.get("name") or "Business listing"),
                       address=str(place.get("address") or "")[:240] or None,
                       source="Google Places",
                       maps_url=_safe_url(place.get("maps_url")),
                       website_url=_safe_url(place.get("website_url")),
                       identity_status="candidate_only_not_verified_as_the_submitted_seller")
        candidate_identifier = str(place.get("target_identifier") or "").casefold().lstrip("@")
        for tid, ident in target_lookup:
            if candidate_identifier and candidate_identifier == ident:
                add_edge(tid, pid, "possible_same_business_as", None, "directory_name_search_candidate_only", "weak")

    return {
        "version": "evidence-graph-v1",
        "scope": "this_investigation_only",
        "nodes": list(nodes.values())[:60],
        "edges": edges[:100],
        "stats": {
            "targets": len(target_ids),
            "evidence_sources": len(evidence_ids),
            "nodes": min(len(nodes), 60),
            "relationships": min(len(edges), 100),
            "map_listing_candidates": min(len(places or []), 5),
        },
        "interpretation_note": "Relationships show where information came from, not that two entities share an owner. Map listings and third-party claims are candidates until independently verified.",
    }
