"""Product-neutral candidate clustering over shared identifiers (union-find).

Replaces the DB-coupled clustering in the consumer app for new products. A cluster is a LEAD for human
review, never proof of common ownership or collusion: a shared device, phone number or beneficiary can be
innocent. Identifiers shared by too many records are ignored because popular identifiers do not discriminate.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, Mapping

Identifier = tuple[str, str]  # (kind, value), values should already be pseudonymised/normalised


@dataclass(frozen=True, slots=True)
class Cluster:
    cluster_id: str
    members: tuple[str, ...]
    shared: tuple[Identifier, ...]
    status: str = "candidate"          # never "confirmed" from this module
    basis: str = "shared_identifier"

    def to_dict(self) -> dict:
        return {"cluster_id": self.cluster_id, "members": list(self.members), "shared": [list(i) for i in self.shared],
                "status": self.status, "basis": self.basis, "risk_propagation": "never_automatic"}


def cluster_by_shared_identifiers(records: Mapping[str, Iterable[Identifier]], *, min_members: int = 2,
                                  max_identifier_fanout: int = 50, ignore_kinds: Iterable[str] = ()) -> list[Cluster]:
    ignored = set(ignore_kinds)
    holders: dict[Identifier, set[str]] = defaultdict(set)
    for record_id, identifiers in records.items():
        for ident in identifiers:
            if ident[0] not in ignored:
                holders[ident].add(record_id)

    parent: dict[str, str] = {r: r for r in records}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    linking: list[Identifier] = []
    for ident, who in holders.items():
        if len(who) < 2 or len(who) > max_identifier_fanout:
            continue
        linking.append(ident)
        first, *rest = sorted(who)
        for other in rest:
            parent[find(other)] = find(first)

    groups: dict[str, set[str]] = defaultdict(set)
    for r in records:
        groups[find(r)].add(r)
    out: list[Cluster] = []
    for members in groups.values():
        if len(members) < min_members:
            continue
        shared = tuple(sorted(i for i in linking if holders[i] <= members))
        ordered = tuple(sorted(members))
        cid = hashlib.sha256("|".join(ordered).encode()).hexdigest()[:12]
        out.append(Cluster(cluster_id=cid, members=ordered, shared=shared))
    return sorted(out, key=lambda c: (-len(c.members), c.cluster_id))
