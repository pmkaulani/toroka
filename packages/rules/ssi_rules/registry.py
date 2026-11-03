"""Loads the official-source registry and answers freshness questions."""
from __future__ import annotations

import functools
import re
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

import yaml

from .observations import VerifiedEntity

DEFAULT_PATH = Path(__file__).parent / "data" / "registry.yaml"


@dataclass(frozen=True)
class Organisation:
    id: str
    display_name: str
    aliases: tuple[str, ...]
    brand_tokens: tuple[str, ...]
    official_domains: tuple[str, ...]
    official_numbers: tuple[str, ...]

    def alias_regex(self) -> re.Pattern:
        return re.compile(r"(?i)(?<![\w-])(?:" + "|".join(re.escape(a) for a in self.aliases) + r")(?![\w-])")


@dataclass(frozen=True)
class Statement:
    id: str
    org: str
    statement: str
    source_url: str
    source_published: date | None
    last_verified_at: date
    review_interval_days: int
    reviewer: str

    def review_due(self) -> date:
        return self.last_verified_at + timedelta(days=self.review_interval_days)

    def is_stale(self, today: date) -> bool:
        return today > self.review_due()


@dataclass
class Registry:
    organisations: dict[str, Organisation] = field(default_factory=dict)
    statements: dict[str, Statement] = field(default_factory=dict)

    def statements_for(self, org_id: str) -> list[Statement]:
        return [s for s in self.statements.values() if s.org == org_id]


@functools.lru_cache(maxsize=8)
def load_registry(path: Path | str = DEFAULT_PATH) -> Registry:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    reg = Registry()
    for oid, o in data["organisations"].items():
        reg.organisations[oid] = Organisation(
            oid, o["display_name"], tuple(o["aliases"]), tuple(o.get("brand_tokens", [])),
            tuple(o["official_domains"]), tuple(o.get("official_numbers", [])))
    for s in data["statements"]:
        if s["org"] not in reg.organisations:
            raise ValueError(f"statement {s['id']} references unknown organisation {s['org']}")
        reg.statements[s["id"]] = Statement(
            s["id"], s["org"], s["statement"], s["source_url"], s.get("source_published"),
            s["last_verified_at"], int(s["review_interval_days"]), s.get("reviewer", "unreviewed"))
    return reg


def verified_entities_from_registry(reg: Registry) -> list[VerifiedEntity]:
    """Create candidate identity records from source data; unreviewed entries must not verify a site."""
    out = []
    for oid, o in reg.organisations.items():
        st = sorted(reg.statements_for(oid), key=lambda x: x.id)[0]
        out.append(VerifiedEntity(f"org-{oid}", o.display_name, "organisation", list(o.official_domains), [], True, "official_registry", st.source_url,
                                  st.last_verified_at.isoformat(), st.review_due().isoformat(), st.reviewer))
    return out
