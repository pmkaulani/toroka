"""Candidate selection + investigation. A cheap pre-filter proposes focuses; the core EvidenceEngine weighs them."""
from __future__ import annotations

from dataclasses import dataclass, field

from toroka_core.evidence.engine import EvidenceEngine
from toroka_core.evidence.models import InvestigationRequest, InvestigationResult

from .ingest import DataQuality
from .profile import INSIDER_PROFILE, LABELS, SURFACED
from .scenarios import SUSPENSE_LEDGERS, Focus, Rules, build_providers
from .schema import SENSITIVE_ACTIONS, Dataset

RANK = {"PRIORITY REVIEW": 0, "REVIEW": 1, "CONFLICTING RECORDS": 2}


@dataclass
class Lead:
    focus: Focus
    result: InvestigationResult
    label: str

    def to_dict(self) -> dict:
        d = self.result.to_dict()
        d.update({"focus": self.focus.label(), "staff_ref": self.focus.staff_ref, "customer_ref": self.focus.customer_ref, "label": self.label})
        return d


@dataclass
class ScanResult:
    leads: list[Lead] = field(default_factory=list)
    examined: int = 0
    not_surfaced: dict[str, int] = field(default_factory=dict)
    quality: DataQuality | None = None


def candidate_focuses(ds: Dataset, rules: Rules) -> list[Focus]:
    out: set[Focus] = set()
    for staff, evs in ds.events_by_staff.items():
        for e in evs:
            if e.action in SENSITIVE_ACTIONS and e.customer_ref:
                out.add(Focus(staff, e.customer_ref))
        port = ds.assignments.get(staff, set())
        viewed = {e.customer_ref for e in evs if e.action == "profile_view" and e.customer_ref and e.customer_ref not in port}
        if len(viewed) >= rules.bulk_unjustified_threshold:
            out.add(Focus(staff))
    for staff, posts in ds.postings_by_staff.items():
        if any(p.manual and (p.ledger in SUSPENSE_LEDGERS or p.narrative == "SALARY") for p in posts):
            out.add(Focus(staff))
    for staff, acc_refs in ds.accounts_by_staff.items():
        counts: dict[str, int] = {}
        for a in acc_refs:
            if ds.accounts[a].status == "active":
                counts[ds.accounts[a].system] = counts.get(ds.accounts[a].system, 0) + 1
        s = ds.staff.get(staff)
        leaver = bool(s and s.status == "terminated" and s.end_date and any(e.ts > s.end_date for e in ds.events_by_staff.get(staff, [])))
        if any(n >= 2 for n in counts.values()) or leaver:
            out.add(Focus(staff))
    return sorted(out, key=lambda f: (f.staff_ref, f.customer_ref or ""))


def run_scan(ds: Dataset, rules: Rules | None = None, quality: DataQuality | None = None) -> ScanResult:
    rules = rules or Rules()
    pair_providers, staff_providers = build_providers(ds, rules)
    engines = {True: EvidenceEngine(providers=pair_providers, profile=INSIDER_PROFILE),
               False: EvidenceEngine(providers=staff_providers, profile=INSIDER_PROFILE)}
    scan = ScanResult(quality=quality)
    for focus in candidate_focuses(ds, rules):
        scan.examined += 1
        res = engines[focus.customer_ref is not None].investigate(
            InvestigationRequest(target=focus.label(), context={"ds": ds, "focus": focus}))
        label = LABELS[res.verdict]
        if label in SURFACED:
            scan.leads.append(Lead(focus, res, label))
        else:
            scan.not_surfaced[label] = scan.not_surfaced.get(label, 0) + 1
    scan.leads.sort(key=lambda l: (RANK[l.label], -(l.result.risk_index or 0), l.focus.label()))
    return scan
