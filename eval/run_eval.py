"""Evaluate the assessment policy on a labelled CSV (blueprint section 15).

    PYTHONPATH=packages/rules python eval/run_eval.py [--cases eval/cases.csv] [--max-legit-flagged 0.0] [--min-scam-flagged 1.0]

Sets: scam (should be flagged: high_risk or suspicious), legit (should never be flagged), ambiguous (should abstain).
The shipped cases are INVENTED. Numbers on them are a regression check, not a performance claim. Replace with consented real messages.
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter

from ssi_rules import Observations, assess, load_registry
from ssi_rules.registry import verified_entities_from_registry

FLAGGED = {"high_risk", "suspicious_verify_first"}


def run(path: str):
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    res = []
    for r in rows:
        a = assess(r["text"], observations=Observations(verified_entities=verified_entities_from_registry(load_registry())))
        label = a.label.value
        ok = (label in FLAGGED) if r["expected"] == "flagged" else label == r["expected"]
        res.append({**r, "got": label, "ok": ok, "accusation": any(w in (a.summary + " ".join(f.plain_text for f in a.findings)).lower() for w in ("scammer", "fraudster", "criminal"))})
    return res


def summarise(res):
    by = {s: [r for r in res if r["set"] == s] for s in ("scam", "legit", "ambiguous")}
    flag = lambda rs: sum(r["got"] in FLAGGED for r in rs)
    return {"n": len(res),
            "scam_flagged_rate": flag(by["scam"]) / max(1, len(by["scam"])),
            "scam_high_risk_rate": sum(r["got"] == "high_risk" for r in by["scam"]) / max(1, len(by["scam"])),
            "legit_flagged_rate": flag(by["legit"]) / max(1, len(by["legit"])),
            "verified_cases_correct": sum(r["got"] == "verified_official" for r in res if r["expected"] == "verified_official"),
            "legit_high_risk": sum(r["got"] == "high_risk" for r in by["legit"]),
            "ambiguous_abstained_rate": sum(r["got"] == "inconclusive" for r in by["ambiguous"]) / max(1, len(by["ambiguous"])),
            "accusatory_wording": sum(r["accusation"] for r in res),
            "mismatches": [(r["id"], r["expected"], r["got"]) for r in res if not r["ok"]],
            "label_counts": dict(Counter(r["got"] for r in res))}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="eval/cases.csv")
    ap.add_argument("--max-legit-flagged", type=float, default=0.0)
    ap.add_argument("--min-scam-flagged", type=float, default=1.0)
    a = ap.parse_args(argv)
    s = summarise(run(a.cases))
    for k, v in s.items():
        print(f"{k:28} {v}")
    bad = s["legit_flagged_rate"] > a.max_legit_flagged or s["scam_flagged_rate"] < a.min_scam_flagged or s["legit_high_risk"] or s["accusatory_wording"]
    print("\nRESULT:", "FAIL" if bad else "pass")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
