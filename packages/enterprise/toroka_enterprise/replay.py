"""Synthetic bank extracts with injected insider patterns, plus an evaluation harness.

EVERYTHING HERE IS INVENTED. The injected patterns mirror the STRUCTURE of publicly reported cases (authentication
redirection, dormant/deceased reactivation, suspense-account diversion, salary-ledger diversion, profile snooping,
leaver activity). No real person, customer or bank record is used. Results measure the plumbing and the
false-positive behaviour on hard negatives; they say nothing about performance on a real bank's data.
"""
from __future__ import annotations

import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .ingest import SPEC
from .profile import LABELS

EAT = timezone(timedelta(hours=3))
START = datetime(2026, 4, 1, 8, 0, tzinfo=EAT)
BRANCHES = ["BR01", "BR02", "BR03", "BR04", "BR05"]   # BR05's CRM is deliberately not integrated (hard negative)


def _t(dt: datetime) -> str:
    return dt.astimezone(EAT).isoformat(timespec="seconds")


class _Builder:
    def __init__(self, seed: int, n_staff: int, n_customers: int, days: int):
        self.rng, self.days = random.Random(seed), days
        self.rows: dict[str, list[dict]] = {k: [] for k in SPEC}
        self.n = {"pay": 0, "req": 0, "ins": 0, "post": 0}
        self.truth: list[dict] = []
        self.staff: list[dict] = []
        for i in range(1, n_staff + 1):
            if i <= 5:
                role, branch = "branch_manager", BRANCHES[i - 1]
            elif i <= 7:
                role, branch = "payroll_officer", "BR01"
            elif i <= 17:
                role, branch = "ops", BRANCHES[(i - 8) % 5]
            else:
                role, branch = ("teller" if i % 2 == 0 else "rel_mgr"), BRANCHES[(i - 1) % 5]
            self.staff.append({"id": f"S{i:04d}", "role": role, "branch": branch, "status": "active", "end": ""})
        self.by_id = {s["id"]: s for s in self.staff}
        self.cust: dict[str, dict] = {}
        for i in range(1, n_customers + 1):
            dormant = self.rng.random() < 0.12
            self.cust[f"C{i:06d}"] = {"branch": BRANCHES[(i - 1) % 5], "dormant": dormant, "sensitive": (not dormant) and self.rng.random() < 0.012,
                                       "dormant_since": _t(START - timedelta(days=self.rng.randint(200, 600))) if dormant else "", "deceased": False}
        self.pool = {b: [c for c, v in self.cust.items() if v["branch"] == b and not v["dormant"]] for b in BRANCHES}
        self.dormant_pool = {b: [c for c, v in self.cust.items() if v["branch"] == b and v["dormant"]] for b in BRANCHES}
        self.portfolio: dict[str, set[str]] = {}
        for s in self.staff:
            if s["role"] in ("teller", "rel_mgr"):
                self.portfolio[s["id"]] = set(self.rng.sample([c for c in self.pool[s["branch"]] if not self.cust[c]["sensitive"]], 30))
            elif s["role"] == "branch_manager":
                self.portfolio[s["id"]] = set(self.pool[s["branch"]])
        self.used: set[str] = set()
        self.extra_accounts: list[dict] = []

    # ---- row helpers ----
    def event(self, ts, staff, action, cust, approver_staff=None, account=None):
        self.rows["audit_log"].append({"ts": _t(ts), "account_id": account or f"A-{staff}", "action": action, "customer_id": cust or "",
                                       "approver_account_id": f"A-{approver_staff}" if approver_staff else ""})

    def request(self, staff, cust, opened, closed, kind="service"):
        self.n["req"] += 1
        self.rows["service_requests"].append({"request_id": f"R{self.n['req']:06d}", "customer_id": cust, "staff_id": staff,
                                              "opened_at": _t(opened), "closed_at": _t(closed) if closed else "", "kind": kind})

    def instruction(self, cust, kind, ts, recorded_at=None):
        self.n["ins"] += 1
        self.rows["instructions"].append({"instruction_id": f"I{self.n['ins']:06d}", "customer_id": cust, "kind": kind,
                                           "received_at": _t(ts), "recorded_at": _t(recorded_at) if recorded_at else ""})

    def payment(self, cust, ts, amount, channel="mobile", ben=None, direction="debit"):
        self.n["pay"] += 1
        self.rows["payments"].append({"payment_id": f"P{self.n['pay']:06d}", "ts": _t(ts), "customer_id": cust, "channel": channel,
                                      "amount": amount, "beneficiary": ben or f"B{self.rng.randint(1, 99999):05d}", "direction": direction})

    def posting(self, ts, ledger, counter, amount, entered_staff, approver_staff, manual, narrative, account=None):
        self.n["post"] += 1
        self.rows["postings"].append({"posting_id": f"L{self.n['post']:06d}", "ts": _t(ts), "ledger": ledger, "counter_party": counter, "amount": amount,
                                      "entered_by_account": account or f"A-{entered_staff}", "approved_by_account": f"A-{approver_staff}" if approver_staff else "",
                                      "manual": str(manual).lower(), "narrative": narrative})

    def pick_staff(self, branch, role):
        for s in self.staff:
            if s["branch"] == branch and s["role"] == role and s["id"] not in self.used and s["status"] == "active":
                self.used.add(s["id"])
                return s["id"]
        raise RuntimeError(f"no free {role} in {branch}")

    def pick_cust(self, branch, portfolio_of=None, dormant=False, avoid_portfolios=True):
        pool = self.dormant_pool[branch] if dormant else self.pool[branch]
        owned = set().union(*(v for k, v in self.portfolio.items() if self.by_id[k]['role'] != 'branch_manager')) if avoid_portfolios else set()
        choices = [c for c in pool if c not in self.used and c not in owned and not self.cust[c]["sensitive"]]
        c = self.rng.choice(choices)
        self.used.add(c)
        return c

    def work_ts(self, day, lo=30, hi=8 * 60):
        d = START + timedelta(days=day)
        while d.weekday() >= 5:
            d += timedelta(days=1)
        return d + timedelta(minutes=self.rng.randint(lo, hi))


def generate(out_dir: str | Path, seed: int = 7, n_staff: int = 80, n_customers: int = 3000, days: int = 120) -> list[dict]:
    b, rng = _Builder(seed, n_staff, n_customers, days), None
    rng = b.rng
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # ---- choose injected actors first so benign generation can respect them ----
    t1a, t1b = b.pick_staff("BR02", "teller"), b.pick_staff("BR03", "teller")
    t2a, t2b = b.pick_staff("BR01", "teller"), b.pick_staff("BR04", "rel_mgr")
    t3a, t3b = b.pick_staff("BR01", "ops"), b.pick_staff("BR03", "ops")
    t5 = b.pick_staff("BR04", "teller")
    t6 = b.pick_staff("BR02", "rel_mgr")
    payroll_a, payroll_b = "S0006", "S0007"
    b.used.update({payroll_a, payroll_b})
    b.by_id[t6]["status"], b.by_id[t6]["end"] = "terminated", _t(START + timedelta(days=60, hours=9))
    leaver_ok = b.pick_staff("BR05", "teller")          # benign leaver with clean offboarding
    b.by_id[leaver_ok]["status"], b.by_id[leaver_ok]["end"] = "terminated", _t(START + timedelta(days=45, hours=9))
    admins = [b.pick_staff("BR02", "ops"), b.pick_staff("BR04", "ops")]   # benign: standard + privileged profile

    # ---- benign daily activity ----
    for d in range(days):
        if (START + timedelta(days=d)).weekday() >= 5:
            continue
        for s in b.staff:
            sid, role, br = s["id"], s["role"], s["branch"]
            if role not in ("teller", "rel_mgr", "branch_manager"):
                continue
            if s["end"] and START + timedelta(days=d) > datetime.fromisoformat(s["end"]):
                continue
            port = sorted(b.portfolio.get(sid, []))
            for _ in range(2 if role == "branch_manager" else 3):
                b.event(b.work_ts(d), sid, "profile_view", rng.choice(port))
            if role != "branch_manager" and rng.random() < (0.33 if br == "BR05" else 0.17):   # walk-in service
                c = b.pick_cust(br, avoid_portfolios=False)
                b.used.discard(c)
                ts = b.work_ts(d, 60, 7 * 60)
                if c not in b.portfolio[sid]:
                    if br != "BR05":
                        b.request(sid, c, ts - timedelta(minutes=rng.randint(5, 90)), ts + timedelta(hours=rng.randint(2, 30)))
                    b.event(ts, sid, "profile_view", c)
            elif role != "branch_manager" and br != "BR05" and rng.random() < 0.03:       # benign noise: unticketed lookup
                b.event(b.work_ts(d), sid, "profile_view", b.pick_cust(br, avoid_portfolios=False))

    # legitimate sensitive changes (with instructions) and hard negatives
    facing = [s["id"] for s in b.staff if s["role"] in ("teller", "rel_mgr") and s["id"] not in b.used and s["status"] == "active"]
    for k in range(28):
        sid = rng.choice(facing)
        c = rng.choice(sorted(b.portfolio[sid]))
        ts = b.work_ts(rng.randint(2, days - 10))
        after = k < 5   # hard negative: instruction is entered into the system AFTER the change
        received = ts - timedelta(hours=rng.randint(1, 30))
        recorded = ts + timedelta(hours=rng.randint(10, 36)) if after else received
        b.instruction(c, "contact_change", received, recorded_at=recorded)
        b.event(ts, sid, "profile_view", c)
        b.event(ts + timedelta(minutes=4), sid, "contact_change", c)
        if k % 3 == 0:
            b.instruction(c, "card_issue", ts - timedelta(hours=2))
            b.event(ts + timedelta(minutes=9), sid, "card_issue", c)
        if k % 4 == 0:
            b.payment(c, ts + timedelta(days=2), rng.randint(3000, 15000) * 100, "atm")
    for br in BRANCHES:                                           # legitimate reactivations: instruction + independent approver
        for _ in range(1 if br != "BR05" else 0):
            c = b.pick_cust(br, dormant=True)
            sid = rng.choice([x for x in facing if b.by_id[x]["branch"] == br])
            b.portfolio[sid].add(c)
            ts = b.work_ts(rng.randint(5, days - 10))
            b.instruction(c, "reactivation", ts - timedelta(hours=rng.randint(1, 10)))
            b.event(ts, sid, "account_reactivate", c, approver_staff=f"S{BRANCHES.index(br) + 1:04d}")
    ops_pool = [s["id"] for s in b.staff if s["role"] == "ops" and s["id"] not in b.used]
    for k in range(20):                                           # legitimate suspense postings: dispute ticket + independent approver
        sid = rng.choice(ops_pool)
        peer = rng.choice([o for o in ops_pool if o != sid])
        c = rng.choice(b.pool[b.by_id[sid]["branch"]])
        ts = b.work_ts(rng.randint(3, days - 10))
        b.request(sid, c, ts - timedelta(days=rng.randint(1, 5)), ts + timedelta(days=1), "dispute")
        b.posting(ts, "SUSPENSE", c, rng.randint(2000, 60000) * 100, sid, peer, True, "DISPUTE_REFUND")
    for m in range(3):                                            # payroll: system run + a few benign manual adjustments to roster accounts
        for s in b.staff:
            b.posting(START + timedelta(days=28 * m + 25, hours=1), "PAYROLL", f"SAL-{s['id']}", rng.randint(40000, 180000) * 100, payroll_a, payroll_b, False, "SALARY")
        b.posting(START + timedelta(days=28 * m + 26), "PAYROLL", f"SAL-{rng.choice(b.staff)['id']}", rng.randint(2000, 9000) * 100, payroll_a, payroll_b, True, "SALARY")
    for sid in admins:                                            # benign: ops staff (privileged base profile) with a second STANDARD profile
        b.extra_accounts.append({"account_id": f"A2-{sid}", "staff_id": sid, "system": "core_banking", "status": "active", "is_privileged": "false"})
    for c in b.cust:                                              # ordinary customer payments
        for _ in range(2):
            b.payment(c, b.work_ts(rng.randint(0, days - 1)), rng.randint(500, 20000) * 100)

    # ---- injected patterns (ground truth) ----
    def log(tid, pattern, staff, customers, basis):
        b.truth.append({"id": tid, "pattern": pattern, "staff": staff, "customers": customers, "public_basis": basis})

    c = b.pick_cust("BR02"); ts = START + timedelta(days=40, hours=9, minutes=22)   # 17:22 EAT
    b.event(ts, t1a, "profile_view", c); b.event(ts + timedelta(minutes=3), t1a, "contact_change", c); b.event(ts + timedelta(minutes=9), t1a, "card_issue", c)
    for dd in (1, 2, 4):
        b.payment(c, ts + timedelta(days=dd), 40000 * 100, "atm")
    log("T1a", "authentication redirection, customer outside portfolio, after hours", t1a, [c], "OTP-redirection insider case reported by the NPA")

    c = sorted(b.portfolio[t1b])[0]; ts = b.work_ts(55)
    b.event(ts, t1b, "contact_change", c); b.event(ts + timedelta(minutes=6), t1b, "card_issue", c)
    for dd in (1, 3, 5):
        b.payment(c, ts + timedelta(days=dd), 35000 * 100, "atm")
    log("T1b", "authentication redirection on the staff member's own portfolio customer", t1b, [c], "OTP-redirection insider case reported by the NPA")

    c = b.pick_cust("BR01", dormant=True); ts = b.work_ts(70)
    b.event(ts, t2a, "account_reactivate", c, approver_staff="S0001"); b.event(ts + timedelta(minutes=40), t2a, "beneficiary_add", c)
    b.payment(c, ts + timedelta(days=2), 250000 * 100, "rtgs")
    log("T2a", "dormant account reactivated without instruction, then beneficiary and payment", t2a, [c], "dormant-account insider cases (Kenya, South Africa)")

    c = b.pick_cust("BR04", dormant=True); b.cust[c]["deceased"] = True; ts = b.work_ts(82)
    b.event(ts, t2b, "account_reactivate", c); b.payment(c, ts + timedelta(days=1), 180000 * 100, "rtgs")
    log("T2b", "reactivation of an account flagged deceased, no approver recorded", t2b, [c], "deceased-customer account cases (Kenya, South Africa)")

    victims = []
    for k in range(4):
        c = b.pick_cust("BR01"); victims.append(c); ts = b.work_ts(30 + 4 * k)
        b.posting(ts, "SUSPENSE", c, rng.randint(90000, 300000) * 100, t3a, t3a, True, "DISPUTE_REFUND")   # self-approved
        b.payment(c, ts + timedelta(days=1), 85000 * 100, "atm")
    log("T3a", "self-approved manual postings out of a suspense ledger, cash-out follows", t3a, victims, "suspense-account insider cases (alleged and convicted)")
    victims = []
    for k in range(3):
        c = b.pick_cust("BR03"); victims.append(c); ts = b.work_ts(50 + 3 * k)
        b.posting(ts, "SUSPENSE", c, rng.randint(90000, 250000) * 100, t3b, None, True, "OTHER")             # no approver
        b.payment(c, ts + timedelta(days=2), 70000 * 100, "mobile")
    log("T3b", "manual suspense postings with no approver recorded, cash-out follows", t3b, victims, "suspense-account insider cases (alleged and convicted)")

    b.extra_accounts.append({"account_id": f"A2-{payroll_b}", "staff_id": payroll_b, "system": "core_banking", "status": "active", "is_privileged": "false"})
    for k in range(7):
        b.posting(b.work_ts(20 + 6 * k), "PAYROLL", f"EXT-{k:04d}", rng.randint(150000, 400000) * 100, payroll_b, payroll_a, True, "SALARY", account=f"A2-{payroll_b}")
    log("T4", "duplicate core-banking profile used for manual salary postings to non-employees", payroll_b, [f"EXT-{k:04d}" for k in range(7)], "alleged salary-ledger diversion (Kenya, 2023-24)")

    victims = rng.sample([c for c in b.pool["BR04"] if c not in set().union(*(v for k, v in b.portfolio.items() if b.by_id[k]['role'] != 'branch_manager'))], 39)
    victims += [c for c, v in b.cust.items() if v["sensitive"] and v["branch"] == "BR04"][:3]
    for k, c in enumerate(victims):
        b.event(b.work_ts(20 + (k * 50) // len(victims)), t5, "profile_view", c)
    log("T5", "bulk lookup of unassigned, unticketed profiles including sensitive ones", t5, victims, "profile-snooping insider case (Singapore)")

    ts = START + timedelta(days=66, hours=3)
    for k in range(5):
        b.event(START + timedelta(days=62 + k, hours=3), t6, "profile_view", b.pick_cust("BR02"))
    c = b.pick_cust("BR02"); b.event(ts, t6, "contact_change", c)
    log("T6", "activity after the recorded employment end date, including an unbacked contact change", t6, [c], "leaver-access failures")

    # ---- write feeds ----
    for s in b.staff:
        b.rows["hr_roster"].append({"staff_id": s["id"], "status": s["status"], "role": s["role"], "branch": s["branch"], "end_date": s["end"], "salary_account": f"SAL-{s['id']}"})
        b.rows["system_accounts"].append({"account_id": f"A-{s['id']}", "staff_id": s["id"], "system": "core_banking",
                                          "status": "disabled" if (s["status"] == "terminated" and s["id"] == leaver_ok) else "active", "is_privileged": str(s["role"] == "ops").lower()})
    b.rows["system_accounts"].extend(b.extra_accounts)
    for sid, custs in b.portfolio.items():
        b.rows["portfolio"].extend({"staff_id": sid, "customer_id": c} for c in sorted(custs))
    for cid, v in b.cust.items():
        b.rows["customers"].append({"customer_id": cid, "status": "dormant" if v["dormant"] else "active", "dormant_since": v["dormant_since"],
                                    "deceased_flag": str(v["deceased"]).lower(), "is_sensitive": str(v["sensitive"]).lower()})
    b.rows["audit_log"].sort(key=lambda r: r["ts"])
    for name, rows in b.rows.items():
        with (out / f"{name}.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(SPEC[name]))
            w.writeheader()
            w.writerows(rows)
    (out / "ground_truth.json").write_text(json.dumps(b.truth, indent=2))
    return b.truth


def evaluate(scan, truth: list[dict], vault: dict[str, str]) -> dict:
    """Score a scan against injected truth. A positive counts as found when any surfaced lead names its staff member."""
    best: dict[str, str] = {}
    for lead in scan.leads:
        raw = vault.get(lead.focus.staff_ref)
        if raw and (raw not in best or lead.label < best[raw]):
            best[raw] = lead.label
    rows = [{"id": t["id"], "pattern": t["pattern"], "found": t["staff"] in best and best[t["staff"]] in ("PRIORITY REVIEW", "REVIEW"),
             "label": best.get(t["staff"], "not surfaced")} for t in truth]
    positives = {t["staff"] for t in truth}
    false_leads = [l for l in scan.leads if vault.get(l.focus.staff_ref) not in positives and l.label in ("PRIORITY REVIEW", "REVIEW")]
    conflicting = [l for l in scan.leads if vault.get(l.focus.staff_ref) not in positives and l.label == "CONFLICTING RECORDS"]
    found = sum(r["found"] for r in rows)
    surfaced = len([l for l in scan.leads if l.label in ("PRIORITY REVIEW", "REVIEW")])
    return {"injected": len(truth), "found": found, "recall": round(found / len(truth), 3), "scenarios": rows,
            "false_review_leads": len(false_leads), "false_lead_summaries": [f"{l.focus.label()}: {l.result.risk_evidence[0].summary if l.result.risk_evidence else l.label}" for l in false_leads[:10]],
            "conflicting_on_benign": len(conflicting), "surfaced_review_leads": surfaced,
            "precision_by_lead": round((surfaced - len(false_leads)) / surfaced, 3) if surfaced else None, "examined": scan.examined}
