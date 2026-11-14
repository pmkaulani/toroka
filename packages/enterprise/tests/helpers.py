import csv
from datetime import datetime, timedelta, timezone
from pathlib import Path

from toroka_enterprise.ingest import SPEC, ingest_dir
from toroka_enterprise.pseudonym import Pseudonymiser
from toroka_enterprise.scan import run_scan

T0 = datetime(2026, 5, 4, 14, 0, tzinfo=timezone(timedelta(hours=3)))


def ts(**delta):
    return (T0 + timedelta(**delta)).isoformat(timespec="seconds")


def write(directory: Path, feeds: dict[str, list[dict]]) -> None:
    for name, rows in feeds.items():
        with (directory / f"{name}.csv").open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(SPEC[name]))
            w.writeheader()
            for r in rows:
                w.writerow({c: r.get(c, "") for c in SPEC[name]})


def base_feeds(extra_staff=(), with_crm=True):
    staff = [{"staff_id": "S1", "status": "active", "role": "teller", "branch": "BR01", "salary_account": "SAL-S1"},
             {"staff_id": "S2", "status": "active", "role": "teller", "branch": "BR01", "salary_account": "SAL-S2"}] + list(extra_staff)
    feeds = {
        "hr_roster": staff,
        "system_accounts": [{"account_id": f"A-{s['staff_id']}", "staff_id": s["staff_id"], "system": "core_banking", "status": "active", "is_privileged": "false"} for s in staff],
        "portfolio": [{"staff_id": "S1", "customer_id": "C-OWN"}],
        "audit_log": [], "instructions": [], "payments": [], "postings": [],
        "customers": [{"customer_id": c, "status": "active"} for c in ("C-OWN", "C-X", "C-Y")],
    }
    if with_crm:   # healthy CRM: every active staff member appears in service requests
        feeds["service_requests"] = [{"request_id": f"R-{s['staff_id']}", "customer_id": "C-OWN", "staff_id": s["staff_id"], "opened_at": ts(days=-30), "closed_at": ts(days=-29), "kind": "service"} for s in staff]
    return feeds


def scan(tmp_path, feeds, secret="s" * 40):
    write(tmp_path, feeds)
    ps = Pseudonymiser(secret)
    ds, quality = ingest_dir(tmp_path, ps)
    return ds, quality, run_scan(ds, quality=quality), ps


def labels(scan_result):
    return {l.focus.label(): l.label for l in scan_result.leads}
