"""Command line: demo (synthetic end-to-end), scan (real extracts), verify-audit, keygen.

Secrets come from the environment, never from arguments:
  TOROKA_ENT_SECRET     >= 32 characters, keys the pseudonymisation
  TOROKA_ENT_VAULT_KEY  Fernet key (see `keygen`), seals the pseudonym->identity vault
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from .audit import AuditLog
from .casework import CaseStore, Principal, generate_key
from .coverage import coverage_report, render
from .discover import suggest_mapping
from .foreign import export
from .ingest import IngestError, ingest_dir
from .manifest import build_manifest, reproduce, result_digest
from .mapping import MappingError, load_mapping
from .profile import INSIDER_PROFILE
from .report import render_case
from .scenarios import Rules
from .pseudonym import Pseudonymiser
from .replay import evaluate, generate
from .scan import run_scan

SYSTEM = Principal("scan-service", "system")


def _open_cases(out: Path, scan, vault: dict[str, str], key: bytes, manifest: dict | None = None, digest: str | None = None):
    audit = AuditLog(out / "audit.db")
    store = CaseStore(out / "cases.db", audit, key)
    store.store_vault(SYSTEM, vault)
    leads = [dict(l.to_dict(), manifest_id=(manifest or {}).get("manifest_id")) for l in scan.leads]
    ids = [store.open_from_lead(SYSTEM, d) for d in leads]
    (out / "leads.json").write_text(json.dumps(leads, indent=2, default=str))
    if manifest:
        (out / "run.json").write_text(json.dumps({"manifest": manifest, "result_digest": digest}, indent=2))
        audit.append(SYSTEM.user_id, SYSTEM.role, "scan.run", manifest["manifest_id"], {"result_digest": digest, "leads": len(leads), "tool_version": manifest["tool_version"]})
    reports = out / "reports"
    reports.mkdir(exist_ok=True)
    for i, d in enumerate(leads[:10], start=1):
        (reports / f"lead-{i:02d}-{d['label'].lower().replace(' ', '-')}.html").write_text(render_case(d, manifest), encoding="utf-8")
    return audit, store, ids


def _print_coverage(ds) -> None:
    print("\ndetector coverage on this data:")
    print(render(coverage_report(ds)))


def _print_scan(scan) -> None:
    q = scan.quality.to_dict() if scan.quality else {}
    print(f"examined {scan.examined} candidate focuses | surfaced {len(scan.leads)} | not surfaced {scan.not_surfaced}")
    for n in q.get("notes", []):
        print(f"  data quality: {n}")
    for lead in scan.leads[:15]:
        top = (lead.result.risk_evidence or lead.result.supporting_evidence or lead.result.context_evidence)[:1]
        print(f"  {lead.label:19} {lead.focus.label():34} idx {lead.result.risk_index}  {top[0].summary if top else ''}")


def cmd_demo(a) -> int:
    out = Path(a.out or tempfile.mkdtemp(prefix="toroka-ent-"))
    data = out / "extracts"
    truth = generate(data, seed=a.seed)
    ps = Pseudonymiser("demo-secret-" + "x" * 32)
    mapping, mapping_text = None, None
    if a.style:
        foreign = out / f"extracts_style_{a.style}"
        mapping_text = export(data, foreign, a.style)
        mapping = load_mapping(mapping_text)
        (out / f"mapping_style_{a.style}.toml").write_text(mapping_text)
        data = foreign
        print(f"Reading a deliberately foreign-shaped export (style {a.style}) through its mapping file: {data}\n")
    ds, quality = ingest_dir(data, ps, mapping)
    scan = run_scan(ds, quality=quality)
    ev = evaluate(scan, truth, ps.vault)
    print(f"SYNTHETIC DEMO ({len(ds.events):,} audit events, {len(ds.staff)} staff, {len(ds.customers):,} customers). Invented data: measures plumbing and false-positive behaviour only.\n")
    _print_scan(scan)
    _print_coverage(ds)
    print(f"\ninjected patterns found: {ev['found']}/{ev['injected']} | false review leads on benign staff: {ev['false_review_leads']} | conflicting on benign: {ev['conflicting_on_benign']}")
    for r in ev["scenarios"]:
        print(f"  {r['id']:4} {'FOUND ' if r['found'] else 'MISSED'} {r['label']:19} {r['pattern']}")
    key = generate_key()
    manifest = build_manifest(quality, mapping_text=mapping_text, rules=Rules(), profile=INSIDER_PROFILE, secret="demo-secret-" + "x" * 32)
    audit, store, ids = _open_cases(out, scan, ps.vault, key, manifest, result_digest(scan))
    print(f"\nrun manifest {manifest['manifest_id']} | result digest {result_digest(scan)[:16]}... | {min(len(ids), 10)} investigation reports in {out / 'reports'}")
    inv, auth = Principal("investigator-1", "investigator"), Principal("authoriser-1", "authoriser")
    case = store.view_case(inv, ids[0])
    pseudo = case["snapshot"]["staff_ref"]
    rid = store.request_reveal(inv, ids[0], pseudo, "Customer complaint 2026-05-14 requires confirming the staff member behind this lead")
    try:
        store.approve_reveal(inv, rid)
    except PermissionError as exc:
        print(f"\nself-approval blocked: {exc}")
    store.approve_reveal(auth, rid)
    print(f"dual-approved reveal released {pseudo} -> {store.reveal(inv, rid)} (one use, logged)")
    res = audit.verify()
    print(f"audit chain: {'intact' if res.ok else 'BROKEN'} over {res.checked} entries, head {res.head_hash[:16]}...  (copy the head hash to a system the DBA does not control)")
    print(f"\nartifacts in {out}")
    return 0


def cmd_scan(a) -> int:
    secret, key = os.environ.get("TOROKA_ENT_SECRET"), os.environ.get("TOROKA_ENT_VAULT_KEY")
    if not secret or not key:
        print("set TOROKA_ENT_SECRET (>=32 chars) and TOROKA_ENT_VAULT_KEY (run `keygen`)", file=sys.stderr)
        return 2
    try:
        ps = Pseudonymiser(secret)
        mapping_text = Path(a.mapping).read_text(encoding="utf-8") if a.mapping else None
        ds, quality = ingest_dir(a.data, ps, load_mapping(mapping_text) if mapping_text else None)
    except (IngestError, MappingError, ValueError) as exc:
        print(f"ingest failed: {exc}", file=sys.stderr)
        return 1
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    scan = run_scan(ds, quality=quality)
    _print_scan(scan)
    _print_coverage(ds)
    (out / "coverage.json").write_text(json.dumps(coverage_report(ds), indent=2))
    from .data_contract import contract_dict
    (out / "data_contract.json").write_text(json.dumps(contract_dict(), indent=2))
    manifest = build_manifest(quality, mapping_text=mapping_text, rules=Rules(), profile=INSIDER_PROFILE, secret=secret)
    _open_cases(out, scan, ps.vault, key.encode(), manifest, result_digest(scan))
    print(f"run manifest {manifest['manifest_id']}; reports in {out / 'reports'}")
    (out / "data_quality.json").write_text(json.dumps(quality.to_dict(), indent=2))
    print(f"cases, audit log and data-quality report written to {out}")
    return 0


def cmd_data_contract(a) -> int:
    from .data_contract import contract_dict, contract_markdown
    if a.format == "json":
        text = json.dumps(contract_dict(), indent=2)
    else:
        text = contract_markdown()
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"Data contract written to {a.out}")
    else:
        print(text)
    return 0


def cmd_validate(a) -> int:
    """Dry run: read the extracts through the mapping and report what the data can and cannot support. Writes nothing unless --out is given."""
    from .coverage import coverage_report, render
    try:
        ds, q = ingest_dir(a.data, Pseudonymiser("validate-only-" + "x" * 32), load_mapping(a.mapping) if a.mapping else None)
    except (IngestError, MappingError, ValueError) as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        return 1

    cov = coverage_report(ds)
    missing_required_fields = []
    for r in cov:
        for f in r.get("missing_required_fields", []):
            if f not in missing_required_fields:
                missing_required_fields.append(f)

    remediations = []
    for r in cov:
        for hint in r.get("remediation", []):
            if hint not in remediations:
                remediations.append(hint)

    if getattr(a, "json", False) or (getattr(a, "out", None) and str(a.out).endswith(".json")):
        payload = {
            "rows_read": q.rows_read,
            "rows_rejected": q.rows_rejected,
            "feeds_missing": q.feeds_missing,
            "missing_required_fields": missing_required_fields,
            "absent_fields": q.absent_fields,
            "feed_health": q.feed_health,
            "notes": q.notes,
            "rejected_samples": q.rejected_samples[:10],
            "detector_coverage": cov,
            "remediation": remediations,
        }
        text = json.dumps(payload, indent=2)
        if getattr(a, "out", None):
            Path(a.out).write_text(text, encoding="utf-8")
            print(f"Validation report written to {a.out}")
        else:
            print(text)
        return 0

    print(f"rows read: {q.rows_read}\nrows rejected: {q.rows_rejected or 'none'}\nfeeds missing: {q.feeds_missing or 'none'}")
    if missing_required_fields:
        print(f"missing required fields: {', '.join(missing_required_fields)}")
    if q.absent_fields:
        print(f"optional fields absent: {', '.join(q.absent_fields)}")
    for n in q.notes:
        print(f"  note: {n}")
    for line in q.rejected_samples[:5]:
        print(f"  rejected: {line}")
    _print_coverage(ds)
    if remediations:
        print("\nrecommended remediation:")
        for hint in remediations:
            print(f"  - {hint}")
    if getattr(a, "out", None):
        Path(a.out).write_text(render(cov), encoding="utf-8")
        print(f"\nValidation summary written to {a.out}")
    return 0


def cmd_suggest(a) -> int:
    try:
        text, report = suggest_mapping(a.file, a.feed, a.delimiter)
    except (ValueError, OSError) as exc:
        print(f"cannot read {a.file}: {exc}", file=sys.stderr)
        return 1
    if a.out:
        Path(a.out).write_text(text)
    else:
        print(text)
    print(f"# matched {len(report['matched'])}/{len(report['matched']) + len(report['unmatched'])} canonical columns; unmatched: {report['unmatched'] or 'none'}; flags: {report['flags'] or 'none'}", file=sys.stderr)
    return 0


def cmd_reproduce(a) -> int:
    """Re-run a past scan from its manifest and say whether inputs, configuration and result are identical."""
    secret = os.environ.get("TOROKA_ENT_SECRET")
    if not secret:
        print("set TOROKA_ENT_SECRET to the same value used for the original run", file=sys.stderr)
        return 2
    run = json.loads((Path(a.out) / "run.json").read_text())
    mapping_text = Path(a.mapping).read_text(encoding="utf-8") if a.mapping else None
    res = reproduce(run["manifest"], run["result_digest"], a.data, mapping_text=mapping_text, rules=Rules(), profile=INSIDER_PROFILE, secret=secret)
    print(json.dumps(res, indent=2))
    return 0 if res["ok"] else 1


def cmd_report(a) -> int:
    out = Path(a.out)
    leads = json.loads((out / "leads.json").read_text())
    run = out / "run.json"
    manifest = json.loads(run.read_text())["manifest"] if run.exists() else None
    target = out / "reports"
    target.mkdir(exist_ok=True)
    chosen = leads if a.all else [leads[a.lead - 1]]
    for d in chosen:
        path = target / f"{d['focus'].replace('/', '_')}.html"
        path.write_text(render_case(d, manifest), encoding="utf-8")
        print(path)
    return 0


def cmd_verify(a) -> int:
    res = AuditLog(a.audit).verify()
    print(json.dumps({"ok": res.ok, "entries": res.checked, "head_hash": res.head_hash, "problems": res.problems}, indent=2))
    return 0 if res.ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="toroka-ent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo"); d.add_argument("--out"); d.add_argument("--seed", type=int, default=7); d.add_argument("--style", choices=["A", "B"], help="read a foreign-shaped export through a mapping"); d.set_defaults(fn=cmd_demo)
    s = sub.add_parser("scan"); s.add_argument("--data", required=True); s.add_argument("--out", required=True); s.add_argument("--mapping"); s.set_defaults(fn=cmd_scan)
    v0 = sub.add_parser("validate"); v0.add_argument("--data", required=True); v0.add_argument("--mapping"); v0.add_argument("--json", action="store_true"); v0.add_argument("--out"); v0.set_defaults(fn=cmd_validate)
    dc = sub.add_parser("data-contract"); dc.add_argument("--format", choices=["json", "markdown"], default="markdown"); dc.add_argument("--out"); dc.set_defaults(fn=cmd_data_contract)
    g = sub.add_parser("suggest-mapping"); g.add_argument("--file", required=True); g.add_argument("--feed", required=True); g.add_argument("--delimiter"); g.add_argument("--out"); g.set_defaults(fn=cmd_suggest)
    rp = sub.add_parser("reproduce"); rp.add_argument("--data", required=True); rp.add_argument("--out", required=True); rp.add_argument("--mapping"); rp.set_defaults(fn=cmd_reproduce)
    r2 = sub.add_parser("report"); r2.add_argument("--out", required=True); r2.add_argument("--lead", type=int, default=1); r2.add_argument("--all", action="store_true"); r2.set_defaults(fn=cmd_report)
    v = sub.add_parser("verify-audit"); v.add_argument("--audit", required=True); v.set_defaults(fn=cmd_verify)
    k = sub.add_parser("keygen"); k.set_defaults(fn=lambda _a: print(generate_key().decode()) or 0)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
