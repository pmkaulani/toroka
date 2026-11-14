"""Suggest a mapping from an unfamiliar export. SUGGESTIONS ONLY: a human confirms every line before it is used.

Heuristics (header-name similarity, timestamp-format probing, keyword matching on action codes) cut the time to a first draft;
they do not replace reading the bank's data dictionary. Ambiguity (e.g. day/month order) is flagged, never silently resolved.
"""
from __future__ import annotations

import csv
import difflib
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

from .ingest import SPEC
from .mapping import OPTIONAL, TS_COLUMNS

SYNONYMS = {
    "ts": ["timestamp", "datetime", "epoch", "unixtime", "stamp", "when", "eventtime", "trandatetime", "txndate", "date", "time", "created", "recvts", "opened", "received", "postts", "pmtts"],
    "account_id": ["userid", "usrid", "user", "operator", "maker", "login", "username", "userref", "enteredby"],
    "action": ["trancode", "txncode", "action", "eventtype", "optype", "function", "activity", "transtype", "event"],
    "customer_id": ["cif", "cifno", "custno", "customerid", "clientno", "client", "cust", "customer", "accountholder", "party"],
    "approver_account_id": ["authby", "approvedby", "verifiedby", "checker", "authorizer", "authoriser", "approver", "supervisor"],
    "staff_id": ["empno", "employeeid", "staffno", "staff", "emp", "pfno", "handler", "handleremp", "rm"],
    "status": ["status", "statuscd", "empstatus", "userstatus", "state"],
    "role": ["role", "jobtitle", "designation", "position", "grade"],
    "branch": ["branch", "branchcode", "sol", "solid", "outlet", "location"],
    "end_date": ["exitdate", "enddate", "terminationdate", "leavingdate", "separation"],
    "salary_account": ["payrollacct", "salaryaccount", "salaryacct", "bankaccount", "payacct"],
    "account_id#sys": ["userid", "usrid", "loginid", "username"],
    "system": ["module", "system", "application", "app", "platform"],
    "is_privileged": ["privflag", "privileged", "admin", "isadmin", "superuser"],
    "request_id": ["ticketno", "ticket", "caseno", "requestid", "reference"],
    "opened_at": ["created", "opened", "opendate", "logged"], "closed_at": ["closed", "closedate", "resolved"],
    "kind": ["category", "type", "kind", "instrtype", "tickettype"],
    "instruction_id": ["instrref", "instructionid", "instrno", "ref"], "received_at": ["recvts", "received", "receiveddate", "instrdate"],
    "payment_id": ["pmtref", "paymentid", "txnref", "reference"], "channel": ["chan", "channel", "medium"], "amount": ["amt", "amount", "value"],
    "beneficiary": ["benefacct", "beneficiary", "payee", "creditacct", "destacct"],
    "dormant_since": ["dormantdt", "dormantsince", "dormantdate"], "deceased_flag": ["deceasedflg", "deceased", "dod"],
    "is_sensitive": ["vipflg", "vip", "sensitive", "pep", "staffflag"],
    "posting_id": ["postid", "postingid", "jrnno", "voucher"], "ledger": ["glcode", "ledger", "glaccount", "account"],
    "counter_party": ["contra", "counterparty", "counteracct", "beneficiary"], "entered_by_account": ["maker", "enteredby", "createdby", "userid"],
    "approved_by_account": ["checker", "approvedby", "authby", "verifiedby"], "manual": ["manualflg", "manual", "ismanual", "manualentry"],
    "narrative": ["narrcd", "narrative", "description", "narr", "particulars"],
}
FORMATS = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d/%m/%Y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%d-%m-%Y %H:%M:%S", "%d/%m/%Y %H:%M",
           "%d-%b-%Y %H:%M:%S", "%Y%m%d%H%M%S", "%d/%m/%Y", "%Y-%m-%d"]
ACTION_RULES = [("contact_change", r"(MOB|PHONE|CONTACT|MSISDN|SMS)", r"(CHG|CHANGE|UPD|UPDATE|MOD|AMEND)"),
                ("card_issue", r"CARD|CRD", r"(ISS|NEW|ADD|REQ|ORDER)"), ("beneficiary_add", r"(BENEF|PAYEE|\bBEN\b|BEN[_.\-])", r"(ADD|NEW|CREATE|REG)"),
                ("account_reactivate", r"(REACT|ACTIVAT|UNDORM|UN-DORM)", r""), ("limit_change", r"LIMIT|LMT", r"(CHG|CHANGE|UPD|INCR|SET)"),
                ("profile_view", r"(VIEW|ENQ|INQ|QUERY|SEARCH|DISPLAY|BROWSE)", r"")]


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _score(canon: str, header: str, feed: str) -> float:
    h, c = _norm(header), _norm(canon)
    if h == c:
        return 1.0
    best = max((1.0 if h == s else (0.8 if (s in h or h in s) and min(len(s), len(h)) >= 3 else 0.0) for s in SYNONYMS.get(canon, [])), default=0.0)
    return max(best, 0.6 * difflib.SequenceMatcher(None, h, c).ratio())


def _probe_format(values: list[str]) -> tuple[str, list[str]]:
    vals = [v for v in values if v][:60]
    if vals and all(re.fullmatch(r"\d{10}", v) for v in vals):
        return "epoch_s", []
    if vals and all(re.fullmatch(r"\d{13}", v) for v in vals):
        return "epoch_ms", []
    ok = []
    for f in FORMATS:
        try:
            for v in vals:
                datetime.strptime(v, f)
            ok.append(f)
        except ValueError:
            continue
    if vals and all(re.match(r"\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d[+-]\d\d:\d\d$|.*Z$", v) for v in vals):
        return "iso", []
    flags = []
    if "%d/%m/%Y %H:%M:%S" in ok and "%m/%d/%Y %H:%M:%S" in ok or ("%d/%m/%Y" in ok and "%m/%d/%Y" in ok):
        flags.append("day/month order is AMBIGUOUS in the sample: confirm with the bank (defaulted to day first)")
    return (ok[0] if ok else "iso"), flags


def suggest_mapping(path: str | Path, feed: str, delimiter: str | None = None) -> tuple[str, dict]:
    if feed not in SPEC:
        raise ValueError(f"unknown feed {feed}")
    path = Path(path)
    sample = path.read_text(encoding="utf-8-sig", errors="replace")[:20000]
    if delimiter:
        delim = delimiter
    else:
        try:
            delim = csv.Sniffer().sniff(sample.splitlines()[0] + "\n", delimiters=",|\t;").delimiter if sample else ","
        except Exception:
            delim = "," 
    with path.open(newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.DictReader(fh, delimiter=delim)
        headers = list(reader.fieldnames or [])
        rows = [r for _, r in zip(range(2000), reader)]
    picks: dict[str, tuple[str, float]] = {}
    scored = sorted(((_score(c, h, feed), c, h) for c in SPEC[feed] for h in headers), reverse=True)
    used_h: set[str] = set()
    for sc, c, h in scored:
        if sc >= 0.55 and c not in picks and h not in used_h:
            picks[c] = (h, sc)
            used_h.add(h)
    flags, unmatched = [], [c for c in SPEC[feed] if c not in picks]
    ts_fmt = "iso"
    for c in TS_COLUMNS.get(feed, ()):
        if c in picks:
            ts_fmt, fl = _probe_format([(r.get(picks[c][0]) or "").strip() for r in rows])
            flags += fl
            break
    lines = [f"# DRAFT for feed '{feed}' from {path.name}. Every line is a SUGGESTION: confirm against the bank's data dictionary.",
             "naive_tz_offset_hours = 3   # timestamps without a UTC offset are read as East Africa Time", "",
             f"[feeds.{feed}]", f"file = {json.dumps(path.name)}", f"delimiter = {json.dumps(delim)}", f'timestamp_format = {json.dumps(ts_fmt)}', "",
             f"[feeds.{feed}.columns]"]
    for c in SPEC[feed]:
        if c in picks:
            lines.append(f"{c} = {json.dumps(picks[c][0])}   # confidence {picks[c][1]:.2f}")
        else:
            tag = "optional: detectors depending on it will stand down" if c in OPTIONAL.get(feed, set()) else "REQUIRED: no match found, map by hand"
            lines.append(f"# {c} = ???   # {tag}")
    unmapped_codes: list[str] = []
    if feed == "audit_log" and "action" in picks:
        # Rare-but-critical codes (e.g. a single beneficiary-add) never show up in a head-of-file sample, so count the whole file.
        counts: Counter = Counter()
        with path.open(newline="", encoding="utf-8-sig", errors="replace") as fh2:
            for r in csv.DictReader(fh2, delimiter=delim):
                counts[(r.get(picks["action"][0]) or "").strip()] += 1
        found: dict[str, str] = {}
        for code, _n in counts.most_common(60):
            up = code.upper()
            for canon, a, b in ACTION_RULES:
                if re.search(a, up) and (not b or re.search(b, up)):
                    found[code] = canon
                    break
            else:
                unmapped_codes.append(code)
        lines += ["", f"[feeds.{feed}.values.action]   # SUGGESTED from code text only"] + [f"{json.dumps(k)} = {json.dumps(v)}" for k, v in found.items()]
        if unmapped_codes:
            lines.append("# codes with no suggestion (extend if any are relevant): " + ", ".join(unmapped_codes[:25]))
    report = {"delimiter": delim, "matched": {c: {"source": h, "confidence": round(s, 2)} for c, (h, s) in picks.items()},
              "unmatched": unmatched, "timestamp_format": ts_fmt, "flags": flags, "rows_sampled": len(rows)}
    return "\n".join(lines) + "\n", report
