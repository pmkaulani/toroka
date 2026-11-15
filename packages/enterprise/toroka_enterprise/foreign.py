"""Re-shape canonical extracts into deliberately foreign exports (two invented styles) + the mapping that reads them back.

Used to PROVE the mapping layer: the same underlying data, exported with different delimiters, headers, date formats, epoch timestamps,
status codes and boolean flags, must yield identical findings. The styles are invented; real exports will differ and need a human-confirmed mapping.
"""
from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from .ingest import SPEC
from .mapping import TS_COLUMNS
from .schema import EAT

BOOL_COLS = {("system_accounts", "is_privileged"), ("customers", "deceased_flag"), ("customers", "is_sensitive"), ("postings", "manual")}

STYLES = {
    "A": {
        "delimiter": "|", "ts": "%d/%m/%Y %H:%M:%S", "bool": ("Y", "N"),
        "files": {"audit_log": "AUDIT_TRAIL_2026Q2.txt", "system_accounts": "USERS_MASTER.txt", "hr_roster": "HR_MASTER.txt", "portfolio": "RM_ASSIGNMENTS.txt",
                  "service_requests": "CRM_TICKETS.txt", "instructions": "CUSTOMER_INSTRUCTIONS.txt", "payments": "PAYMENTS_FEED.txt",
                  "customers": "CUSTOMER_MASTER.txt", "postings": "GL_JOURNALS.txt"},
        "cols": {
            "audit_log": {"ts": "TRAN_DATE_TIME", "account_id": "USR_ID", "action": "TRAN_CODE", "customer_id": "CIF_NO", "approver_account_id": "AUTH_BY"},
            "system_accounts": {"account_id": "USER_ID", "staff_id": "EMP_NO", "system": "MODULE", "status": "USER_STATUS", "is_privileged": "PRIV_FLAG"},
            "hr_roster": {"staff_id": "EMP_NO", "status": "EMP_STATUS", "role": "JOB_TITLE", "branch": "BRANCH_CODE", "end_date": "EXIT_DATE", "salary_account": "PAYROLL_ACCT"},
            "portfolio": {"staff_id": "EMP_NO", "customer_id": "CIF_NO"},
            "service_requests": {"request_id": "TICKET_NO", "customer_id": "CIF_NO", "staff_id": "HANDLER_EMP", "opened_at": "CREATED", "closed_at": "CLOSED", "kind": "CATEGORY"},
            "instructions": {"instruction_id": "INSTR_REF", "customer_id": "CIF_NO", "kind": "INSTR_TYPE", "received_at": "RECV_TS", "recorded_at": "ENTRY_TS"},
            "payments": {"payment_id": "PMT_REF", "ts": "PMT_TS", "customer_id": "CIF_NO", "channel": "CHAN", "amount": "AMT", "beneficiary": "BENEF_ACCT", "direction": "DIR"},
            "customers": {"customer_id": "CIF_NO", "status": "STATUS_CD", "dormant_since": "DORMANT_DT", "deceased_flag": "DECEASED_FLG", "is_sensitive": "VIP_FLG"},
            "postings": {"posting_id": "POST_ID", "ts": "POST_TS", "ledger": "GL_CODE", "counter_party": "CONTRA", "amount": "AMT", "entered_by_account": "MAKER",
                         "approved_by_account": "CHECKER", "manual": "MANUAL_FLG", "narrative": "NARR_CD"}},
        "codes": {
            ("audit_log", "action"): {"profile_view": "ENQ01", "contact_change": "CUS-MOB-CHG", "card_issue": "CARD_NEW", "beneficiary_add": "BEN_REG", "limit_change": "LMT_UPD", "account_reactivate": "ACCT_UNDORM"},
            ("system_accounts", "system"): {"core_banking": "CBS"}, ("system_accounts", "status"): {"active": "A", "disabled": "D"},
            ("hr_roster", "status"): {"active": "ACTIVE", "terminated": "LEFT"}, ("service_requests", "kind"): {"service": "SRV", "dispute": "DSP"},
            ("instructions", "kind"): {"contact_change": "MOBCHG", "card_issue": "CRDREQ", "reactivation": "REACT"},
            ("payments", "channel"): {"atm": "ATM", "mobile": "MPESA", "rtgs": "RTGS"},
            ("payments", "direction"): {"debit": "DR", "credit": "CR", "unknown": "UNK"},
            ("customers", "status"): {"active": "A", "dormant": "D", "closed": "C"},
            ("postings", "ledger"): {"SUSPENSE": "GL4100", "DISPUTE": "GL4200", "PAYROLL": "GL7000"},
            ("postings", "narrative"): {"SALARY": "SAL", "DISPUTE_REFUND": "DSPREF", "OTHER": "OTH"}},
    },
    "B": {
        "delimiter": "\t", "ts": "epoch_s", "bool": ("1", "0"),
        "files": {k: f"{k}_export.tsv" for k in SPEC},
        "cols": {
            "audit_log": {"ts": "event_epoch", "account_id": "operator", "action": "op_type", "customer_id": "client_no", "approver_account_id": "approved_by"},
            "system_accounts": {"account_id": "login", "staff_id": "employee_ref", "system": "app", "status": "state", "is_privileged": "is_admin"},
            "hr_roster": {"staff_id": "employee_ref", "status": "employment_state", "role": "title", "branch": "branch_cd", "end_date": "left_on", "salary_account": "pay_account"},
            "portfolio": {"staff_id": "employee_ref", "customer_id": "client_no"},
            "service_requests": {"request_id": "case_ref", "customer_id": "client_no", "staff_id": "owner_emp", "opened_at": "opened_epoch", "closed_at": "closed_epoch", "kind": "case_type"},
            "instructions": {"instruction_id": "instr_no", "customer_id": "client_no", "kind": "instr_kind", "received_at": "received_epoch", "recorded_at": "entered_epoch"},
            "payments": {"payment_id": "txn_ref", "ts": "txn_epoch", "customer_id": "client_no", "channel": "medium", "amount": "value", "beneficiary": "dest_account", "direction": "txn_type"},
            "customers": {"customer_id": "client_no", "status": "acct_state", "dormant_since": "dormant_epoch", "deceased_flag": "deceased", "is_sensitive": "vip"},
            "postings": {"posting_id": "jrn_no", "ts": "jrn_epoch", "ledger": "ledger_code", "counter_party": "contra_acct", "amount": "value", "entered_by_account": "entered_by",
                         "approved_by_account": "authorised_by", "manual": "manual_entry", "narrative": "description"}},
        "codes": {
            ("audit_log", "action"): {"profile_view": "customer.view", "contact_change": "customer.update.phone", "card_issue": "card.issue", "beneficiary_add": "payee.create", "limit_change": "limit.update", "account_reactivate": "account.undormant"},
            ("system_accounts", "system"): {"core_banking": "cbs-prod"}, ("system_accounts", "status"): {"active": "enabled", "disabled": "locked"},
            ("hr_roster", "status"): {"active": "employed", "terminated": "exited"}, ("service_requests", "kind"): {"service": "general", "dispute": "dispute"},
            ("instructions", "kind"): {"contact_change": "phone_update", "card_issue": "card_request", "reactivation": "undormant_request"},
            ("payments", "channel"): {"atm": "atm", "mobile": "mobile_money", "rtgs": "rtgs"},
            ("payments", "direction"): {"debit": "outbound", "credit": "inbound", "unknown": "unknown"},
            ("customers", "status"): {"active": "open", "dormant": "inactive", "closed": "closed"},
            ("postings", "ledger"): {"SUSPENSE": "SUSP-01", "DISPUTE": "DISP-01", "PAYROLL": "PAY-01"},
            ("postings", "narrative"): {"SALARY": "salary", "DISPUTE_REFUND": "dispute refund", "OTHER": "other"}},
    },
}


def _fmt(iso: str, fmt: str) -> str:
    if not iso:
        return ""
    dt = datetime.fromisoformat(iso)
    return str(int(dt.timestamp())) if fmt == "epoch_s" else dt.astimezone(EAT).strftime(fmt)


def export(src_dir: str | Path, out_dir: str | Path, style: str) -> str:
    """Write the foreign-shaped files and return the TOML mapping that reads them."""
    st, src, out = STYLES[style], Path(src_dir), Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    t, f = st["bool"]
    for feed, fname in st["files"].items():
        with (src / f"{feed}.csv").open(newline="", encoding="utf-8") as fh, (out / fname).open("w", newline="", encoding="utf-8") as oh:
            w = csv.writer(oh, delimiter=st["delimiter"])
            w.writerow([st["cols"][feed][c] for c in SPEC[feed]])
            for row in csv.DictReader(fh):
                vals = []
                for c in SPEC[feed]:
                    v = row[c]
                    if (feed, c) in st["codes"] and v:
                        v = st["codes"][(feed, c)][v]
                    elif (feed, c) in BOOL_COLS:
                        v = t if v == "true" else f
                    elif c in TS_COLUMNS.get(feed, ()):
                        v = _fmt(v, st["ts"])
                    vals.append(v)
                w.writerow(vals)
    return mapping_toml(style)


def mapping_toml(style: str) -> str:
    st = STYLES[style]
    t, f = st["bool"]
    lines = ["naive_tz_offset_hours = 3", ""]
    for feed in SPEC:
        lines += [f"[feeds.{feed}]", f"file = {json.dumps(st['files'][feed])}", f"delimiter = {json.dumps(st['delimiter'])}"]
        if TS_COLUMNS.get(feed):
            lines.append(f"timestamp_format = {json.dumps(st['ts'])}")
        lines += ["", f"[feeds.{feed}.columns]"] + [f"{c} = {json.dumps(st['cols'][feed][c])}" for c in SPEC[feed]] + [""]
        for (fd, col), m in st["codes"].items():
            if fd == feed:
                lines += [f"[feeds.{feed}.values.{col}]"] + [f"{json.dumps(src)} = {json.dumps(canon)}" for canon, src in m.items()] + [""]
        for (fd, col) in sorted(BOOL_COLS):
            if fd == feed:
                lines += [f"[feeds.{feed}.values.{col}]", f"{json.dumps(t)} = \"true\"", f"{json.dumps(f)} = \"false\"", ""]
    return "\n".join(lines)
