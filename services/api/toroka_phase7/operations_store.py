from __future__ import annotations
import json, sqlite3, uuid, re
from datetime import datetime, timedelta, timezone
from typing import Iterable
from .models import Indicator, FeedHealth, OperationalAlert
from .policy import FeedPolicy
from .indicators import normalize_indicator


def _dt(value):
    if isinstance(value, datetime):
        d = value
    elif isinstance(value, str):
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        d = datetime.now(timezone.utc)
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)

def _iso(value): return _dt(value).isoformat()

class OperationsStore:
    """SQLite state for feed leases, indicators, run history and deduplicated ops alerts."""
    def __init__(self, db_path: str = ":memory:"):
        self.conn = sqlite3.connect(db_path, timeout=15, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        if db_path != ":memory:":
            self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS feed_state(
          source_id TEXT PRIMARY KEY, policy_json TEXT NOT NULL, enabled INTEGER NOT NULL,
          last_attempt TEXT, last_success TEXT, next_attempt TEXT NOT NULL,
          last_error_code TEXT, consecutive_failures INTEGER NOT NULL DEFAULT 0,
          circuit_open_until TEXT, lease_owner TEXT, lease_until TEXT,
          last_digest TEXT, cached_count INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS indicators(
          source_id TEXT NOT NULL, indicator_type TEXT NOT NULL, value TEXT NOT NULL,
          confidence REAL NOT NULL, labels_json TEXT NOT NULL, observed_at TEXT NOT NULL,
          expires_at TEXT NOT NULL, reference_url TEXT,
          PRIMARY KEY(source_id,indicator_type,value));
        CREATE INDEX IF NOT EXISTS idx_indicators_lookup ON indicators(indicator_type,value,expires_at);
        CREATE TABLE IF NOT EXISTS ingest_runs(
          run_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, started_at TEXT NOT NULL,
          completed_at TEXT, outcome TEXT NOT NULL, received_count INTEGER NOT NULL DEFAULT 0,
          inserted_count INTEGER NOT NULL DEFAULT 0, digest TEXT, error_code TEXT);
        CREATE TABLE IF NOT EXISTS ops_alerts(
          alert_id TEXT PRIMARY KEY, dedupe_key TEXT NOT NULL UNIQUE, source_id TEXT NOT NULL,
          alert_type TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open');
        """)

    def register_policy(self, policy: FeedPolicy, *, commercial_mode: bool = True, enabled: bool = True, now=None) -> None:
        policy.validate(commercial_mode=commercial_mode, now=now)
        stamp = _iso(now)
        payload = json.dumps(policy.__dict__ if hasattr(policy, "__dict__") else {
            name: getattr(policy, name) for name in policy.__dataclass_fields__
        }, sort_keys=True)
        self.conn.execute("""INSERT INTO feed_state(source_id,policy_json,enabled,next_attempt,updated_at)
        VALUES(?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET policy_json=excluded.policy_json,
        enabled=excluded.enabled,updated_at=excluded.updated_at""",
        (policy.source_id, payload, int(enabled), stamp, stamp))

    def policy(self, source_id: str) -> FeedPolicy:
        row = self.conn.execute("SELECT policy_json FROM feed_state WHERE source_id=?", (source_id,)).fetchone()
        if not row: raise KeyError(source_id)
        return FeedPolicy(**json.loads(row[0]))

    def list_due(self, *, now=None) -> list[str]:
        stamp = _iso(now)
        rows = self.conn.execute("""SELECT source_id FROM feed_state WHERE enabled=1 AND next_attempt<=?
          AND (lease_until IS NULL OR lease_until<=?) AND (circuit_open_until IS NULL OR circuit_open_until<=?)
          ORDER BY next_attempt,source_id""", (stamp,stamp,stamp)).fetchall()
        return [r[0] for r in rows]

    def claim(self, source_id: str, worker_id: str, *, now=None, lease_seconds: int = 120) -> bool:
        if not worker_id or len(worker_id) > 128: raise ValueError("invalid worker_id")
        current = _dt(now); stamp = current.isoformat(); until = (current + timedelta(seconds=lease_seconds)).isoformat()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            cur = self.conn.execute("""UPDATE feed_state SET lease_owner=?,lease_until=?,last_attempt=?,updated_at=?
              WHERE source_id=? AND enabled=1 AND next_attempt<=?
              AND (lease_until IS NULL OR lease_until<=?)
              AND (circuit_open_until IS NULL OR circuit_open_until<=?)""",
              (worker_id,until,stamp,stamp,source_id,stamp,stamp,stamp))
            self.conn.execute("COMMIT")
            return cur.rowcount == 1
        except Exception:
            self.conn.execute("ROLLBACK"); raise

    def _release_lease(self, source_id, worker_id):
        self.conn.execute("UPDATE feed_state SET lease_owner=NULL,lease_until=NULL WHERE source_id=? AND lease_owner=?", (source_id,worker_id))

    def ingest_success(self, source_id: str, worker_id: str, records: Iterable[Indicator], *, digest: str, now=None) -> int:
        policy = self.policy(source_id); policy.validate(commercial_mode=True, now=now)
        records = list(records)
        if len(records) > policy.max_indicators: raise ValueError("feed record count exceeds policy")
        prepared = []
        stamp = _iso(now); expiry_default = (_dt(now) + timedelta(seconds=policy.freshness_ttl_seconds)).isoformat()
        for record in records:
            kind = record.indicator_type.lower()
            value = normalize_indicator(kind, record.value)
            if not 0 <= record.confidence <= 1: raise ValueError("indicator confidence must be between 0 and 1")
            expires = _iso(record.valid_until) if record.valid_until else expiry_default
            if _dt(expires) <= _dt(now):
                continue
            labels = json.dumps(list(record.labels)[:10])
            ref = record.reference_url
            if ref:
                from urllib.parse import urlsplit
                parts = urlsplit(ref)
                if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
                    raise ValueError("reference_url must be public HTTPS")
                ref = f"https://{parts.hostname.encode('idna').decode('ascii').lower()}{(parts.path or '/')[:160]}"
            prepared.append((source_id,kind,value,record.confidence,labels,stamp,expires,ref))
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            state = self.conn.execute("SELECT lease_owner,last_digest FROM feed_state WHERE source_id=?",(source_id,)).fetchone()
            if not state or state["lease_owner"] != worker_id: raise PermissionError("worker does not own feed lease")
            if not isinstance(digest,str) or not re.fullmatch(r"[a-f0-9]{64}",digest.lower()):
                raise ValueError("snapshot digest must be a SHA-256 hex string")
            digest=digest.lower()
            run_id = str(uuid.uuid4())
            self.conn.execute("INSERT INTO ingest_runs(run_id,source_id,started_at,completed_at,outcome,received_count,digest) VALUES(?,?,?,?,?,?,?)",
                              (run_id,source_id,stamp,stamp,"success",len(prepared),digest))
            # Always refresh timestamps/expiry even when the provider returns an identical snapshot.
            # The primary key keeps the import idempotent without leaving previously-fresh rows stale.
            self.conn.executemany("""INSERT INTO indicators(source_id,indicator_type,value,confidence,labels_json,observed_at,expires_at,reference_url)
            VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(source_id,indicator_type,value) DO UPDATE SET
            confidence=excluded.confidence,labels_json=excluded.labels_json,observed_at=excluded.observed_at,
            expires_at=excluded.expires_at,reference_url=excluded.reference_url""", prepared)
            count = self.conn.execute("SELECT COUNT(*) FROM indicators WHERE source_id=? AND expires_at>?",(source_id,stamp)).fetchone()[0]
            self.conn.execute("""UPDATE feed_state SET last_success=?,next_attempt=?,last_error_code=NULL,consecutive_failures=0,
              circuit_open_until=NULL,last_digest=?,cached_count=?,lease_owner=NULL,lease_until=NULL,updated_at=? WHERE source_id=?""",
              (stamp,(_dt(now)+timedelta(seconds=policy.poll_interval_seconds)).isoformat(),digest,count,stamp,source_id))
            self.conn.execute("UPDATE ops_alerts SET status='resolved',updated_at=? WHERE source_id=? AND status='open' AND alert_type IN ('feed_stale','feed_circuit_open','feed_provider_error')",(stamp,source_id))
            self.conn.execute("COMMIT")
            return count
        except Exception:
            self.conn.execute("ROLLBACK"); raise

    def ingest_failure(self, source_id: str, worker_id: str, error_code: str, *, retry_after_seconds: int | None = None, now=None) -> None:
        policy = self.policy(source_id); current = _dt(now); stamp = current.isoformat()
        row = self.conn.execute("SELECT consecutive_failures FROM feed_state WHERE source_id=? AND lease_owner=?",(source_id,worker_id)).fetchone()
        if not row: raise PermissionError("worker does not own feed lease")
        failures = int(row[0])+1
        base = min(3600, 30 * (2 ** min(failures-1,7)))
        retry = max(0,min(86400,int(retry_after_seconds))) if retry_after_seconds is not None else base
        circuit_until = (current+timedelta(seconds=policy.circuit_cooldown_seconds)).isoformat() if failures >= policy.max_failures_before_circuit else None
        next_attempt = (current+timedelta(seconds=max(retry, policy.circuit_cooldown_seconds if circuit_until else 0))).isoformat()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.execute("INSERT INTO ingest_runs(run_id,source_id,started_at,completed_at,outcome,error_code) VALUES(?,?,?,?,?,?)",
                              (str(uuid.uuid4()),source_id,stamp,stamp,"failure",str(error_code)[:48]))
            self.conn.execute("""UPDATE feed_state SET next_attempt=?,last_error_code=?,consecutive_failures=?,
              circuit_open_until=?,lease_owner=NULL,lease_until=NULL,updated_at=? WHERE source_id=?""",
              (next_attempt,str(error_code)[:48],failures,circuit_until,stamp,source_id))
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK"); raise
        is_server_error=error_code.isdigit() and 500 <= int(error_code) <= 599
        if error_code in {"401","403","408","429","509","timeout","network_error","invalid_payload"} or is_server_error:
            kind = "feed_provider_error" if error_code not in {"429","509"} else "feed_rate_limited"
            severity = "high" if error_code in {"401","403"} else "medium"
            self.upsert_alert(source_id,kind,severity,f"Provider refresh failed ({error_code}); last known-good data is retained.",now=now)
        if circuit_until:
            self.upsert_alert(source_id,"feed_circuit_open","high","Feed circuit breaker opened after consecutive failures.",now=now)

    def upsert_alert(self, source_id, alert_type, severity, message, *, now=None) -> None:
        stamp = _iso(now); dedupe = f"{source_id}:{alert_type}"
        self.conn.execute("""INSERT INTO ops_alerts(alert_id,dedupe_key,source_id,alert_type,severity,message,created_at,updated_at,status)
        VALUES(?,?,?,?,?,?,?,?, 'open') ON CONFLICT(dedupe_key) DO UPDATE SET severity=excluded.severity,
        message=excluded.message,updated_at=excluded.updated_at,status='open'""",
        (str(uuid.uuid4()),dedupe,source_id,alert_type,severity,message,stamp,stamp))

    def evaluate_health(self, *, now=None) -> list[FeedHealth]:
        current = _dt(now); stamp = current.isoformat(); out=[]
        rows = self.conn.execute("SELECT * FROM feed_state ORDER BY source_id").fetchall()
        for row in rows:
            policy = FeedPolicy(**json.loads(row["policy_json"]))
            age = (current-_dt(row["last_success"])).total_seconds() if row["last_success"] else None
            circuit = row["circuit_open_until"] and _dt(row["circuit_open_until"]) > current
            if not row["enabled"]: state="disabled"
            elif circuit: state="circuit_open"
            elif not row["last_success"]: state="never_succeeded"
            elif age > policy.freshness_ttl_seconds: state="stale"
            elif row["consecutive_failures"]: state="degraded"
            else: state="healthy"
            out.append(FeedHealth(row["source_id"],state,row["last_attempt"],row["last_success"],row["next_attempt"],row["consecutive_failures"],row["cached_count"],row["last_error_code"],row["circuit_open_until"]))
            if state == "stale": self.upsert_alert(row["source_id"],"feed_stale","medium","Threat feed is beyond its configured freshness window.",now=now)
            elif state == "circuit_open": self.upsert_alert(row["source_id"],"feed_circuit_open","high","Feed circuit breaker is open; cached indicators may become stale.",now=now)
            elif state == "never_succeeded" and row["last_attempt"]:
                self.upsert_alert(row["source_id"],"feed_never_succeeded","medium","Feed has been attempted but has never completed a successful refresh.",now=now)
        return out

    def indicator_lookup(self, kind: str, value: str, *, now=None) -> list[dict]:
        normalized = normalize_indicator(kind,value); stamp=_iso(now)
        rows=self.conn.execute("SELECT * FROM indicators WHERE indicator_type=? AND value=? ORDER BY source_id",(kind.lower(),normalized)).fetchall()
        out=[]
        for row in rows:
            feed=self.conn.execute("SELECT policy_json FROM feed_state WHERE source_id=?",(row["source_id"],)).fetchone()
            policy=FeedPolicy(**json.loads(feed[0]))
            expired = row["expires_at"] <= stamp
            out.append({"source_id":row["source_id"],"indicator_type":kind.lower(),"confidence":row["confidence"],"labels":json.loads(row["labels_json"]) if policy.display_allowed else [],"observed_at":row["observed_at"],"expires_at":row["expires_at"],"fresh":not expired,"display_allowed":policy.display_allowed,"attribution":policy.attribution if policy.display_allowed else None,"reference_url":row["reference_url"] if policy.display_allowed else None})
        return out

    def list_alerts(self, *, status="open") -> list[OperationalAlert]:
        rows=self.conn.execute("SELECT * FROM ops_alerts WHERE status=? ORDER BY created_at DESC",(status,)).fetchall()
        return [OperationalAlert(r["alert_id"],r["source_id"],r["alert_type"],r["severity"],r["message"],r["created_at"],r["status"]) for r in rows]

    def acknowledge_alert(self, alert_id: str, *, status: str = "acknowledged", now=None) -> None:
        if status not in {"acknowledged","resolved"}: raise ValueError("invalid alert status")
        cur=self.conn.execute("UPDATE ops_alerts SET status=?,updated_at=? WHERE alert_id=?",(status,_iso(now),alert_id))
        if cur.rowcount != 1: raise KeyError(alert_id)

    def prune_expired_indicators(self, *, now=None) -> int:
        stamp=_iso(now)
        cur=self.conn.execute("DELETE FROM indicators WHERE expires_at<=?",(stamp,))
        for row in self.conn.execute("SELECT source_id FROM feed_state").fetchall():
            count=self.conn.execute("SELECT COUNT(*) FROM indicators WHERE source_id=? AND expires_at>?",(row[0],stamp)).fetchone()[0]
            self.conn.execute("UPDATE feed_state SET cached_count=? WHERE source_id=?",(count,row[0]))
        return cur.rowcount

    def export_to_phase4(self, source_id: str, intel_store, *, phase4_source_name: str, now=None) -> int:
        """Bridge current cache rows into an already-registered Phase 4 ThreatIntelStore."""
        source_policy=self.policy(source_id)  # ensure the source exists in Phase 7's permission registry
        source_policy.validate(commercial_mode=True, now=now)
        if not source_policy.display_allowed:
            raise PermissionError("source policy does not allow end-user display; keep the indicator in the internal-only cache")
        try:
            from toroka_phase4.intel import IndicatorRecord
        except ImportError as exc:
            raise RuntimeError("toroka_phase4 is not installed; add the Phase 4 package to PYTHONPATH") from exc
        rows=self.conn.execute("SELECT * FROM indicators WHERE source_id=? AND expires_at>?",(source_id,_iso(now))).fetchall()
        records=[IndicatorRecord(indicator_type=r["indicator_type"],value=r["value"],source_name=phase4_source_name,
            confidence=r["confidence"],first_seen=r["observed_at"],valid_until=r["expires_at"],
            labels=tuple(json.loads(r["labels_json"])),reference_url=r["reference_url"]) for r in rows]
        imported=intel_store.import_records(records,phase4_source_name)
        intel_store.mark_refresh(phase4_source_name,success=True)
        return imported

    def metrics_snapshot(self, *, now=None) -> dict:
        health=self.evaluate_health(now=now)
        states={}
        for item in health: states[item.state]=states.get(item.state,0)+1
        stamp=(_dt(now)-timedelta(hours=24)).isoformat()
        failures=self.conn.execute("SELECT COUNT(*) FROM ingest_runs WHERE outcome='failure' AND started_at>=?",(stamp,)).fetchone()[0]
        active_indicators=self.conn.execute("SELECT COUNT(*) FROM indicators WHERE expires_at>?",(_iso(now),)).fetchone()[0]
        open_alerts=self.conn.execute("SELECT COUNT(*) FROM ops_alerts WHERE status='open'").fetchone()[0]
        return {"feeds_total":len(health),"feeds_by_state":states,"active_indicators":active_indicators,
                "open_alerts":open_alerts,"feed_failures_24h":failures,
                "privacy_note":"Metrics contain aggregate counts only; do not add case IDs, URLs, phone numbers or customer data as metric labels."}

    def close(self) -> None:
        self.conn.close()
