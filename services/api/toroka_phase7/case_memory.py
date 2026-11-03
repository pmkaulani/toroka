from __future__ import annotations
import hashlib, hmac, json, re, sqlite3, uuid, ipaddress
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

_ALLOWED_ENTITY_TYPES={"domain","url","phone_ke","account_handle","sha256"}
_ALLOWED_SOURCE_FAMILIES={"official_registry","external_threat_feed","public_web_observation","platform_authorized_api","user_report","merchant_supplied","payment_provider_authorized"}
_ALLOWED_REVIEW_STATES={"pending","corroborated_indicator","not_corroborated","corrected","withdrawn"}
_ALLOWED_CORRECTION_CODES={"wrong_entity_match","outdated_information","source_retracted","identity_mismatch","insufficient_evidence","other"}


def _utc(value=None):
    if value is None: d=datetime.now(timezone.utc)
    elif isinstance(value,datetime): d=value
    else: d=datetime.fromisoformat(str(value).replace("Z","+00:00"))
    if d.tzinfo is None: d=d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc)

def _safe_case_ref(value):
    if not isinstance(value,str) or not re.fullmatch(r"[A-Za-z0-9_-]{8,80}",value):
        raise ValueError("case_ref must be an opaque 8-80 character identifier")
    return value

def normalize_entity(entity_type: str, value: str) -> str:
    if entity_type not in _ALLOWED_ENTITY_TYPES or not isinstance(value,str) or not value.strip():
        raise ValueError("unsupported entity type or empty value")
    raw=value.strip()
    if entity_type=="domain":
        candidate=raw if "://" in raw else "https://"+raw
        parts=urlsplit(candidate)
        if not parts.hostname or parts.username or parts.password: raise ValueError("invalid domain")
        host=parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        if "." not in host or host in {"localhost","127.0.0.1"} or host.endswith((".local",".internal",".test",".invalid")): raise ValueError("non-public domain")
        try: ipaddress.ip_address(host)
        except ValueError: pass
        else: raise ValueError("domain must be a DNS hostname, not an IP literal")
        return host
    if entity_type=="url":
        parts=urlsplit(raw)
        if parts.scheme not in {"http","https"} or not parts.hostname or parts.username or parts.password: raise ValueError("invalid URL")
        host=parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        # Memory intentionally reduces URLs to origin; do not retain a private path/query.
        if host in {"localhost","127.0.0.1"} or host.endswith((".local",".internal",".test",".invalid")): raise ValueError("non-public URL")
        return f"{parts.scheme.lower()}://{host}"
    if entity_type=="phone_ke":
        digits=re.sub(r"\D","",raw)
        if digits.startswith("+254"): digits=digits[1:]
        if digits.startswith("254") and len(digits)==12: return digits
        if digits.startswith("0") and len(digits)==10: return "254"+digits[1:]
        if len(digits)==9 and digits[0] in "17": return "254"+digits
        raise ValueError("invalid Kenyan mobile number")
    if entity_type=="account_handle":
        handle=raw.lstrip("@").lower()
        if not re.fullmatch(r"[a-z0-9._-]{2,64}",handle): raise ValueError("invalid account handle")
        return handle
    if entity_type=="sha256":
        digest=raw.lower()
        if not re.fullmatch(r"[a-f0-9]{64}",digest): raise ValueError("invalid SHA-256")
        return digest
    raise ValueError("unsupported entity type")

class CaseMemoryStore:
    """Private-by-default, correction-capable entity memory. Stores keyed fingerprints only."""
    def __init__(self, db_path=":memory:", *, secret: bytes, retention_days: int=180):
        if not isinstance(secret,bytes) or len(secret)<32: raise ValueError("memory secret must be at least 32 bytes")
        if not 1<=retention_days<=3650: raise ValueError("retention_days out of range")
        self.secret=secret; self.retention_days=retention_days
        self.conn=sqlite3.connect(db_path,timeout=15,isolation_level=None,check_same_thread=False)
        self.conn.row_factory=sqlite3.Row
        if db_path != ":memory:": self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript("""
        CREATE TABLE IF NOT EXISTS memory_records(
          record_id TEXT PRIMARY KEY, case_ref TEXT NOT NULL, entity_type TEXT NOT NULL,
          entity_hmac TEXT NOT NULL, source_family TEXT NOT NULL, evidence_ref_hash TEXT NOT NULL,
          review_state TEXT NOT NULL, authoritative_source INTEGER NOT NULL DEFAULT 0,
          confidence REAL NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
          correction_state TEXT NOT NULL DEFAULT 'none', active INTEGER NOT NULL DEFAULT 1);
        CREATE INDEX IF NOT EXISTS idx_memory_entity ON memory_records(entity_type,entity_hmac,active,expires_at);
        CREATE TABLE IF NOT EXISTS memory_audit(
          audit_id TEXT PRIMARY KEY, record_id TEXT NOT NULL, action TEXT NOT NULL,
          actor_role TEXT NOT NULL, code TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS correction_requests(
          request_id TEXT PRIMARY KEY, record_id TEXT NOT NULL, request_code TEXT NOT NULL,
          status TEXT NOT NULL, created_at TEXT NOT NULL, resolved_at TEXT, resolution_code TEXT);
        """)

    def _fingerprint(self, entity_type, normalized):
        # Match the existing Phase 3 EntityLinkGraph digest contract so the same
        # secret links entity memory without storing raw identifiers.
        compatible_type=entity_type
        compatible_value=normalized
        if entity_type == "phone_ke":
            compatible_type="phone"
            compatible_value="+" + normalized
        elif entity_type == "account_handle":
            compatible_type="social_handle"
        elif entity_type == "url":
            compatible_type="domain"
            compatible_value=urlsplit(normalized).hostname or normalized
        elif entity_type == "sha256":
            compatible_type="other"
        return hmac.new(self.secret,f"toroka-v3:{compatible_type}:{compatible_value}".encode(),hashlib.sha256).hexdigest()

    def add_observation(self, *, case_ref: str, entity_type: str, value: str, source_family: str,
                        evidence_ref: str, confidence: float=0.5, authoritative_source: bool=False, now=None) -> str:
        case_ref=_safe_case_ref(case_ref)
        if source_family not in _ALLOWED_SOURCE_FAMILIES: raise ValueError("unsupported source family")
        if not isinstance(evidence_ref,str) or not re.fullmatch(r"[A-Za-z0-9_-]{6,100}",evidence_ref): raise ValueError("evidence_ref must be opaque")
        if not 0<=confidence<=1: raise ValueError("confidence out of range")
        if authoritative_source and source_family not in {"official_registry","external_threat_feed","payment_provider_authorized"}:
            raise ValueError("this source family cannot be marked authoritative")
        normalized=normalize_entity(entity_type,value)
        token=self._fingerprint(entity_type,normalized)
        current=_utc(now); stamp=current.isoformat(); expires=(current+timedelta(days=self.retention_days)).isoformat()
        record_id=str(uuid.uuid4())
        ref_hash=hashlib.sha256(evidence_ref.encode()).hexdigest()
        self.conn.execute("""INSERT INTO memory_records(record_id,case_ref,entity_type,entity_hmac,source_family,evidence_ref_hash,review_state,authoritative_source,confidence,created_at,expires_at)
        VALUES(?,?,?,?,?,?,'pending',?,?,?,?)""",
        (record_id,case_ref,entity_type,token,source_family,ref_hash,int(authoritative_source),confidence,stamp,expires))
        self._audit(record_id,"observation_added","system","private_by_default",now=current)
        return record_id

    def _audit(self, record_id, action, actor_role, code, now=None):
        self.conn.execute("INSERT INTO memory_audit VALUES(?,?,?,?,?,?)",(str(uuid.uuid4()),record_id,action,actor_role,code,_utc(now).isoformat()))

    def moderate(self, record_id: str, *, review_state: str, actor_role: str, reason_code: str, now=None) -> None:
        if actor_role not in {"moderator","admin"}: raise PermissionError("moderator/admin role required")
        if review_state not in _ALLOWED_REVIEW_STATES-{"pending"}: raise ValueError("invalid review state")
        if reason_code not in {"corroborated_by_independent_sources","authoritative_feed_match","not_supported","duplicate","withdrawn_by_reporter","correction_accepted"}:
            raise ValueError("invalid moderation reason code")
        row=self.conn.execute("SELECT * FROM memory_records WHERE record_id=? AND active=1",(record_id,)).fetchone()
        if not row: raise KeyError(record_id)
        if review_state=="corroborated_indicator":
            distinct=self.conn.execute("SELECT COUNT(DISTINCT source_family) FROM memory_records WHERE entity_type=? AND entity_hmac=? AND active=1 AND expires_at>? AND review_state IN ('pending','corroborated_indicator')",
                (row["entity_type"],row["entity_hmac"],_utc(now).isoformat())).fetchone()[0]
            if not row["authoritative_source"] and distinct<2:
                raise ValueError("corroboration requires an authoritative source or two independent source families")
            if reason_code not in {"corroborated_by_independent_sources","authoritative_feed_match"}:
                raise ValueError("corroboration reason does not match review state")
        self.conn.execute("UPDATE memory_records SET review_state=? WHERE record_id=?",(review_state,record_id))
        self._audit(record_id,"moderated",actor_role,reason_code,now)

    def lookup(self, *, entity_type: str, value: str, now=None) -> dict:
        normalized=normalize_entity(entity_type,value); token=self._fingerprint(entity_type,normalized); stamp=_utc(now).isoformat()
        rows=self.conn.execute("""SELECT review_state,source_family,confidence,created_at,expires_at,authoritative_source,correction_state
          FROM memory_records WHERE entity_type=? AND entity_hmac=? AND active=1 AND expires_at>? AND review_state='corroborated_indicator' AND correction_state NOT IN ('accepted','requested') ORDER BY created_at DESC""",
          (entity_type,token,stamp)).fetchall()
        # Pending/unreviewed community submissions are intentionally invisible to lookup callers.
        return {
            "matched":bool(rows), "corroborated_indicator_history":bool(rows),
            "corroborated_observations":len(rows),
            "source_families":sorted({r["source_family"] for r in rows}),
            "latest_observation":rows[0]["created_at"] if rows else None,
            "limitations":["Memory contains scoped observations, not a legal finding or proof of seller identity.","Pending and unreviewed reports are private and are not exposed by lookup.","A match on one identifier does not establish common ownership of related accounts."],
        }

    def request_correction(self, record_id: str, *, request_code: str, now=None) -> str:
        if request_code not in _ALLOWED_CORRECTION_CODES: raise ValueError("invalid correction code")
        row=self.conn.execute("SELECT record_id FROM memory_records WHERE record_id=? AND active=1",(record_id,)).fetchone()
        if not row: raise KeyError(record_id)
        request_id=str(uuid.uuid4()); stamp=_utc(now).isoformat()
        self.conn.execute("INSERT INTO correction_requests VALUES(?,?,?,'open',?,NULL,NULL)",(request_id,record_id,request_code,stamp))
        self.conn.execute("UPDATE memory_records SET correction_state='requested' WHERE record_id=?",(record_id,))
        self._audit(record_id,"correction_requested","data_subject",request_code,now)
        return request_id

    def resolve_correction(self, request_id: str, *, resolution: str, actor_role: str, resolution_code: str, now=None) -> None:
        if actor_role not in {"moderator","admin","privacy_officer"}: raise PermissionError("authorized reviewer role required")
        if resolution not in {"accepted","rejected"}: raise ValueError("resolution must be accepted or rejected")
        if resolution_code not in {"record_withdrawn","record_corrected_outside_memory","insufficient_basis","duplicate_request","source_rechecked"}: raise ValueError("invalid resolution code")
        row=self.conn.execute("SELECT * FROM correction_requests WHERE request_id=? AND status='open'",(request_id,)).fetchone()
        if not row: raise KeyError(request_id)
        stamp=_utc(now).isoformat()
        self.conn.execute("UPDATE correction_requests SET status=?,resolved_at=?,resolution_code=? WHERE request_id=?",(resolution,stamp,resolution_code,request_id))
        if resolution=="accepted":
            self.conn.execute("UPDATE memory_records SET active=0,review_state='corrected',correction_state='accepted' WHERE record_id=?",(row["record_id"],))
        else:
            self.conn.execute("UPDATE memory_records SET correction_state='rejected' WHERE record_id=?",(row["record_id"],))
        self._audit(row["record_id"],"correction_resolved",actor_role,resolution_code,now)

    def purge_expired(self, *, now=None) -> int:
        stamp=_utc(now).isoformat()
        rows=self.conn.execute("SELECT record_id FROM memory_records WHERE expires_at<=?",(stamp,)).fetchall()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.executemany("DELETE FROM memory_audit WHERE record_id=?",[(r[0],) for r in rows])
            self.conn.executemany("DELETE FROM correction_requests WHERE record_id=?",[(r[0],) for r in rows])
            self.conn.execute("DELETE FROM memory_records WHERE expires_at<=?",(stamp,))
            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK"); raise
        return len(rows)


    def close(self) -> None:
        self.conn.close()
