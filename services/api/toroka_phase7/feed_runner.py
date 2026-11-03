from __future__ import annotations
from datetime import datetime, timezone
from urllib.parse import urlsplit
from .models import FetchResponse
from .operations_store import OperationsStore
from .indicators import parse_stix_bundle, snapshot_digest

class FeedRunner:
    """Runs a caller-supplied fetcher; intentionally contains no direct networking."""
    def __init__(self, store: OperationsStore, fetcher, *, worker_id: str, commercial_mode: bool = True):
        if not callable(fetcher): raise TypeError("fetcher callback is required")
        self.store=store; self.fetcher=fetcher; self.worker_id=worker_id; self.commercial_mode=commercial_mode

    def run_due_once(self, *, now=None) -> dict:
        outcomes=[]
        for source_id in self.store.list_due(now=now):
            if not self.store.claim(source_id,self.worker_id,now=now):
                outcomes.append({"source_id":source_id,"outcome":"lease_unavailable"}); continue
            policy=self.store.policy(source_id)
            try:
                policy.validate(commercial_mode=self.commercial_mode, now=now)
                response=self.fetcher(policy.endpoint_url, max_bytes=policy.max_response_bytes, timeout_seconds=15)
                if not isinstance(response,FetchResponse): raise TypeError("fetcher must return FetchResponse")
                if response.status_code != 200:
                    retry = None
                    hdr={k.lower():v for k,v in response.headers.items()}
                    if "retry-after" in hdr:
                        try: retry=int(hdr["retry-after"])
                        except Exception: retry=None
                    raise ProviderResponseError(str(response.status_code), retry)
                if not isinstance(response.body,bytes): raise ValueError("provider response body must be bytes")
                if len(response.body)>policy.max_response_bytes: raise ValueError("provider response exceeds policy byte limit")
                requested=urlsplit(policy.endpoint_url).hostname.lower()
                final=urlsplit(response.final_url)
                allowed={h.lower() for h in policy.allowed_hosts}
                if final.scheme!="https" or not final.hostname or final.hostname.lower() not in allowed:
                    raise ValueError("provider response final URL left the approved HTTPS host allowlist")
                if final.username or final.password: raise ValueError("provider final URL contains credentials")
                content_type=next((v.lower() for k,v in response.headers.items() if k.lower()=="content-type"),"")
                if content_type and not any(x in content_type for x in ("json","stix","text/plain","application/octet-stream")):
                    raise ValueError("unexpected provider content type")
                records,warnings=parse_stix_bundle(response.body,source_id=source_id,max_objects=policy.max_indicators)
                digest=snapshot_digest(response.body)
                count=self.store.ingest_success(source_id,self.worker_id,records,digest=digest,now=now)
                outcomes.append({"source_id":source_id,"outcome":"success","records":len(records),"cached_indicators":count,"warnings":warnings[:20],"digest":digest})
            except ProviderResponseError as exc:
                self.store.ingest_failure(source_id,self.worker_id,exc.code,retry_after_seconds=exc.retry_after,now=now)
                outcomes.append({"source_id":source_id,"outcome":"failed","error_code":exc.code})
            except PermissionError:
                self.store.ingest_failure(source_id,self.worker_id,"403",now=now)
                outcomes.append({"source_id":source_id,"outcome":"blocked_by_policy","error_code":"permission_not_confirmed"})
            except TimeoutError:
                self.store.ingest_failure(source_id,self.worker_id,"timeout",now=now)
                outcomes.append({"source_id":source_id,"outcome":"failed","error_code":"timeout"})
            except ValueError as exc:
                self.store.ingest_failure(source_id,self.worker_id,"invalid_payload",now=now)
                outcomes.append({"source_id":source_id,"outcome":"failed","error_code":"invalid_payload","detail":str(exc)[:180]})
            except Exception:
                self.store.ingest_failure(source_id,self.worker_id,"network_error",now=now)
                outcomes.append({"source_id":source_id,"outcome":"failed","error_code":"network_error"})
        return {"processed":len(outcomes),"outcomes":outcomes}

class ProviderResponseError(Exception):
    def __init__(self, code: str, retry_after: int | None = None):
        self.code=code; self.retry_after=retry_after
        super().__init__(code)
