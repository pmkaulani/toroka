from __future__ import annotations
from .feed_runner import FeedRunner
from .multilingual import analyze_message
from .readiness import production_readiness

class Phase7Coordinator:
    """Small orchestration facade for the app's existing investigation pipeline."""
    def __init__(self, *, feed_runner: FeedRunner | None=None, operations_store=None, case_memory=None):
        self.feed_runner=feed_runner; self.operations_store=operations_store; self.case_memory=case_memory

    def refresh_due_feeds(self, *, now=None) -> dict:
        if self.feed_runner is None: return {"processed":0,"outcomes":[],"status":"feed_runner_not_configured"}
        return self.feed_runner.run_due_once(now=now)

    def analyze_text(self, text: str) -> dict:
        return analyze_message(text).to_dict()

    def operational_status(self, *, now=None) -> dict:
        if self.operations_store is None:
            return {"feeds":[],"alerts":[],"status":"operations_store_not_configured"}
        health=self.operations_store.evaluate_health(now=now)
        alerts=self.operations_store.list_alerts()
        states=[h.state for h in health]
        status="critical" if any(s=="circuit_open" for s in states) else "degraded" if any(s in {"stale","degraded","never_succeeded"} for s in states) else "healthy"
        return {"status":status,"feeds":[h.__dict__ if hasattr(h,"__dict__") else {k:getattr(h,k) for k in h.__dataclass_fields__} for h in health],
                "alerts":[a.__dict__ if hasattr(a,"__dict__") else {k:getattr(a,k) for k in a.__dataclass_fields__} for a in alerts]}

    def readiness(self, config): return production_readiness(config)
