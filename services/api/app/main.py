"""Toroka API. Assembly only: behaviour lives in the routers and in packages/rules."""
from __future__ import annotations

import logging
import os
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from ssi_connectors import channels

from . import db as m
from . import pipeline
from .config import Settings
from .deps import Ctx
from .ratelimit import RateLimiter
from .routes_community import router as community
from .routes_core import router as core
from .routes_email import router as email_forensics
from .security import Crypto
from .seed import seed_opportunities, seed_verified

STATIC = os.path.join(os.path.dirname(__file__), "static")


def create_app(settings: Settings | None = None, *, deps: pipeline.Deps | None = None, senders: dict | None = None) -> FastAPI:
    s = (settings or Settings.from_env()).with_dev_keys()
    engine = m.make_engine(s.database_url)
    m.Base.metadata.create_all(engine)          # dev convenience; production uses `alembic upgrade head`
    sm = m.make_sessionmaker(engine)
    if senders is None:
        senders = {}
        if s.whatsapp_token and s.whatsapp_phone_number_id:
            senders["whatsapp"] = channels.WhatsAppSender(s.whatsapp_token, s.whatsapp_phone_number_id)
        if s.at_username and s.at_api_key:
            senders["sms"] = channels.AfricasTalkingSender(s.at_username, s.at_api_key, s.at_shortcode or None)
    app = FastAPI(title="Toroka API", version="0.2.0",
                  description="Evidence-first checks. Results are never accusations and never a guarantee.")
    app.state.ctx = Ctx(s, Crypto(s.encryption_key, s.hmac_key), RateLimiter(), deps or pipeline.build_deps(s), sm, senders)
    with sm() as db:
        seed_opportunities(db)
        seed_verified(db)

    @app.middleware("http")
    async def request_id(request: Request, call_next):
        rid = request.headers.get("x-request-id") or str(uuid.uuid4())
        request.state.request_id = rid
        try:
            response = await call_next(request)
        except Exception:
            logging.getLogger('ssi').exception('unhandled error (request %s)', rid)    # no message text is logged
            response = JSONResponse({"status": "failed_safely", "request_id": rid, "detail": "Something went wrong on our side. Nothing was concluded about your message."}, status_code=500)
        response.headers["X-Request-ID"] = rid
        response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/v1") else response.headers.get("Cache-Control", "no-cache")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; "
                                                       "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        return response

    app.include_router(core)
    app.include_router(email_forensics)
    app.include_router(community)
    try:
        from toroka_evidence.api_contract import router as evidence_router
        app.include_router(evidence_router)
    except Exception as e:
        logging.getLogger("toroka.evidence").warning(f"Could not initialize evidence router: {e}")

    try:
        from .routes_phase5_phase6 import router as phase5_6_router
        app.include_router(phase5_6_router)
    except Exception as e:
        logging.getLogger("toroka.phase5_6").warning(f"Could not initialize phase 5/6 router: {e}")

    try:
        from .routes_phase7 import router as phase7_router
        app.include_router(phase7_router)
    except Exception as e:
        logging.getLogger("toroka.phase7").warning(f"Could not initialize phase 7 router: {e}")

    try:
        from .routes_build3 import router as build3_router
        app.include_router(build3_router)
    except Exception as e:
        logging.getLogger("toroka.build3").warning(f"Could not initialize Build 3 registry router: {e}")

    try:
        from .routes_build4 import router as build4_router
        app.include_router(build4_router)
    except Exception as e:
        logging.getLogger("toroka.build4").warning(f"Could not initialize Build 4 campaign router: {e}")

    # Autonomous ML Worker Daemon
    if os.environ.get("SSI_NO_WORKER") != "1":
        try:
            from ssi_rules.ml.autonomous_orchestrator import AutonomousMLEngine
            engine = AutonomousMLEngine.get_instance()
            if engine.config.auto_train_enabled or engine.config.auto_ingest_enabled:
                engine.start_worker(poll_interval_seconds=60)

            @app.on_event("shutdown")
            def shutdown_autonomous_worker():
                try:
                    engine.stop_worker()
                except Exception:
                    pass
        except Exception as e:
            logging.getLogger("toroka.ml").warning(f"Could not initialize autonomous ML worker: {e}")

    if os.path.isdir(STATIC):
        app.mount("/static", StaticFiles(directory=STATIC), name="static")

        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(os.path.join(STATIC, "index.html"), headers={"Cache-Control": "no-cache"})

        @app.get("/manifest.webmanifest", include_in_schema=False)
        def manifest():
            return FileResponse(os.path.join(STATIC, "manifest.webmanifest"), media_type="application/manifest+json")

        @app.get("/sw.js", include_in_schema=False)
        def sw():
            return FileResponse(os.path.join(STATIC, "sw.js"), media_type="text/javascript", headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"})
    return app


app = create_app() if os.environ.get("SSI_NO_AUTOAPP") != "1" else None
