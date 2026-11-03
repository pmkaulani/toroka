from __future__ import annotations

import os
import secrets
import warnings
from dataclasses import dataclass, field

from cryptography.fernet import Fernet


@dataclass
class Settings:
    env: str = "dev"
    database_url: str = "sqlite:///./ssi.db"
    encryption_key: str = ""
    hmac_key: str = ""
    diagnostics_api_key: str = ""  # Optional, dedicated key for system diagnostics; never reuse HMAC_KEY.
    storage_dir: str = "./evidence_store"
    public_base_url: str = "http://localhost:8000"
    retention_days: int = 7
    evidence_retention_days: int = 7
    max_evidence_per_check: int = 5
    trust_proxy_headers: bool = False
    # connectors (all optional; absent means "not checked", never silently "clean")
    webrisk_api_key: str = ""
    tavily_api_key: str = ""  # Optional public-web search; absence means live search is not checked.
    weir_api_key: str = ""  # Optional X/Reddit public-post search; absence means not checked.
    scrape_creators_api_key: str = ""  # Optional public social-profile/page inspection.
    intelligence_cache_ttl_seconds: int = 900  # Short cache for public evidence; never caches private message bodies.
    google_places_api_key: str = ""  # Optional Google Places API (New), shop-location corroboration only.
    urlscan_api_key: str = ""  # Optional urlscan.io historical domain search; never submits user URLs.
    blocklist_path: str = ""
    enable_link_fetch: bool = False
    enable_rdap: bool = False
    geocoder_user_agent: str = ""
    # rate limits: (requests, window seconds)
    rl_checks: tuple = (20, 3600)
    rl_checks_user: tuple = (120, 3600)
    rl_evidence: tuple = (15, 3600)
    rl_reports: tuple = (10, 86400)
    rl_search: tuple = (30, 3600)
    rl_search_distinct: int = 10
    rl_auth: tuple = (10, 900)
    rl_appeals: tuple = (5, 86400)
    min_independent_to_publish: int = 2
    dev_echo_codes: bool = False
    # AI Engine
    gemini_api_key: str = ""
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    ai_model: str = "gemini-flash-lite-latest"
    # channels
    whatsapp_verify_token: str = ""
    whatsapp_app_secret: str = ""
    whatsapp_token: str = ""
    whatsapp_phone_number_id: str = ""
    at_username: str = ""
    at_api_key: str = ""
    at_shortcode: str = ""
    at_callback_secret: str = ""

    @classmethod
    def from_env(cls) -> "Settings":
        # Load .env file automatically if present across multiple working-directory contexts
        cur_dir = os.path.dirname(os.path.abspath(__file__))
        candidate_env_paths = [
            os.environ.get("ENV_FILE"),
            os.path.join(os.getcwd(), ".env"),
            os.path.join(os.getcwd(), "smart-scam-identifier", ".env"),
            os.path.join(cur_dir, "..", "..", ".env"),  # smart-scam-identifier/.env
            os.path.join(cur_dir, "..", "..", "..", ".env"),  # root Toroka/.env
            ".env",
            "../.env",
            "../../.env",
        ]
        for env_path in candidate_env_paths:
            if env_path and os.path.exists(env_path):
                try:
                    with open(env_path, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith("#") and "=" in line:
                                k, v = line.split("=", 1)
                                k, v = k.strip(), v.strip().strip("\"'")
                                if k and k not in os.environ:
                                    os.environ[k] = v
                except Exception:
                    pass

        g = os.environ.get

        def rl(name: str, default: tuple) -> tuple:          # e.g. RL_CHECKS=20/3600  (requests / seconds)
            v = g(name)
            if not v:
                return default
            n, w = v.split("/")
            return (int(n), int(w))
        s = cls(env=g("SSI_ENV", "dev"), database_url=g("DATABASE_URL", cls.database_url), encryption_key=g("ENCRYPTION_KEY", ""),
                hmac_key=g("HMAC_KEY", ""), diagnostics_api_key=g("DIAGNOSTICS_API_KEY", ""), storage_dir=g("STORAGE_DIR", cls.storage_dir), public_base_url=g("PUBLIC_BASE_URL", cls.public_base_url),
                retention_days=int(g("RETENTION_DAYS", 7)), trust_proxy_headers=g("TRUST_PROXY_HEADERS") == "1",
                webrisk_api_key=g("WEBRISK_API_KEY", ""), tavily_api_key=g("TAVILY_API_KEY", ""), weir_api_key=g("WEIR_API_KEY", ""), scrape_creators_api_key=g("SCRAPE_CREATORS_API_KEY", ""), intelligence_cache_ttl_seconds=max(0, min(int(g("INTELLIGENCE_CACHE_TTL_SECONDS", 900)), 86400)), google_places_api_key=g("GOOGLE_PLACES_API_KEY", ""), urlscan_api_key=g("URLSCAN_API_KEY", ""), blocklist_path=g("BLOCKLIST_PATH", ""), enable_link_fetch=g("ENABLE_LINK_FETCH") == "1",
                enable_rdap=g("ENABLE_RDAP") == "1", geocoder_user_agent=g("GEOCODER_USER_AGENT", ""), dev_echo_codes=g("DEV_ECHO_CODES") == "1",
                whatsapp_verify_token=g("WHATSAPP_VERIFY_TOKEN", ""), whatsapp_app_secret=g("WHATSAPP_APP_SECRET", ""), whatsapp_token=g("WHATSAPP_TOKEN", ""),
                whatsapp_phone_number_id=g("WHATSAPP_PHONE_NUMBER_ID", ""), at_username=g("AT_USERNAME", ""), at_api_key=g("AT_API_KEY", ""),
                at_shortcode=g("AT_SHORTCODE", ""), at_callback_secret=g("AT_CALLBACK_SECRET", ""),
                gemini_api_key=g("GEMINI_API_KEY", ""), openai_api_key=g("OPENAI_API_KEY", ""), anthropic_api_key=g("ANTHROPIC_API_KEY", ""),
                ai_model=g("AI_MODEL", "gemini-flash-lite-latest"),
                rl_checks=rl("RL_CHECKS", cls.rl_checks), rl_checks_user=rl("RL_CHECKS_USER", cls.rl_checks_user), rl_evidence=rl("RL_EVIDENCE", cls.rl_evidence),
                rl_reports=rl("RL_REPORTS", cls.rl_reports), rl_search=rl("RL_SEARCH", cls.rl_search), rl_auth=rl("RL_AUTH", cls.rl_auth),
                rl_appeals=rl("RL_APPEALS", cls.rl_appeals), rl_search_distinct=int(g("RL_SEARCH_DISTINCT", cls.rl_search_distinct)))
        return s.with_dev_keys()

    def with_dev_keys(self) -> "Settings":
        if not self.encryption_key or not self.hmac_key:
            if self.env == "production":
                raise RuntimeError("ENCRYPTION_KEY and HMAC_KEY are required in production")
            warnings.warn("Using ephemeral development keys: encrypted data will not survive a restart.")
            self.encryption_key = self.encryption_key or Fernet.generate_key().decode()
            self.hmac_key = self.hmac_key or secrets.token_hex(32)
        return self
