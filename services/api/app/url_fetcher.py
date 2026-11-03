"""Re-export of ssi_connectors.url_fetcher."""
from ssi_connectors.url_fetcher import (
    SafePageContent,
    default_resolver,
    is_ip_allowed,
    resolve_and_pin,
    safe_fetch_page,
)

__all__ = [
    "SafePageContent",
    "default_resolver",
    "is_ip_allowed",
    "resolve_and_pin",
    "safe_fetch_page",
]
