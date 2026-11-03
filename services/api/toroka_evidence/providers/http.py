from __future__ import annotations
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


class ProviderError(RuntimeError):
    pass


def get_json(url: str, headers: dict[str, str] | None = None, timeout: int = 10) -> dict:
    req = Request(url, headers={"Accept": "application/json", "User-Agent": "Toroka/Phase2 evidence-checker" , **(headers or {})})
    try:
        with urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise ProviderError(f"HTTP {exc.code} from provider") from exc
    except (URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProviderError(f"Provider request failed: {type(exc).__name__}") from exc


def post_json(url: str, payload: dict, headers: dict | None = None, timeout: int = 10) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = Request(url, data=body, method="POST", headers={"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "Toroka/Phase2 evidence-checker", **(headers or {})})
    try:
        with urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise ProviderError(f"HTTP {exc.code} from provider") from exc
    except (URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProviderError(f"Provider request failed: {type(exc).__name__}") from exc
