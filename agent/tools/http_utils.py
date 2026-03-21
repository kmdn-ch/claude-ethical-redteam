"""HTTP utilities — retry with exponential backoff + stealth integration."""

import time
import logging
import requests

logger = logging.getLogger(__name__)


def retry_request(
    url: str,
    *,
    method: str = "GET",
    max_retries: int = 3,
    backoff_factor: float = 2.0,
    timeout: int = 15,
    **kwargs,
) -> requests.Response:
    """Execute an HTTP request with exponential backoff on failure.

    Automatically applies stealth headers and proxy if stealth module is loaded
    and no explicit headers/proxies are provided.
    """
    # Integrate stealth headers if not explicitly provided
    try:
        from .stealth import stealth_headers, get_proxy
        if "headers" not in kwargs:
            kwargs["headers"] = stealth_headers()
        proxies = get_proxy()
        if proxies and "proxies" not in kwargs:
            kwargs["proxies"] = proxies
    except ImportError:
        pass

    last_exc = None
    for attempt in range(max_retries + 1):
        try:
            resp = requests.request(method, url, timeout=timeout, **kwargs)
            resp.raise_for_status()
            return resp
        except (requests.RequestException, Exception) as exc:
            last_exc = exc
            if attempt < max_retries:
                wait = backoff_factor ** attempt
                logger.warning(
                    "HTTP %s %s failed (attempt %d/%d): %s — retrying in %.1fs",
                    method, url, attempt + 1, max_retries + 1, exc, wait,
                )
                time.sleep(wait)
            else:
                logger.error(
                    "HTTP %s %s failed after %d attempts: %s",
                    method, url, max_retries + 1, exc,
                )
    raise last_exc
