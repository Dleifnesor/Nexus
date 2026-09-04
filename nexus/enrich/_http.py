"""Shared HTTP helpers for enrichment clients: minimum-interval pacing and retry with
backoff that honors ``Retry-After`` on 429/503 responses.

External vuln-intel APIs (notably NVD) are aggressively rate limited. The enricher can issue
many lookups per run, so these helpers keep it polite and resilient instead of failing the
whole enrichment pass on the first throttle.
"""
from __future__ import annotations

import threading
import time

import httpx

from ..logging_ import get_logger

log = get_logger(__name__)

_RETRY_STATUS = {429, 500, 502, 503, 504}


class RateLimiter:
    """Thread-safe minimum-interval limiter (spacing, not a token bucket)."""

    def __init__(self, min_interval_s: float):
        self.min_interval_s = max(0.0, min_interval_s)
        self._last = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if self.min_interval_s <= 0:
            return
        with self._lock:
            now = time.monotonic()
            gap = self.min_interval_s - (now - self._last)
            if gap > 0:
                time.sleep(gap)
            self._last = time.monotonic()


def request_with_retry(
    method: str,
    url: str,
    *,
    limiter: RateLimiter | None = None,
    retries: int = 3,
    backoff: float = 2.0,
    max_wait: float = 30.0,
    **kwargs,
) -> httpx.Response:
    """Issue an HTTP request, retrying transient/throttling responses with backoff.

    Raises the final ``httpx.HTTPError`` (via ``raise_for_status``) if all attempts fail.
    """
    last_exc: httpx.HTTPError | None = None
    for attempt in range(retries + 1):
        if limiter is not None:
            limiter.wait()
        try:
            resp = httpx.request(method, url, **kwargs)
        except httpx.HTTPError as e:
            last_exc = e
            if attempt >= retries:
                raise
            time.sleep(min(backoff ** attempt, max_wait))
            continue
        if resp.status_code in _RETRY_STATUS and attempt < retries:
            wait = _retry_after(resp) or min(backoff ** attempt, max_wait)
            log.info("HTTP %s from %s; retrying in %.1fs", resp.status_code, url, wait)
            time.sleep(min(wait, max_wait))
            continue
        resp.raise_for_status()
        return resp
    if last_exc is not None:
        raise last_exc
    raise httpx.HTTPError("request failed after retries")  # pragma: no cover


def _retry_after(resp: httpx.Response) -> float | None:
    value = resp.headers.get("Retry-After")
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None
