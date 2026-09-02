"""Headless browser automation via Playwright.

Used for JS-heavy or interactive OSINT sources that plain HTTP cannot render. Playwright is
imported lazily so the package remains importable without browsers installed.
"""
from __future__ import annotations

from ..logging_ import get_logger

log = get_logger(__name__)


class Browser:
    def __init__(self, timeout_ms: int = 30000):
        self.timeout_ms = timeout_ms

    def available(self) -> bool:
        try:
            import playwright  # noqa: F401

            return True
        except Exception:
            return False

    def fetch_text(self, url: str) -> str | None:
        """Return the rendered text content of a URL, or None on failure."""
        try:
            from playwright.sync_api import sync_playwright
        except Exception as e:
            log.warning("Playwright unavailable: %s", e)
            return None
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                try:
                    page = browser.new_page()
                    page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
                    return page.inner_text("body")
                finally:
                    browser.close()
        except Exception as e:
            log.warning("Browser fetch failed for %s: %s", url, e)
            return None
