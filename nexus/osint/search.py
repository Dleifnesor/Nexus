"""Browser-driven web search for tool discovery.

The discovery module needs to find the right open-source CLI for a capability the registry
does not cover. A plain HTTP GET against a search engine is unreliable (bot challenges, JS-
rendered results), so this module drives a real headless Chromium via Playwright: it runs the
query, extracts the top organic results (title / url / snippet), and fetches the text of the
most relevant result pages (preferring GitHub, which usually documents the install command).

Everything degrades gracefully: if Playwright or a browser is unavailable, an optional HTTP
fallback is used, and any failure yields an empty string so discovery simply finds nothing
rather than crashing the run.
"""
from __future__ import annotations

from collections.abc import Callable
from urllib.parse import parse_qs, urlparse

from ..logging_ import get_logger

log = get_logger(__name__)

_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0 Safari/537.36"
)
_DDG_HTML = "https://html.duckduckgo.com/html/"
_BING = "https://www.bing.com/search"


class WebSearch:
    def __init__(
        self,
        timeout_ms: int = 30000,
        max_results: int = 6,
        fetch_pages: int = 2,
        page_chars: int = 4000,
        http_fallback: Callable[[str], str] | None = None,
    ):
        self.timeout_ms = timeout_ms
        self.max_results = max_results
        self.fetch_pages = fetch_pages
        self.page_chars = page_chars
        self.http_fallback = http_fallback

    # discovery expects a plain (query -> text) callable
    def __call__(self, query: str) -> str:
        return self.run(query)

    def run(self, query: str) -> str:
        results: list[dict] = []
        excerpts: list[tuple[str, str]] = []
        try:
            results, excerpts = self._browser_gather(query)
        except Exception as e:
            log.warning("Browser search failed for %r: %s", query, e)

        if not results:
            if self.http_fallback is not None:
                log.info("Falling back to HTTP search for: %s", query)
                return self.http_fallback(query)
            return ""
        return _format(query, results, excerpts)

    # -- Playwright driver ------------------------------------------------
    def _browser_gather(self, query: str) -> tuple[list[dict], list[tuple[str, str]]]:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                ctx = browser.new_context(user_agent=_UA, locale="en-US")
                page = ctx.new_page()
                results = self._ddg(page, query) or self._bing(page, query)
                results = _dedupe(results)[: self.max_results]

                excerpts: list[tuple[str, str]] = []
                for r in _rank_for_fetch(results)[: self.fetch_pages]:
                    text = self._fetch(ctx, r["url"])
                    if text:
                        excerpts.append((r["url"], text[: self.page_chars]))
                return results, excerpts
            finally:
                browser.close()

    def _ddg(self, page, query: str) -> list[dict]:
        try:
            page.goto(f"{_DDG_HTML}?q={_q(query)}", timeout=self.timeout_ms, wait_until="domcontentloaded")
            anchors = page.query_selector_all("a.result__a")
            snippets = page.query_selector_all(".result__snippet")
            out: list[dict] = []
            for i, a in enumerate(anchors):
                url = _ddg_target(a.get_attribute("href") or "")
                if not url:
                    continue
                snippet = snippets[i].inner_text().strip() if i < len(snippets) else ""
                out.append({"title": (a.inner_text() or "").strip(), "url": url, "snippet": snippet})
            return out
        except Exception as e:
            log.info("DuckDuckGo search failed: %s", e)
            return []

    def _bing(self, page, query: str) -> list[dict]:
        try:
            page.goto(f"{_BING}?q={_q(query)}", timeout=self.timeout_ms, wait_until="domcontentloaded")
            items = page.query_selector_all("li.b_algo h2 a")
            out: list[dict] = []
            for a in items:
                url = a.get_attribute("href") or ""
                if url.startswith("http"):
                    out.append({"title": (a.inner_text() or "").strip(), "url": url, "snippet": ""})
            return out
        except Exception as e:
            log.info("Bing search failed: %s", e)
            return []

    def _fetch(self, ctx, url: str) -> str | None:
        try:
            page = ctx.new_page()
            try:
                page.goto(url, timeout=self.timeout_ms, wait_until="domcontentloaded")
                return page.inner_text("body")
            finally:
                page.close()
        except Exception as e:
            log.info("Result fetch failed for %s: %s", url, e)
            return None


def _q(query: str) -> str:
    from urllib.parse import quote_plus

    return quote_plus(query)


def _ddg_target(href: str) -> str:
    """DuckDuckGo HTML wraps result links in a redirect (/l/?uddg=<encoded>); unwrap it."""
    if not href:
        return ""
    if href.startswith("//"):
        href = "https:" + href
    parsed = urlparse(href)
    if "duckduckgo.com" in parsed.netloc and parsed.path.startswith("/l/"):
        target = parse_qs(parsed.query).get("uddg", [""])[0]
        return target or ""
    return href if href.startswith("http") else ""


def _dedupe(results: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for r in results:
        if r["url"] and r["url"] not in seen:
            seen.add(r["url"])
            out.append(r)
    return out


def _rank_for_fetch(results: list[dict]) -> list[dict]:
    """Prefer pages that tend to document install commands (GitHub, package indexes)."""
    def score(r: dict) -> int:
        u = r["url"].lower()
        if "github.com" in u:
            return 0
        if any(h in u for h in ("pypi.org", "pkg.go.dev", "kali.org", "readthedocs", "gitlab.com")):
            return 1
        return 2

    return sorted(results, key=score)


def _format(query: str, results: list[dict], excerpts: list[tuple[str, str]]) -> str:
    lines = [f"Search results for: {query}", ""]
    for i, r in enumerate(results, 1):
        lines.append(f"{i}. {r['title']}\n   {r['url']}\n   {r['snippet']}".rstrip())
    for url, text in excerpts:
        lines.append(f"\n--- Page content: {url} ---\n{text}")
    return "\n".join(lines)
