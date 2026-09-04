"""Tests for the browser-driven tool-discovery search backend."""
from nexus.osint.search import (
    WebSearch,
    _ddg_target,
    _dedupe,
    _format,
    _rank_for_fetch,
)


def test_ddg_target_unwraps_redirect():
    href = "//duckduckgo.com/l/?uddg=https%3A%2F%2Fgithub.com%2Fx%2Fy&rut=abc"
    assert _ddg_target(href) == "https://github.com/x/y"


def test_ddg_target_passes_direct_links_and_drops_junk():
    assert _ddg_target("https://example.com/tool") == "https://example.com/tool"
    assert _ddg_target("/relative/path") == ""
    assert _ddg_target("") == ""


def test_rank_prefers_github_then_indexes():
    results = [
        {"url": "https://blog.example.com/x", "title": "", "snippet": ""},
        {"url": "https://pypi.org/project/x", "title": "", "snippet": ""},
        {"url": "https://github.com/a/b", "title": "", "snippet": ""},
    ]
    ranked = _rank_for_fetch(results)
    assert ranked[0]["url"].startswith("https://github.com")
    assert "pypi.org" in ranked[1]["url"]


def test_dedupe_keeps_first_of_each_url():
    results = [
        {"url": "https://a", "title": "1", "snippet": ""},
        {"url": "https://a", "title": "2", "snippet": ""},
        {"url": "https://b", "title": "3", "snippet": ""},
    ]
    assert [r["title"] for r in _dedupe(results)] == ["1", "3"]


def test_format_includes_results_and_page_excerpts():
    results = [{"title": "ffuf", "url": "https://github.com/ffuf/ffuf", "snippet": "fuzzer"}]
    excerpts = [("https://github.com/ffuf/ffuf", "go install github.com/ffuf/ffuf@latest")]
    text = _format("web fuzzer", results, excerpts)
    assert "ffuf" in text and "github.com/ffuf/ffuf" in text
    assert "Page content" in text and "go install" in text


def test_run_uses_http_fallback_when_browser_yields_nothing(monkeypatch):
    ws = WebSearch(http_fallback=lambda q: f"FALLBACK:{q}")
    # simulate no browser results
    monkeypatch.setattr(ws, "_browser_gather", lambda q: ([], []))
    assert ws.run("subdomain brute force") == "FALLBACK:subdomain brute force"


def test_run_returns_empty_without_fallback(monkeypatch):
    ws = WebSearch(http_fallback=None)
    monkeypatch.setattr(ws, "_browser_gather", lambda q: ([], []))
    assert ws.run("anything") == ""


def test_websearch_is_callable(monkeypatch):
    ws = WebSearch(http_fallback=lambda q: "X")
    monkeypatch.setattr(ws, "_browser_gather", lambda q: ([], []))
    assert ws("q") == "X"  # __call__ delegates to run


# -- CLI wiring: discovery on by default, --no-tool-search disables it -------
def test_cli_tool_search_defaults_on_and_can_disable():
    from nexus.cli import build_parser

    parser = build_parser()
    default = parser.parse_args(["--sandbox", "--scope-entry", "10.0.0.1"])
    assert default.no_tool_search is False

    disabled = parser.parse_args(["--sandbox", "--scope-entry", "10.0.0.1", "--no-tool-search"])
    assert disabled.no_tool_search is True


def test_config_defaults_enable_discovery_and_install():
    from nexus.config import Config, Mode

    cfg = Config(mode=Mode.SANDBOX)
    assert cfg.tool_search is True
    assert cfg.allow_tool_install is True
