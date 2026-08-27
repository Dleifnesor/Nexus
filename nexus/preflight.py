"""Prerequisite verification for the Kali/Parrot box.

Checks (non-fatal, reported to the operator):
- Docker availability (required to run non-built-in / discovered tools in isolation),
- LLM backend reachability (Ollama by default),
- presence of common built-in tools,
- Playwright browser availability for OSINT.
"""
from __future__ import annotations

import shutil
from dataclasses import dataclass

import httpx

from .config import Config


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str


COMMON_TOOLS = ["nmap", "theHarvester", "nikto", "whatweb", "subfinder"]


def check_docker(cfg: Config) -> CheckResult:
    try:
        import docker

        client = docker.from_env()
        client.ping()
        return CheckResult("docker", True, "daemon reachable")
    except Exception as e:
        return CheckResult("docker", False, f"unavailable: {e}")


def check_llm(cfg: Config) -> CheckResult:
    if cfg.llm.provider == "ollama":
        base = (cfg.llm.base_url or "http://localhost:11434").rstrip("/")
        try:
            r = httpx.get(base + "/api/tags", timeout=5)
            r.raise_for_status()
            models = [m.get("name") for m in r.json().get("models", [])]
            ok = cfg.llm.model in models or not models
            return CheckResult("llm(ollama)", True, f"reachable; models={models[:5]}")
        except Exception as e:
            return CheckResult("llm(ollama)", False, f"unreachable: {e}")
    # cloud providers: just check for API key
    if cfg.llm.api_key:
        return CheckResult(f"llm({cfg.llm.provider})", True, "api key present")
    return CheckResult(f"llm({cfg.llm.provider})", False, "no API key configured")


def check_builtin_tools() -> list[CheckResult]:
    results = []
    for t in COMMON_TOOLS:
        present = shutil.which(t) is not None
        results.append(CheckResult(f"tool:{t}", present, "found" if present else "missing (will containerize)"))
    return results


def check_playwright() -> CheckResult:
    try:
        import playwright  # noqa: F401

        return CheckResult("playwright", True, "installed")
    except Exception:
        return CheckResult("playwright", False, "missing (OSINT browser disabled)")


def run_all(cfg: Config) -> list[CheckResult]:
    results = [check_docker(cfg), check_llm(cfg), check_playwright()]
    results.extend(check_builtin_tools())
    return results
