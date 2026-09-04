"""Web-search-driven tool discovery.

When the planner requests a capability not covered by the registry, discovery performs a
web search, feeds the results to the LLM, and synthesizes a new ToolEntry (install + run +
parser). Discovered tools are marked non-builtin so they always run inside a container.

The actual web search is injected as a callable so the engine can wire in whatever search
backend is available (or a stub in offline mode).
"""
from __future__ import annotations

import re
from collections.abc import Callable

from ..config import Mode
from ..llm.provider import BaseProvider
from ..logging_ import audit, get_logger
from .registry import Registry, ToolEntry

log = get_logger(__name__)

SearchFn = Callable[[str], str]  # query -> summarized results text

# The install string of a discovered tool is model-authored from web-search content, so it is
# untrusted input that would otherwise be run through a shell. Only allow a package install
# from a known manager, with package tokens drawn from a safe character set, and reject
# anything containing shell metacharacters. A binary name must be a bare token (no path).
_INSTALL_MANAGERS = ("apt-get install", "apt install", "pip install", "pip3 install",
                     "go install", "gem install")
_SHELL_METACHARS = re.compile(r"[;&|`$><\n\r()\\]")
_PKG_TOKENS = re.compile(r"^[A-Za-z0-9 ._+/@:=-]+$")
_BINARY_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def sanitize_install(install: str) -> str:
    """Return the install command if it is a safe single package-manager install, else ""."""
    cmd = (install or "").strip()
    if not cmd:
        return ""
    if _SHELL_METACHARS.search(cmd):
        return ""
    manager = next((m for m in _INSTALL_MANAGERS if cmd.startswith(m + " ")), None)
    if manager is None:
        return ""
    args = cmd[len(manager):].strip()
    # allow a leading "-y" for apt; validate the remaining package tokens
    args = re.sub(r"^-y\s+", "", args)
    if not args or not _PKG_TOKENS.match(args):
        return ""
    return cmd


def valid_binary(cmd_template: list[str]) -> bool:
    return bool(cmd_template) and bool(_BINARY_RE.match(str(cmd_template[0])))


DISCOVERY_SCHEMA_HINT = {
    "name": "short-tool-name",
    "category": "recon|enumeration|vuln|web|osint|exploit",
    "when_to_use": "one sentence",
    "install": "apt-get install -y <pkg>  OR  pip install <pkg>  OR  git clone ... ",
    "image": "docker image if a well-known one exists, else null",
    "cmd_template": ["binary", "{target}"],
    "parser": "generic",
}


class ToolDiscovery:
    def __init__(
        self,
        registry: Registry,
        provider: BaseProvider,
        mode: Mode,
        search_fn: SearchFn | None = None,
    ):
        self.registry = registry
        self.provider = provider
        self.mode = mode
        self.search_fn = search_fn

    def discover(self, query: str) -> ToolEntry | None:
        if self.search_fn is None:
            log.warning("No search backend configured; cannot discover tools for: %s", query)
            return None
        try:
            results = self.search_fn(query)
        except Exception as e:
            log.warning("Tool discovery search failed: %s", e)
            return None

        prompt = (
            f"A security assessment needs a tool for: {query}\n\n"
            f"Search results:\n{results[:6000]}\n\n"
            "Identify the single best open-source CLI tool and produce a registry entry as JSON "
            f"with exactly these keys: {list(DISCOVERY_SCHEMA_HINT.keys())}. "
            "cmd_template must be an argv list using {target} placeholder. Prefer apt or pip "
            "installs. Set image to a known Docker image name or null."
        )
        try:
            data = self._structured(prompt)
        except Exception as e:
            log.warning("Discovery synthesis failed: %s", e)
            return None

        cmd_template = list(data.get("cmd_template") or [])
        raw_install = str(data.get("install") or "")
        safe_install = sanitize_install(raw_install)
        if raw_install and not safe_install:
            log.warning(
                "Discovered tool install command rejected by sanitizer: %r", raw_install
            )
        entry = ToolEntry(
            name=str(data.get("name") or "").strip() or f"discovered-{abs(hash(query)) % 10000}",
            category=str(data.get("category") or "recon"),
            when_to_use=str(data.get("when_to_use") or query),
            builtin=False,  # discovered tools always run in a container
            cmd_template=cmd_template,
            install=safe_install,
            image=data.get("image") or None,
            parser=str(data.get("parser") or "generic"),
            phases=[],  # available to all phases
        )
        if not entry.cmd_template:
            log.warning("Discovered tool %s has no command template; discarding", entry.name)
            return None
        if not valid_binary(entry.cmd_template):
            log.warning(
                "Discovered tool %s has an unsafe binary name %r; discarding",
                entry.name, entry.cmd_template[0] if entry.cmd_template else None,
            )
            return None
        self.registry.add(entry)
        audit(
            "tool.discovered",
            name=entry.name,
            install=entry.install,
            image=entry.image,
            query=query,
            mode=self.mode.value,
        )
        log.info("Discovered and registered tool '%s' for query: %s", entry.name, query)
        return entry

    def _structured(self, prompt: str) -> dict:
        from ..llm.provider import _extract_json  # reuse robust JSON extractor

        raw = self.provider.generate(prompt, system="Return only JSON.")
        return _extract_json(raw)
