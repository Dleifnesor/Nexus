"""Tool registry.

Each entry describes how to install, run, and parse a security tool. Built-in tools run on
the host; non-built-in tools run inside an ephemeral Docker container. Dynamically discovered
tools are appended at runtime by the discovery module.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ToolEntry:
    name: str
    category: str  # recon, enumeration, vuln, web, osint, exploit
    when_to_use: str
    builtin: bool = True
    # command template; {target} and {args} are substituted. Used as argv list.
    cmd_template: list[str] = field(default_factory=list)
    install: str = ""  # shell install command (host) if not built-in / missing
    image: Optional[str] = None  # docker image for non-builtin tools
    parser: str = "generic"  # parser key in parsers.py
    phases: list[str] = field(default_factory=list)
    timeout: int = 600


# A pragmatic seed set covering the core phases. Extendable at runtime via discovery.
_SEED: list[ToolEntry] = [
    ToolEntry(
        name="nmap",
        category="enumeration",
        when_to_use="Host discovery, port scanning, and service/version detection.",
        cmd_template=["nmap", "-sV", "-Pn", "-oX", "-", "{target}"],
        parser="nmap",
        phases=["active_recon", "vuln_discovery", "reach_expansion"],
        timeout=1800,
    ),
    ToolEntry(
        name="nmap-vuln",
        category="vuln",
        when_to_use="Run nmap NSE vuln scripts against a host with known open services.",
        cmd_template=["nmap", "-sV", "--script", "vuln", "-Pn", "-oX", "-", "{target}"],
        parser="nmap",
        phases=["vuln_discovery"],
        timeout=2400,
    ),
    ToolEntry(
        name="theharvester",
        category="osint",
        when_to_use="Collect emails, subdomains, and hosts for a domain from public sources.",
        cmd_template=["theHarvester", "-d", "{target}", "-b", "all"],
        parser="theharvester",
        phases=["passive_recon"],
        timeout=900,
    ),
    ToolEntry(
        name="subfinder",
        category="recon",
        when_to_use="Fast passive subdomain enumeration for a domain.",
        cmd_template=["subfinder", "-silent", "-d", "{target}"],
        parser="lines_domains",
        phases=["passive_recon", "reach_expansion"],
        timeout=600,
    ),
    ToolEntry(
        name="nikto",
        category="web",
        when_to_use="Scan a web server URL for common misconfigurations and known issues.",
        cmd_template=["nikto", "-host", "{target}", "-Format", "txt"],
        parser="nikto",
        phases=["vuln_discovery"],
        timeout=1200,
    ),
    ToolEntry(
        name="whatweb",
        category="web",
        when_to_use="Fingerprint web technologies, servers, and frameworks for a URL.",
        cmd_template=["whatweb", "--no-errors", "{target}"],
        parser="whatweb",
        phases=["passive_recon", "active_recon"],
        timeout=300,
    ),
]


class Registry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolEntry] = {t.name: t for t in _SEED}

    def get(self, name: str) -> Optional[ToolEntry]:
        return self._tools.get(name)

    def add(self, entry: ToolEntry) -> None:
        self._tools[entry.name] = entry

    def all(self) -> list[ToolEntry]:
        return list(self._tools.values())

    def for_phase(self, phase: str) -> list[ToolEntry]:
        return [t for t in self._tools.values() if phase in t.phases or not t.phases]

    def describe_for_phase(self, phase: str) -> str:
        lines = [f"- {t.name}: {t.when_to_use}" for t in self.for_phase(phase)]
        return "\n".join(lines) if lines else "(none)"
