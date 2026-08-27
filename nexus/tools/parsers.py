"""Output parsers that normalize tool output into assets and findings.

Each parser takes raw stdout (str) and the target, returning a ParseResult of discovered
assets and findings. Parser failures are caught by the executor and routed to recovery, so
parsers may raise on malformed input.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class AssetRec:
    type: str  # host, domain, url, service, email
    value: str
    metadata: dict = field(default_factory=dict)


@dataclass
class FindingRec:
    title: str
    description: str = ""
    severity: str = "info"
    evidence: str = ""
    cve_ids: list[str] = field(default_factory=list)


@dataclass
class ParseResult:
    assets: list[AssetRec] = field(default_factory=list)
    findings: list[FindingRec] = field(default_factory=list)


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)


def parse_nmap(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return parse_generic(raw, target)
    for host in root.findall("host"):
        addr_el = host.find("address")
        host_ip = addr_el.get("addr") if addr_el is not None else target
        res.assets.append(AssetRec("host", host_ip))
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid", "")
            svc = port.find("service")
            svc_name = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            svc_label = f"{host_ip}:{portid}/{svc_name}".strip("/")
            meta = {"product": product, "version": version, "port": portid}
            res.assets.append(AssetRec("service", svc_label, meta))
            # NSE script output may contain CVEs / vuln info
            for script in port.findall("script"):
                out = script.get("output", "")
                cves = list(dict.fromkeys(m.upper() for m in _CVE_RE.findall(out)))
                if cves or script.get("id", "").startswith("vuln"):
                    res.findings.append(
                        FindingRec(
                            title=f"{svc_name or 'service'} issue on {host_ip}:{portid} ({script.get('id','')})",
                            description=out.strip()[:1000],
                            severity="medium" if cves else "info",
                            evidence=out.strip()[:2000],
                            cve_ids=cves,
                        )
                    )
            if product:
                res.findings.append(
                    FindingRec(
                        title=f"Service {product} {version} on {host_ip}:{portid}".strip(),
                        description=f"Detected service version for CVE matching.",
                        severity="info",
                        evidence=f"{product} {version}".strip(),
                    )
                )
    return res


def parse_theharvester(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    for m in dict.fromkeys(_EMAIL_RE.findall(raw)):
        res.assets.append(AssetRec("email", m))
    for m in dict.fromkeys(_DOMAIN_RE.findall(raw)):
        if m.lower().endswith(target.lower()) or target.lower().endswith(m.lower()):
            res.assets.append(AssetRec("domain", m.lower()))
    return res


def parse_lines_domains(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    for line in raw.splitlines():
        line = line.strip()
        if line and _DOMAIN_RE.fullmatch(line):
            res.assets.append(AssetRec("domain", line.lower()))
    return res


def parse_nikto(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    res.assets.append(AssetRec("url", target))
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("+") and len(line) > 3:
            cves = list(dict.fromkeys(m.upper() for m in _CVE_RE.findall(line)))
            res.findings.append(
                FindingRec(
                    title=f"Web finding: {line[1:80].strip()}",
                    description=line[1:].strip(),
                    severity="low",
                    evidence=line.strip(),
                    cve_ids=cves,
                )
            )
    return res


def parse_whatweb(raw: str, target: str) -> ParseResult:
    res = ParseResult(assets=[AssetRec("url", target)])
    for m in re.findall(r"([A-Za-z][\w-]+)\[([^\]]+)\]", raw):
        res.assets.append(AssetRec("service", f"{target} {m[0]}={m[1]}", {"tech": m[0], "value": m[1]}))
    return res


def parse_generic(raw: str, target: str) -> ParseResult:
    """Fallback parser: extract CVEs, emails, and domains; make a low-signal finding."""
    res = ParseResult()
    cves = list(dict.fromkeys(m.upper() for m in _CVE_RE.findall(raw)))
    for e in dict.fromkeys(_EMAIL_RE.findall(raw)):
        res.assets.append(AssetRec("email", e))
    if cves:
        res.findings.append(
            FindingRec(
                title=f"CVEs referenced in tool output for {target}",
                description="Generic parser extracted CVE identifiers from tool output.",
                severity="medium",
                evidence=raw[:2000],
                cve_ids=cves,
            )
        )
    return res


PARSERS: dict[str, Callable[[str, str], ParseResult]] = {
    "nmap": parse_nmap,
    "theharvester": parse_theharvester,
    "lines_domains": parse_lines_domains,
    "nikto": parse_nikto,
    "whatweb": parse_whatweb,
    "generic": parse_generic,
}


def get_parser(key: str) -> Callable[[str, str], ParseResult]:
    return PARSERS.get(key, parse_generic)
