"""Risk scoring and MITRE ATT&CK mapping helpers for findings."""
from __future__ import annotations

import re

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CRITICAL_ROLE_RE = re.compile(
    r"\b(dc\d*|adc\d*|domain[- ]?controller|exchange\d*|vault\d*|sql\d*|db\d*|database\d*|financ|payroll|prod\d*)\b",
    re.IGNORECASE,
)

# Keyword -> MITRE ATT&CK technique mapping (lowercase substring match).
_ATTACK_MAP: list[tuple[tuple[str, ...], str]] = [
    (("sql injection", "sqli", "sqlmap"), "T1190 Exploit Public-Facing Application"),
    (("xss", "cross-site scripting"), "T1189 Drive-by Compromise"),
    (("remote code execution", "rce", "log4j"), "T1210 Exploitation of Remote Services"),
    (("credential", "password", "brute force", "default login", "default cred"), "T1110 Brute Force"),
    (("tls", "ssl", "certificate"), "T1573 Encrypted Channel"),
    (("secret", "api key", "token", "exposed cred"), "T1552 Unsecured Credentials"),
    (("smb", "share", "netexec", "windows"), "T1021 Remote Services"),
    (("privilege escalation", "privilege"), "T1068 Exploitation for Privilege Escalation"),
    (("information disclosure", "directory listing"), "T1083 File and Directory Discovery"),
]


def risk_score(cvss: float | None, epss: float | None, exploit_available: bool) -> float:
    """Compute a normalized 0-100 risk score from CVSS, EPSS, and exploit availability."""
    base = (cvss or 0.0) * 10.0  # CVSS 0..10 -> 0..100
    if exploit_available:
        base = max(base, 85.0)
    if epss is not None:
        base = max(base, float(epss) * 100.0)
    return round(min(100.0, base), 1)


def risk_level(score: float) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 10:
        return "low"
    return "info"


def attack_techniques(title: str, description: str, source_tool: str) -> list[str]:
    """Return MITRE ATT&CK techniques implied by a finding's text and source tool."""
    haystack = f"{title} {description} {source_tool}".lower()
    techniques = []
    for keywords, technique in _ATTACK_MAP:
        if any(k in haystack for k in keywords):
            techniques.append(technique)
    return techniques


def asset_criticality(host: str, exposed: bool = False) -> float:
    """Criticality multiplier for an asset based on its role and internet exposure."""
    critical = bool(_CRITICAL_ROLE_RE.search(host.lower()))
    if critical and exposed:
        return 1.5
    if critical:
        return 1.3
    if exposed:
        return 1.2
    return 1.0


def weighted_risk(cvss: float | None, epss: float | None, exploit_available: bool, criticality: float) -> float:
    """Risk score weighted by asset criticality."""
    return round(min(100.0, risk_score(cvss, epss, exploit_available) * criticality), 1)


def _node_id(value: str) -> str:
    return re.sub(r"\W", "_", value)[:40]


def _label(value: str, limit: int = 40) -> str:
    """Sanitize text for a Mermaid node label: strip quotes/brackets/newlines that would
    otherwise break the diagram syntax."""
    cleaned = re.sub(r'["\[\]{}|<>]', " ", str(value))
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:limit] or "?"


def build_attack_graph(assets: list[dict], findings: list[dict]) -> str:
    """Render a Mermaid attack-path graph from assets and findings."""
    hosts = [a["value"] for a in assets if a["type"] == "host"]
    services = [a["value"] for a in assets if a["type"] == "service"]
    lines = ["graph TD"]
    for h in hosts:
        lines.append(f'  H_{_node_id(h)}["{_label(h)}"]')
    for s in services:
        sid = _node_id(s)
        lines.append(f'  S_{sid}["{_label(s)}"]')
        for h in hosts:
            if h in s:
                lines.append(f"  H_{_node_id(h)} --> S_{sid}")
                break
    for f in findings:
        fid = _node_id(f["title"])
        lines.append(f'  F_{fid}["{_label(f["title"])}"]')
        text = f["evidence"] or f["title"]
        linked = False
        for h in hosts:
            if h in text:
                lines.append(f"  H_{_node_id(h)} --> F_{fid}")
                linked = True
                break
        if not linked:
            for s in services:
                if s in text:
                    lines.append(f"  S_{_node_id(s)} --> F_{fid}")
                    linked = True
                    break
        for cve in f["cve_ids"]:
            lines.append(f'  V_{_node_id(cve)}["{cve}"]')
            lines.append(f"  F_{fid} --> V_{_node_id(cve)}")
    return "\n".join(lines)
