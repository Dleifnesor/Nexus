"""Output parsers that normalize tool output into assets and findings.

Each parser takes raw stdout (str) and the target, returning a ParseResult of discovered
assets and findings. Parser failures are caught by the executor and routed to recovery, so
parsers may raise on malformed input.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field


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
class CredentialRec:
    host: str
    service: str
    username: str
    password: str


@dataclass
class ParseResult:
    assets: list[AssetRec] = field(default_factory=list)
    findings: list[FindingRec] = field(default_factory=list)
    credentials: list[CredentialRec] = field(default_factory=list)


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s\"']+")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


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
                        description="Detected service version for CVE matching.",
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


def parse_nuclei(raw: str, target: str) -> ParseResult:
    """Parse nuclei JSON-lines output (-jsonl)."""
    res = ParseResult()
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = data.get("info") or {}
        name = info.get("name") or data.get("template-id") or "nuclei finding"
        severity = (info.get("severity") or "info").lower()
        matched = data.get("matched-at") or data.get("host") or target
        classification = info.get("classification") or {}
        cve_ids = [str(c).upper() for c in (classification.get("cve-id") or [])]
        cve_ids += [m.upper() for m in _CVE_RE.findall(json.dumps(data))]
        evidence = data.get("extracted-results") or data.get("matcher-name") or json.dumps(data)[:2000]
        res.findings.append(
            FindingRec(
                title=f"{name} on {matched}",
                description=str(info.get("description") or ""),
                severity=severity,
                evidence=str(evidence)[:2000],
                cve_ids=list(dict.fromkeys(cve_ids)),
            )
        )
    return res


def parse_sqlmap(raw: str, target: str) -> ParseResult:
    res = ParseResult(assets=[AssetRec("url", target)])
    if re.search(r"identified the following injection point|is vulnerable", raw, re.IGNORECASE):
        res.findings.append(
            FindingRec(
                title=f"SQL injection in {target}",
                description="sqlmap identified an injectable parameter.",
                severity="high",
                evidence=raw[:2000],
            )
        )
    return res


def parse_ffuf(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return parse_generic(raw, target)
    for r in data.get("results", []):
        url = r.get("url")
        if url:
            res.assets.append(
                AssetRec("url", url, {"status": r.get("status"), "length": r.get("length")})
            )
    return res


def parse_wpscan(raw: str, target: str) -> ParseResult:
    res = ParseResult(assets=[AssetRec("url", target)])
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return parse_generic(raw, target)
    ver = data.get("version") or {}
    if ver.get("number"):
        res.assets.append(
            AssetRec("service", f"{target} wordpress={ver['number']}", {"tech": "wordpress", "version": ver["number"]})
        )
    for f in data.get("interesting_findings") or []:
        title = f.get("type") or f.get("url") or "wpscan finding"
        res.findings.append(
            FindingRec(
                title=f"WordPress {title}",
                description=str(f.get("to_s") or ""),
                severity="low",
                evidence=str(f.get("confirmed_by") or f.get("url") or "")[:2000],
            )
        )
    vulns = data.get("vulnerabilities") or {}
    if isinstance(vulns, dict):
        for slug, entries in vulns.items():
            if not isinstance(entries, list):
                continue
            for e in entries:
                refs = e.get("references") or {}
                cves = (
                    [c.upper() for c in refs.get("cve", [])]
                    if isinstance(refs, dict)
                    else []
                )
                res.findings.append(
                    FindingRec(
                        title=f"WordPress vuln {slug}",
                        description=str(e.get("title") or ""),
                        severity="high",
                        evidence=str(e.get("fixed_in") or "")[:2000],
                        cve_ids=cves,
                    )
                )
    return res


def parse_gitleaks(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return parse_generic(raw, target)
    items = data if isinstance(data, list) else data.get("findings", [])
    for f in items:
        rule = f.get("Description") or f.get("RuleID") or "secret"
        file_ = f.get("File") or f.get("Commit") or ""
        line = f.get("StartLine") or f.get("Line") or ""
        res.findings.append(
            FindingRec(
                title=f"Secret exposure: {rule}",
                description=str(f.get("Description") or ""),
                severity="critical",
                evidence=f"{file_}:{line}".strip(":") if (file_ or line) else str(f.get("Match") or "")[:500],
            )
        )
    return res


def parse_testssl(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return parse_generic(raw, target)
    for f in data if isinstance(data, list) else []:
        sev = (f.get("severity") or "").lower()
        if sev in ("ok", "info", ""):
            continue
        severity = "low" if sev == "low" else "medium" if sev == "medium" else "high"
        res.findings.append(
            FindingRec(
                title=f"TLS: {f.get('id')}",
                description=str(f.get("finding") or ""),
                severity=severity,
                evidence=str(f.get("finding") or "")[:2000],
            )
        )
    return res


def parse_netexec(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if "[+]" in line:
            res.findings.append(
                FindingRec(
                    title=f"netexec finding on {target}",
                    description=line,
                    severity="medium",
                    evidence=line[:2000],
                )
            )
        host = next((m for m in _IP_RE.findall(line) if m != target), None) or target
        if host and not any(a.value == host and a.type == "host" for a in res.assets):
            res.assets.append(AssetRec("host", host))
    return res


def parse_dalfox(raw: str, target: str) -> ParseResult:
    res = ParseResult(assets=[AssetRec("url", target)])
    if "[POC]" in raw:
        res.findings.append(
            FindingRec(
                title=f"XSS found in {target}",
                description="dalfox identified a reflected/dom XSS.",
                severity="medium",
                evidence=raw[:2000],
            )
        )
    return res


def parse_crt(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return parse_generic(raw, target)
    for entry in data if isinstance(data, list) else []:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower()
            if name and _DOMAIN_RE.fullmatch(name):
                res.assets.append(AssetRec("domain", name))
    return res


def parse_lines_urls(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    for u in dict.fromkeys(_URL_RE.findall(raw)):
        res.assets.append(AssetRec("url", u))
    return res


def parse_trivy(raw: str, target: str) -> ParseResult:
    res = ParseResult(assets=[AssetRec("service", f"{target} trivy-scan", {"tech": "sca"})])
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return parse_generic(raw, target)
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            vid = v.get("VulnerabilityID", "")
            pkg = v.get("PkgName", "")
            ver = v.get("InstalledVersion", "")
            res.findings.append(
                FindingRec(
                    title=f"{vid} in {pkg} {ver}".strip(),
                    description=str(v.get("Title") or ""),
                    severity=(v.get("Severity") or "info").lower(),
                    evidence=f"{pkg}@{ver}",
                    cve_ids=[vid.upper()] if vid.upper().startswith("CVE") else [],
                )
            )
    return res


def parse_grype(raw: str, target: str) -> ParseResult:
    res = ParseResult(assets=[AssetRec("service", f"{target} grype-scan", {"tech": "sca"})])
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return parse_generic(raw, target)
    for m in data.get("matches", []):
        vuln = m.get("vulnerability", {})
        artifact = m.get("artifact", {})
        vid = vuln.get("id", "")
        name = artifact.get("name", "")
        ver = artifact.get("version", "")
        res.findings.append(
            FindingRec(
                title=f"{vid} in {name} {ver}".strip(),
                description=str(vuln.get("description") or ""),
                severity=(vuln.get("severity") or "info").lower(),
                evidence=f"{name}@{ver}",
                cve_ids=[vid.upper()] if vid.upper().startswith("CVE") else [],
            )
        )
    return res


def parse_lynis(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    for line in raw.splitlines():
        low = line.lower()
        if "[warning]" in low or "warning:" in low:
            res.findings.append(
                FindingRec(title=f"lynis warning on {target}", description=line, severity="low", evidence=line)
            )
        elif "[suggestion]" in low or "suggestion:" in low:
            res.findings.append(
                FindingRec(title=f"lynis suggestion on {target}", description=line, severity="info", evidence=line)
            )
    return res


def parse_naabu(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    for line in raw.splitlines():
        line = line.strip()
        if line and ":" in line:
            res.assets.append(AssetRec("service", line, {"source": "naabu"}))
    return res


def parse_httpx(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        url = d.get("url") or d.get("input")
        if url:
            res.assets.append(
                AssetRec(
                    "url",
                    url,
                    {"status": d.get("status_code"), "title": d.get("title"), "tech": d.get("tech")},
                )
            )
    return res


def parse_wafw00f(raw: str, target: str) -> ParseResult:
    res = ParseResult(assets=[AssetRec("url", target)])
    m = re.search(r"is behind\s+(.+?)\s+WAF", raw, re.IGNORECASE)
    if m:
        waf = m.group(1).strip()
        res.findings.append(
            FindingRec(
                title=f"WAF detected: {waf}",
                description=f"{target} is behind {waf} WAF.",
                severity="info",
                evidence=raw[:2000],
            )
        )
    return res


def parse_kerbrute(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    for line in raw.splitlines():
        if "[+]" in line or "VALID" in line.upper():
            res.findings.append(
                FindingRec(
                    title=f"Kerberos account found on {target}",
                    description=line,
                    severity="medium",
                    evidence=line,
                )
            )
    return res


def parse_ssh_audit(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    for line in raw.splitlines():
        low = line.lower()
        if "(fail)" in low or "(warn)" in low or "deprecated" in low:
            res.findings.append(
                FindingRec(title=f"SSH weakness on {target}", description=line, severity="low", evidence=line)
            )
    return res


def parse_hydra(raw: str, target: str) -> ParseResult:
    res = ParseResult()
    cred_re = re.compile(r"\[(\d+)\]\[(\w+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)")
    for m in cred_re.finditer(raw):
        port, service, host, login, password = m.groups()
        res.findings.append(
            FindingRec(
                title=f"Valid credentials on {host}:{port}",
                description=f"Valid {service} credentials discovered.",
                severity="critical",
                evidence=f"{host}:{port} login={login}",
            )
        )
        res.credentials.append(CredentialRec(host=host, service=service, username=login, password=password))
    return res


def parse_gvm(raw: str, target: str) -> ParseResult:
    res = ParseResult(assets=[AssetRec("service", f"{target} openvas", {"tech": "gvm"})])
    for cve in dict.fromkeys(_CVE_RE.findall(raw)):
        res.findings.append(
            FindingRec(
                title=f"OpenVAS: {cve}",
                description="Detected by Greenbone/OpenVAS (GVM).",
                severity="high",
                cve_ids=[cve],
                evidence=raw[:2000],
            )
        )
    for name in re.findall(r"<name>(.*?)</name>", raw):
        res.assets.append(AssetRec("service", f"gvm task: {name}", {"tech": "gvm"}))
    return res


PARSERS: dict[str, Callable[[str, str], ParseResult]] = {
    "nmap": parse_nmap,
    "theharvester": parse_theharvester,
    "lines_domains": parse_lines_domains,
    "nikto": parse_nikto,
    "whatweb": parse_whatweb,
    "nuclei": parse_nuclei,
    "sqlmap": parse_sqlmap,
    "ffuf": parse_ffuf,
    "wpscan": parse_wpscan,
    "gitleaks": parse_gitleaks,
    "testssl": parse_testssl,
    "netexec": parse_netexec,
    "dalfox": parse_dalfox,
    "crt": parse_crt,
    "lines_urls": parse_lines_urls,
    "trivy": parse_trivy,
    "grype": parse_grype,
    "lynis": parse_lynis,
    "naabu": parse_naabu,
    "httpx": parse_httpx,
    "wafw00f": parse_wafw00f,
    "kerbrute": parse_kerbrute,
    "ssh_audit": parse_ssh_audit,
    "hydra": parse_hydra,
    "gvm": parse_gvm,
    "generic": parse_generic,
}


def get_parser(key: str) -> Callable[[str, str], ParseResult]:
    return PARSERS.get(key, parse_generic)
