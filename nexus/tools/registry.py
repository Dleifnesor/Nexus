"""Tool registry.

Each entry describes how to install, run, and parse a security tool. Built-in tools run on
the host; non-built-in tools run inside an ephemeral Docker container. Dynamically discovered
tools are appended at runtime by the discovery module.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ToolEntry:
    name: str
    category: str  # recon, enumeration, vuln, web, osint, exploit
    when_to_use: str
    builtin: bool = True
    # command template; {target} and {args} are substituted. Used as argv list.
    cmd_template: list[str] = field(default_factory=list)
    install: str = ""  # shell install command (host) if not built-in / missing
    image: str | None = None  # docker image for non-builtin tools
    parser: str = "generic"  # parser key in parsers.py
    phases: list[str] = field(default_factory=list)
    timeout: int = 600
    uses_creds: bool = False  # inject {cred} from the credential store
    host_only: bool = False  # never containerize; install + run on the host


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
    ToolEntry(
        name="nuclei",
        category="vuln",
        when_to_use="Template-based web/network vulnerability scanning and validation.",
        cmd_template=["nuclei", "-u", "{target}", "-silent", "-jsonl", "-severity", "low,medium,high,critical"],
        image="projectdiscovery/nuclei:latest",
        parser="nuclei",
        phases=["vuln_discovery", "exploitation"],
        timeout=1800,
    ),
    ToolEntry(
        name="sqlmap",
        category="vuln",
        when_to_use="Detect SQL injection on a URL (detection/validation only).",
        cmd_template=["sqlmap", "-u", "{target}", "--batch", "--banner", "--level", "1", "--risk", "1"],
        install="apt-get install -y sqlmap",
        parser="sqlmap",
        phases=["vuln_discovery", "exploitation"],
        timeout=1800,
    ),
    ToolEntry(
        name="ffuf",
        category="web",
        when_to_use="Web content/directory fuzzing for a base URL.",
        cmd_template=["ffuf", "-u", "{target}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-mc", "200,204,301,302,307,401,403", "-json"],
        install="apt-get install -y ffuf dirb",
        parser="ffuf",
        phases=["vuln_discovery", "reach_expansion"],
        timeout=1200,
    ),
    ToolEntry(
        name="wpscan",
        category="web",
        when_to_use="Scan a WordPress site for version, themes, plugins, and known issues.",
        cmd_template=["wpscan", "--url", "{target}", "--format", "json", "--no-banner"],
        install="apt-get install -y wpscan",
        parser="wpscan",
        phases=["vuln_discovery"],
        timeout=1800,
    ),
    ToolEntry(
        name="gitleaks",
        category="vuln",
        when_to_use="Scan a repository/source path for exposed secrets.",
        cmd_template=["gitleaks", "detect", "--source", "{target}", "--report-format", "json", "--no-banner", "--exit-code", "0"],
        image="zricethezav/gitleaks:latest",
        parser="gitleaks",
        phases=["vuln_discovery"],
        timeout=1200,
    ),
    ToolEntry(
        name="testssl",
        category="vuln",
        when_to_use="Analyze a host:port for TLS/SSL misconfigurations and weaknesses.",
        cmd_template=["testssl.sh", "--json-pretty", "{target}"],
        image="drwetter/testssl.sh:latest",
        parser="testssl",
        phases=["active_recon", "vuln_discovery"],
        timeout=1200,
    ),
    ToolEntry(
        name="netexec",
        category="vuln",
        when_to_use="Enumerate SMB/AD services, shares, and signing on a LAN host; validate creds.",
        cmd_template=["netexec", "smb", "{target}", "{cred}"],
        install="apt-get install -y netexec",
        parser="netexec",
        phases=["active_recon", "vuln_discovery", "reach_expansion", "exploitation"],
        timeout=900,
        uses_creds=True,
    ),
    ToolEntry(
        name="dalfox",
        category="web",
        when_to_use="Detect reflected/DOM XSS on a URL.",
        cmd_template=["dalfox", "url", "{target}", "--silence"],
        install="apt-get install -y dalfox",
        parser="dalfox",
        phases=["vuln_discovery"],
        timeout=900,
    ),
    ToolEntry(
        name="crt",
        category="recon",
        when_to_use="Query certificate transparency logs for subdomains of a domain.",
        cmd_template=["curl", "-s", "https://crt.sh/?q=%25.{target}&output=json"],
        parser="crt",
        phases=["passive_recon"],
        timeout=120,
    ),
    ToolEntry(
        name="gau",
        category="recon",
        when_to_use="Fetch known URLs for a domain from archives (Wayback, Common Crawl).",
        cmd_template=["gau", "{target}"],
        install="apt-get install -y gau",
        parser="lines_urls",
        phases=["passive_recon", "reach_expansion"],
        timeout=600,
    ),
    ToolEntry(
        name="trivy",
        category="vuln",
        when_to_use="Scan a filesystem/image path for known dependency CVEs (SCA).",
        cmd_template=["trivy", "fs", "--format", "json", "--no-progress", "{target}"],
        image="aquasec/trivy:latest",
        parser="trivy",
        phases=["vuln_discovery"],
        timeout=1800,
    ),
    ToolEntry(
        name="grype",
        category="vuln",
        when_to_use="Scan a filesystem/image path for known dependency CVEs (SCA).",
        cmd_template=["grype", "dir:{target}", "-o", "json"],
        image="anchore/grype:latest",
        parser="grype",
        phases=["vuln_discovery"],
        timeout=1800,
    ),
    ToolEntry(
        name="lynis",
        category="vuln",
        when_to_use="Audit a Unix host for security misconfigurations and hardening gaps.",
        cmd_template=["lynis", "audit", "system", "--quick", "--no-colors"],
        install="apt-get install -y lynis",
        parser="lynis",
        phases=["vuln_discovery"],
        timeout=1800,
    ),
    ToolEntry(
        name="naabu",
        category="enumeration",
        when_to_use="Fast port scanning to discover open TCP ports.",
        cmd_template=["naabu", "-host", "{target}", "-silent"],
        install="apt-get install -y naabu",
        parser="naabu",
        phases=["active_recon", "reach_expansion"],
        timeout=900,
    ),
    ToolEntry(
        name="httpx",
        category="web",
        when_to_use="Probe and fingerprint live HTTP(S) services (title, tech, status).",
        cmd_template=["httpx", "-u", "{target}", "-json", "-silent"],
        install="apt-get install -y httpx-toolkit",
        parser="httpx",
        phases=["active_recon", "reach_expansion"],
        timeout=600,
    ),
    ToolEntry(
        name="wafw00f",
        category="web",
        when_to_use="Detect whether a web app sits behind a WAF.",
        cmd_template=["wafw00f", "{target}"],
        install="apt-get install -y wafw00f",
        parser="wafw00f",
        phases=["active_recon"],
        timeout=300,
    ),
    ToolEntry(
        name="gowitness",
        category="recon",
        when_to_use="Capture a screenshot of a web target for visual triage.",
        cmd_template=["gowitness", "single", "{target}", "-o", "/tmp/gowitness"],
        install="apt-get install -y gowitness",
        parser="generic",
        phases=["active_recon"],
        timeout=300,
    ),
    ToolEntry(
        name="puredns",
        category="recon",
        when_to_use="DNS brute force and resolution of subdomains for a domain.",
        cmd_template=["puredns", "bruteforce", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "{target}"],
        install="apt-get install -y puredns seclists",
        parser="lines_domains",
        phases=["passive_recon", "reach_expansion"],
        timeout=1200,
    ),
    ToolEntry(
        name="dnsx",
        category="recon",
        when_to_use="Fast DNS resolution and record enumeration for a domain.",
        cmd_template=["dnsx", "-d", "{target}", "-silent", "-a", "-resp"],
        install="apt-get install -y dnsx",
        parser="generic",
        phases=["passive_recon"],
        timeout=300,
    ),
    ToolEntry(
        name="ssh-audit",
        category="vuln",
        when_to_use="Audit an SSH server's supported algorithms and configuration.",
        cmd_template=["ssh-audit", "{target}"],
        install="apt-get install -y ssh-audit",
        parser="ssh_audit",
        phases=["vuln_discovery"],
        timeout=300,
    ),
    ToolEntry(
        name="kerbrute",
        category="vuln",
        when_to_use="Enumerate/validate Kerberos accounts (non-destructive user enumeration).",
        cmd_template=["kerbrute", "userenum", "/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt", "-d", "{target}", "--dc", "{target}"],
        image="ropnop/kerbrute:latest",
        parser="kerbrute",
        phases=["vuln_discovery", "reach_expansion"],
        timeout=900,
    ),
    ToolEntry(
        name="hydra",
        category="exploit",
        when_to_use="Brute-force weak credentials against a service (intrusive).",
        cmd_template=["hydra", "-L", "/usr/share/seclists/Usernames/top-usernames-shortlist.txt", "-P", "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt", "{target}", "ssh"],
        install="apt-get install -y hydra seclists",
        parser="hydra",
        phases=["exploitation"],
        timeout=1800,
    ),
    ToolEntry(
        name="nuclei-default-login",
        category="vuln",
        when_to_use="Test for default/weak login credentials via nuclei templates.",
        cmd_template=["nuclei", "-u", "{target}", "-tags", "default-login", "-silent", "-jsonl"],
        image="projectdiscovery/nuclei:latest",
        parser="nuclei",
        phases=["vuln_discovery", "exploitation"],
        timeout=1800,
    ),
    ToolEntry(
        name="bloodhound-python",
        category="vuln",
        when_to_use="Collect Active Directory relationship data for attack-path analysis.",
        cmd_template=["bloodhound-python", "-d", "{target}", "-ns", "{target}", "-c", "All", "--zip"],
        install="apt-get install -y bloodhound.py",
        parser="generic",
        phases=["reach_expansion", "exploitation"],
        timeout=1800,
    ),
    ToolEntry(
        name="gvm",
        category="vuln",
        when_to_use="Run Greenbone/OpenVAS (GVM) vulnerability scans against a target.",
        cmd_template=["gvm-cli", "socket", "--socketpath", "/run/gvmd/gvmd.sock", "--xml", "<commands><get_tasks/></commands>"],
        install="apt-get update && apt-get install -y gvm && gvm-start",
        parser="gvm",
        phases=["vuln_discovery"],
        timeout=1800,
        host_only=True,
    ),
]


class Registry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolEntry] = {t.name: t for t in _SEED}

    def get(self, name: str) -> ToolEntry | None:
        return self._tools.get(name)

    def add(self, entry: ToolEntry) -> None:
        self._tools[entry.name] = entry

    def all(self) -> list[ToolEntry]:
        return list(self._tools.values())

    def for_phase(self, phase: str | None) -> list[ToolEntry]:
        # An empty/None phase means "no filter": return every registered tool. A concrete
        # phase returns tools scoped to it, plus phaseless (discovered) tools available to all.
        if not phase:
            return list(self._tools.values())
        return [t for t in self._tools.values() if phase in t.phases or not t.phases]

    def describe_for_phase(self, phase: str | None) -> str:
        lines = [f"- {t.name}: {t.when_to_use}" for t in self.for_phase(phase)]
        return "\n".join(lines) if lines else "(none)"
