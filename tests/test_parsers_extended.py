import json

from nexus.tools.parsers import (
    parse_crt,
    parse_dalfox,
    parse_ffuf,
    parse_gitleaks,
    parse_grype,
    parse_gvm,
    parse_httpx,
    parse_hydra,
    parse_lines_urls,
    parse_netexec,
    parse_nuclei,
    parse_sqlmap,
    parse_testssl,
    parse_trivy,
    parse_wafw00f,
    parse_wpscan,
)


def test_parse_nuclei():
    line = json.dumps(
        {
            "template-id": "CVE-2021-4104",
            "info": {
                "name": "Apache Log4j RCE",
                "severity": "critical",
                "classification": {"cve-id": ["CVE-2021-4104"]},
            },
            "matched-at": "http://10.0.0.5",
        }
    )
    res = parse_nuclei(line, "10.0.0.5")
    assert res.findings
    assert res.findings[0].severity == "critical"
    assert "CVE-2021-4104" in res.findings[0].cve_ids


def test_parse_sqlmap():
    raw = "sqlmap identified the following injection point(s) with a total of 1 HTTP(s) requests"
    res = parse_sqlmap(raw, "http://x")
    assert any(f.title.startswith("SQL injection") for f in res.findings)


def test_parse_ffuf():
    res = parse_ffuf(json.dumps({"results": [{"url": "http://x/admin", "status": 200}]}), "http://x")
    assert any(a.type == "url" and a.value == "http://x/admin" for a in res.assets)


def test_parse_wpscan():
    data = {
        "version": {"number": "6.0"},
        "interesting_findings": [{"type": "robots.txt", "to_s": "found"}],
        "vulnerabilities": {"plugin-x": [{"title": "SQLi", "references": {"cve": ["CVE-2020-1"]}}]},
    }
    res = parse_wpscan(json.dumps(data), "http://x")
    assert any(a.type == "service" and "wordpress" in a.value for a in res.assets)
    assert any("CVE-2020-1" in f.cve_ids for f in res.findings)


def test_parse_gitleaks():
    res = parse_gitleaks(json.dumps([{"Description": "AWS Key", "File": "a.txt", "StartLine": 1}]), ".")
    assert any(f.severity == "critical" for f in res.findings)


def test_parse_testssl():
    res = parse_testssl(json.dumps([{"id": "TLSv1_0", "severity": "HIGH", "finding": "TLSv1.0 offered"}]), "x")
    assert any(f.title.startswith("TLS:") for f in res.findings)


def test_parse_netexec():
    raw = "SMB         10.0.0.9    445    HOST  [*] Windows 10.0 Build 19041 (name:HOST) (signing:False)"
    res = parse_netexec(raw, "10.0.0.9")
    assert any(a.type == "host" for a in res.assets)


def test_parse_dalfox():
    res = parse_dalfox("[POC][V][GET] http://x/?a=1", "http://x")
    assert any(f.title.startswith("XSS") for f in res.findings)


def test_parse_crt():
    res = parse_crt(json.dumps([{"name_value": "a.example.com\nb.example.com"}]), "example.com")
    assert any(a.value == "a.example.com" for a in res.assets)


def test_parse_lines_urls():
    res = parse_lines_urls("garbage http://a.example.com/x and https://b.example.com", "x")
    vals = {a.value for a in res.assets}
    assert "http://a.example.com/x" in vals


def test_parse_trivy():
    raw = json.dumps(
        {"Results": [{"Vulnerabilities": [
            {"VulnerabilityID": "CVE-2021-44228", "Severity": "CRITICAL", "PkgName": "log4j-core", "InstalledVersion": "2.14.1"},
        ]}]}
    )
    res = parse_trivy(raw, "/app")
    assert any("CVE-2021-44228" in f.cve_ids for f in res.findings)


def test_parse_grype():
    raw = json.dumps(
        {"matches": [{"vulnerability": {"id": "CVE-2022-1", "severity": "High"}, "artifact": {"name": "openssl", "version": "1.1.1"}}]}
    )
    res = parse_grype(raw, ".")
    assert any(f.cve_ids == ["CVE-2022-1"] for f in res.findings)


def test_parse_httpx():
    raw = json.dumps({"url": "http://x", "status_code": 200, "title": "hi", "tech": ["nginx"]}) + "\n"
    res = parse_httpx(raw, "x")
    assert any(a.type == "url" and a.value == "http://x" for a in res.assets)


def test_parse_wafw00f():
    res = parse_wafw00f("The site http://x is behind Cloudflare (Cloudflare Inc.) WAF.", "http://x")
    assert any("WAF detected" in f.title for f in res.findings)


def test_parse_hydra_credentials():
    raw = "[22][ssh] host: 10.0.0.5   login: admin   password: hunter2"
    res = parse_hydra(raw, "10.0.0.5")
    assert any(f.severity == "critical" for f in res.findings)
    assert res.credentials and res.credentials[0].username == "admin"
    assert res.credentials[0].password == "hunter2"


def test_parse_gvm():
    raw = "<get_tasks_response><task id=\"1\"><name>Scan</name><status>Done</status></task></get_tasks_response> CVE-2021-44228"
    res = parse_gvm(raw, "10.0.0.5")
    assert any("CVE-2021-44228" in f.cve_ids for f in res.findings)
    assert any("gvm task: Scan" in a.value for a in res.assets)
