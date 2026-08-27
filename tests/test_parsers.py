from nexus.tools.parsers import (
    get_parser,
    parse_generic,
    parse_lines_domains,
    parse_nikto,
    parse_nmap,
    parse_theharvester,
)

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <address addr="10.0.0.5" addrtype="ipv4"/>
  <ports>
   <port protocol="tcp" portid="22">
    <state state="open"/>
    <service name="ssh" product="OpenSSH" version="7.4"/>
   </port>
   <port protocol="tcp" portid="80">
    <state state="open"/>
    <service name="http" product="Apache httpd" version="2.4.29"/>
    <script id="vuln-check" output="CVE-2017-15710 detected in Apache"/>
   </port>
  </ports>
 </host>
</nmaprun>
"""


def test_parse_nmap_assets_and_findings():
    res = parse_nmap(NMAP_XML, "10.0.0.5")
    hosts = [a for a in res.assets if a.type == "host"]
    services = [a for a in res.assets if a.type == "service"]
    assert any(h.value == "10.0.0.5" for h in hosts)
    assert len(services) == 2
    cve_findings = [f for f in res.findings if f.cve_ids]
    assert any("CVE-2017-15710" in f.cve_ids for f in cve_findings)


def test_parse_nmap_malformed_falls_back():
    res = parse_nmap("not xml at all CVE-2021-1234", "x")
    assert any("CVE-2021-1234" in f.cve_ids for f in res.findings)


def test_parse_theharvester():
    raw = "Found: admin@example.com\nhost: mail.example.com\nrandom@other.com"
    res = parse_theharvester(raw, "example.com")
    emails = [a.value for a in res.assets if a.type == "email"]
    assert "admin@example.com" in emails
    domains = [a.value for a in res.assets if a.type == "domain"]
    assert "mail.example.com" in domains


def test_parse_lines_domains():
    res = parse_lines_domains("a.example.com\nb.example.com\ngarbage line\n", "example.com")
    vals = [a.value for a in res.assets]
    assert "a.example.com" in vals and "b.example.com" in vals


def test_parse_nikto():
    raw = "+ Server: Apache\n+ OSVDB-3268: /icons/: Directory indexing found CVE-1999-0001"
    res = parse_nikto(raw, "http://x")
    assert any(f.cve_ids for f in res.findings)


def test_get_parser_default():
    assert get_parser("nonexistent") is parse_generic
