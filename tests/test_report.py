import json

from nexus.report.renderer import Renderer
from nexus.report.risk import (
    asset_criticality,
    attack_techniques,
    build_attack_graph,
    risk_level,
    risk_score,
    weighted_risk,
)
from nexus.storage.db import Database


def test_renderer_html_and_json(tmp_path):
    db = Database(tmp_path / "r.db")
    rid = db.create_run("scope", {"raw": ["example.com"]}, {}, {})
    db.add_asset(rid, "host", "10.0.0.1", source="scope", phase="preflight")
    fid = db.add_finding(
        rid, "Apache 2.4.29 outdated", description="Old Apache", severity="high",
        cvss=7.5, cve_ids=["CVE-2021-4104"], evidence="Apache httpd 2.4.29", source_tool="nmap",
    )
    db.add_remediation(fid, "Upgrade Apache", "- apt upgrade apache2", ["https://httpd.apache.org"], "test-model")
    db.add_error(rid, "coverage_gap", "nikto failed on 10.0.0.2", is_coverage_gap=True)

    outputs = Renderer(db, rid, tmp_path / "reports").render()
    assert "html" in outputs and "json" in outputs

    html = open(outputs["html"], encoding="utf-8").read()
    assert "Apache 2.4.29 outdated" in html
    assert "CVE-2021-4104" in html
    assert "Upgrade Apache" in html
    assert "coverage gap" in html.lower()

    data = json.loads(open(outputs["json"], encoding="utf-8").read())
    assert data["counts"]["high"] == 1
    assert data["findings"][0]["cve_ids"] == ["CVE-2021-4104"]
    assert len(data["gaps"]) == 1

    sarif = json.loads(open(outputs["sarif"], encoding="utf-8").read())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "CVE-2021-4104"
    db.close()


def test_renderer_risk_and_techniques(tmp_path):
    db = Database(tmp_path / "r.db")
    rid = db.create_run("scope", {}, {}, {})
    db.add_finding(rid, "SQL injection", description="sqli in login", severity="high", cvss=9.0)
    fid = db.list_findings(rid)[0]["id"]
    db.update_finding_cve(fid, ["CVE-2020-1"], 9.0, "high", epss=0.8, exploit_available=True)
    data = Renderer(db, rid, tmp_path / "reports")._build_model()
    f = data["findings"][0]
    assert f["exploit_available"] is True
    assert f["risk"] >= 85
    assert f["risk_level"] == "critical"
    assert any("T1190" in t for t in f["attack_techniques"])
    db.close()


def test_risk_helpers():
    assert risk_score(9.0, None, False) == 90.0
    assert risk_score(5.0, 0.9, False) == 90.0
    assert risk_score(3.0, None, True) == 85.0
    assert risk_level(95) == "critical"
    assert risk_level(50) == "medium"
    assert attack_techniques("SQL injection", "sqli", "sqlmap") == ["T1190 Exploit Public-Facing Application"]


def test_asset_criticality_and_weighted_risk():
    assert asset_criticality("webserver01", exposed=False) == 1.0
    assert asset_criticality("webserver01", exposed=True) == 1.2
    assert asset_criticality("dc01.corp.local", exposed=False) == 1.3
    assert asset_criticality("dc01.corp.local", exposed=True) == 1.5
    assert weighted_risk(5.0, None, False, 1.5) == 75.0


def test_attack_graph():
    assets = [{"type": "host", "value": "10.0.0.5"}, {"type": "service", "value": "10.0.0.5:80 http"}]
    findings = [{"title": "Apache outdated", "evidence": "10.0.0.5:80", "cve_ids": ["CVE-2021-4104"]}]
    g = build_attack_graph(assets, findings)
    assert "graph TD" in g
    assert "10.0.0.5" in g
    assert "CVE-2021-4104" in g


def test_render_diff(tmp_path):
    db = Database(tmp_path / "r.db")
    rid_a = db.create_run("scope", {}, {}, {})
    rid_b = db.create_run("scope", {}, {}, {})
    db.add_finding(rid_a, "Only in A", severity="high")
    db.add_finding(rid_b, "Only in B", severity="low")
    db.add_finding(rid_a, "Changed", severity="medium", cvss=5.0)
    db.add_finding(rid_b, "Changed", severity="critical", cvss=9.8)

    outputs = Renderer(db, rid_b, tmp_path / "reports").render_diff(rid_a)
    data = json.loads(open(outputs["json"], encoding="utf-8").read())
    assert any(f["title"] == "Only in B" for f in data["added"])
    assert any(f["title"] == "Only in A" for f in data["removed"])
    assert len(data["changed"]) == 1
    db.close()
