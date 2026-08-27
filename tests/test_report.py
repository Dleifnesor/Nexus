import json

from nexus.report.renderer import Renderer
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
    db.close()
