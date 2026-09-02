import json

from nexus.enrich.nvd import _extract_cvss, _sev_from_score
from nexus.report.enrich_findings import FindingEnricher, _extract_product_version
from nexus.storage.db import Database


def test_extract_cvss_prefers_v31():
    metrics = {
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
        "cvssMetricV30": [{"cvssData": {"baseScore": 7.5}}],
    }
    score, sev = _extract_cvss(metrics)
    assert score == 9.8
    assert sev == "critical"


def test_extract_cvss_v2():
    metrics = {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}]}
    score, sev = _extract_cvss(metrics)
    assert score == 5.0
    assert sev == "medium"


def test_extract_cvss_empty():
    assert _extract_cvss({}) == (None, "unknown")


def test_sev_from_score():
    assert _sev_from_score(9.5) == "critical"
    assert _sev_from_score(7.0) == "high"
    assert _sev_from_score(4.0) == "medium"
    assert _sev_from_score(1.0) == "low"
    assert _sev_from_score(0) == "info"
    assert _sev_from_score(None) == "unknown"


def test_extract_product_version():
    assert _extract_product_version("Apache httpd 2.4.29", "") == ("Apache httpd", "2.4.29")
    assert _extract_product_version("", "nginx 1.18.0 here") == ("nginx", "1.18.0")
    assert _extract_product_version("nothing", "still nothing") == ("", "")


class _FakeNVD:
    def __init__(self, cpe_items=None, product_items=None, cve=None):
        self.cpe_items = cpe_items or []
        self.product_items = product_items or []
        self.cve = cve

    def lookup_cve(self, cve_id):
        return self.cve

    def search_cpe(self, product, version, limit=5):
        return self.cpe_items

    def search_product(self, product, version, limit=3):
        return self.product_items


class _FakeOSV:
    def query(self, product, version):
        return []


class _FakeKev:
    def __init__(self, exploited=()):
        self.exploited = {c.upper() for c in exploited}

    def is_known_exploited(self, cve_id):
        return cve_id.upper() in self.exploited


class _FakeEpss:
    def __init__(self, scores=None):
        self.scores = {k.upper(): {"epss": v} for k, v in (scores or {}).items()}

    def score(self, cve_id):
        return self.scores.get(cve_id.upper())


class _FakeExploitDB:
    def __init__(self, found=()):
        self.found = {c.upper() for c in found}

    def has_exploit(self, cve_id):
        return cve_id.upper() in self.found


class _FakeGitHub:
    def __init__(self, found=()):
        self.found = {c.upper() for c in found}

    def has_poc(self, cve_id):
        return cve_id.upper() in self.found


class _FakeVulners:
    def __init__(self, found=()):
        self.found = {c.upper() for c in found}

    def has_public_exploit(self, cve_id):
        return cve_id.upper() in self.found


def test_finding_enricher_cpe_kev_epss(tmp_path):
    db = Database(tmp_path / "t.db")
    rid = db.create_run("scope", {}, {}, {})
    db.add_finding(rid, "Apache httpd 2.4.29", evidence="Apache httpd 2.4.29 on 10.0.0.1")
    nvd = _FakeNVD(cpe_items=[{"cve_id": "CVE-2019-0211", "cvss": 7.2, "severity": "high"}])
    kev = _FakeKev(["CVE-2019-0211"])
    epss = _FakeEpss({"CVE-2019-0211": 0.95})
    enriched = FindingEnricher(db, rid, nvd, _FakeOSV(), kev, epss).enrich_all()
    assert enriched == 1
    row = db.list_findings(rid)[0]
    assert "CVE-2019-0211" in json.loads(row["cve_ids_json"])
    assert row["cvss"] == 7.2
    assert row["severity"] == "high"
    assert row["epss"] == 0.95
    assert row["exploit_available"] == 1


def test_finding_enricher_falls_back_to_keyword(tmp_path):
    db = Database(tmp_path / "t.db")
    rid = db.create_run("scope", {}, {}, {})
    db.add_finding(rid, "Apache httpd 2.4.29")
    nvd = _FakeNVD(cpe_items=[], product_items=[{"cve_id": "CVE-2021-44790", "cvss": 9.8, "severity": "critical"}])
    FindingEnricher(db, rid, nvd, _FakeOSV(), _FakeKev(), _FakeEpss()).enrich_all()
    row = db.list_findings(rid)[0]
    assert "CVE-2021-44790" in json.loads(row["cve_ids_json"])
    assert row["exploit_available"] == 0


def test_finding_enricher_kev_from_existing_cve(tmp_path):
    db = Database(tmp_path / "t.db")
    rid = db.create_run("scope", {}, {}, {})
    db.add_finding(rid, "Something else", cve_ids=["CVE-2023-0001"])
    FindingEnricher(db, rid, _FakeNVD(), _FakeOSV(), _FakeKev(["CVE-2023-0001"]), _FakeEpss()).enrich_all()
    assert db.list_findings(rid)[0]["exploit_available"] == 1


def test_finding_enricher_exploit_signal_from_exploitdb(tmp_path):
    db = Database(tmp_path / "t.db")
    rid = db.create_run("scope", {}, {}, {})
    db.add_finding(rid, "Something", cve_ids=["CVE-2024-0001"])
    FindingEnricher(
        db, rid, _FakeNVD(), _FakeOSV(), _FakeKev(), _FakeEpss(),
        _FakeExploitDB(["CVE-2024-0001"]), _FakeGitHub(), _FakeVulners(),
    ).enrich_all()
    assert db.list_findings(rid)[0]["exploit_available"] == 1


def test_finding_enricher_exploit_signal_from_github_and_vulners(tmp_path):
    db = Database(tmp_path / "t.db")
    rid = db.create_run("scope", {}, {}, {})
    db.add_finding(rid, "Something", cve_ids=["CVE-2024-0002", "CVE-2024-0003"])
    FindingEnricher(
        db, rid, _FakeNVD(), _FakeOSV(), _FakeKev(), _FakeEpss(),
        _FakeExploitDB(), _FakeGitHub(["CVE-2024-0002"]), _FakeVulners(["CVE-2024-0003"]),
    ).enrich_all()
    assert db.list_findings(rid)[0]["exploit_available"] == 1
