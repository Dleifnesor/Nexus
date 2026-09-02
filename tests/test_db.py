from nexus.storage.db import Database


def make_db(tmp_path):
    return Database(tmp_path / "t.db")


def test_run_lifecycle(tmp_path):
    db = make_db(tmp_path)
    rid = db.create_run("scope", {"raw": ["example.com"]}, {}, {})
    assert db.get_run(rid)["status"] == "running"
    db.set_run_phase(rid, "active_recon")
    assert db.get_run(rid)["current_phase"] == "active_recon"
    db.finish_run(rid, "completed")
    assert db.get_run(rid)["status"] == "completed"


def test_asset_dedup(tmp_path):
    db = make_db(tmp_path)
    rid = db.create_run("scope", {}, {}, {})
    first = db.add_asset(rid, "host", "10.0.0.1")
    dup = db.add_asset(rid, "host", "10.0.0.1")
    assert first is not None
    assert dup is None
    assert db.count_assets(rid) == 1


def test_findings_and_remediation(tmp_path):
    db = make_db(tmp_path)
    rid = db.create_run("scope", {}, {}, {})
    fid = db.add_finding(rid, "Test finding", severity="high", cve_ids=["CVE-2021-1"])
    db.update_finding_cve(fid, ["CVE-2021-1", "CVE-2021-2"], 9.8, "critical")
    f = db.list_findings(rid)[0]
    assert f["cvss"] == 9.8 and f["severity"] == "critical"
    db.add_remediation(fid, "fix it", "- step", ["http://ref"], "model")
    assert db.get_remediation(fid)["summary"] == "fix it"


def test_update_finding_risk_metadata(tmp_path):
    db = make_db(tmp_path)
    rid = db.create_run("scope", {}, {}, {})
    fid = db.add_finding(rid, "Test", severity="high", cve_ids=["CVE-2021-1"])
    db.update_finding_cve(fid, ["CVE-2021-1"], 7.5, "high", epss=0.9, exploit_available=True)
    f = db.list_findings(rid)[0]
    assert f["epss"] == 0.9
    assert f["exploit_available"] == 1


def test_migration_adds_columns(tmp_path):
    # Simulate a DB created before the epss/exploit_available columns existed.
    import sqlite3

    path = tmp_path / "old.db"
    conn = sqlite3.connect(str(path))
    conn.execute(
        "CREATE TABLE findings (id TEXT PRIMARY KEY, run_id TEXT, asset_id TEXT, title TEXT, "
        "description TEXT, severity TEXT, cvss REAL, cve_ids_json TEXT, evidence TEXT, "
        "source_tool TEXT, created_at REAL)"
    )
    conn.commit()
    conn.close()

    db = Database(path)
    rid = db.create_run("scope", {}, {}, {})
    fid = db.add_finding(rid, "Test")
    db.update_finding_cve(fid, [], None, "info", epss=0.5, exploit_available=False)
    assert db.list_findings(rid)[0]["epss"] == 0.5


def test_checkpoint_roundtrip(tmp_path):
    db = make_db(tmp_path)
    rid = db.create_run("scope", {}, {}, {})
    db.save_checkpoint(rid, "active_recon", {"phase_index": 2, "iteration": 5})
    cp = db.latest_checkpoint(rid)
    assert cp["phase"] == "active_recon"
    assert cp["state"]["phase_index"] == 2


def test_coverage_gap(tmp_path):
    db = make_db(tmp_path)
    rid = db.create_run("scope", {}, {}, {})
    db.add_error(rid, "coverage_gap", "tool failed", is_coverage_gap=True)
    db.add_error(rid, "tool_error", "minor", is_coverage_gap=False)
    assert len(db.list_coverage_gaps(rid)) == 1
    assert len(db.list_errors(rid)) == 2


def test_cache(tmp_path):
    db = make_db(tmp_path)
    assert db.cache_get("k") is None
    db.cache_put("k", "nvd", {"v": 1})
    assert db.cache_get("k") == {"v": 1}


def test_credential_store(tmp_path):
    db = make_db(tmp_path)
    rid = db.create_run("scope", {}, {}, {})
    cid = db.add_credential(rid, "10.0.0.5", "admin", "hunter2", service="ssh", source_tool="hydra")
    assert cid is not None
    creds = db.list_credentials(rid, "10.0.0.5")
    assert len(creds) == 1
    assert creds[0]["username"] == "admin"
    assert db.list_credentials(rid, "10.0.0.99") == []


def test_knowledge_base(tmp_path):
    db = make_db(tmp_path)
    rid = db.create_run("scope", {}, {}, {})
    db.kb_set(rid, "open_ports", "22,80,443")
    assert db.kb_get(rid, "open_ports") == "22,80,443"
    assert db.kb_all(rid) == {"open_ports": "22,80,443"}
