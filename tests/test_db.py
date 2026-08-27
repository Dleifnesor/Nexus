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
