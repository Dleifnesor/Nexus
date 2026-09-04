"""SQLite schema and data-access layer for Nexus.

Single-file store holding runs, assets, actions, findings, remediations, errors,
checkpoints, and an enrichment cache. Thread-safe for the single-writer engine via a
connection-level lock; readers (TUI/web) open their own read-only connections.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    scope_json TEXT,
    budgets_json TEXT,
    config_json TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    current_phase TEXT,
    started_at REAL NOT NULL,
    ended_at REAL
);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT,
    discovered_phase TEXT,
    metadata_json TEXT,
    created_at REAL NOT NULL,
    UNIQUE(run_id, type, value)
);

CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    phase TEXT,
    tool TEXT,
    target TEXT,
    cmd TEXT,
    container_id TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    exit_code INTEGER,
    started_at REAL,
    ended_at REAL,
    output_excerpt TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    asset_id TEXT,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT,
    cvss REAL,
    epss REAL,
    exploit_available INTEGER,
    cve_ids_json TEXT,
    evidence TEXT,
    source_tool TEXT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS remediations (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    summary TEXT,
    steps_md TEXT,
    references_json TEXT,
    generated_by TEXT
);

CREATE TABLE IF NOT EXISTS errors (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    action_id TEXT,
    kind TEXT,
    message TEXT,
    recovery_action TEXT,
    is_coverage_gap INTEGER DEFAULT 0,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    phase TEXT,
    state_json TEXT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS enrichment_cache (
    key TEXT PRIMARY KEY,
    source TEXT,
    payload_json TEXT,
    fetched_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    host TEXT NOT NULL,
    service TEXT,
    username TEXT NOT NULL,
    secret TEXT,
    source_tool TEXT,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS kb_entries (
    run_id TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    updated_at REAL NOT NULL,
    PRIMARY KEY (run_id, key)
);

CREATE INDEX IF NOT EXISTS idx_assets_run ON assets(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_actions_run ON actions(run_id);
CREATE INDEX IF NOT EXISTS idx_errors_run ON errors(run_id);
CREATE INDEX IF NOT EXISTS idx_credentials_run ON credentials(run_id);
"""


def _uid() -> str:
    return uuid.uuid4().hex


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._conn.executescript(SCHEMA)
        self._migrate()
        self._conn.commit()

    def _migrate(self) -> None:
        """Additive migrations for databases created by older schema versions."""
        for column, decl in (("epss", "REAL"), ("exploit_available", "INTEGER")):
            try:
                self._conn.execute(f"ALTER TABLE findings ADD COLUMN {column} {decl}")
            except sqlite3.OperationalError:
                pass  # column already present

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- generic helpers -------------------------------------------------
    def _exec(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur

    def _query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, tuple(params)).fetchall())

    # -- runs ------------------------------------------------------------
    def create_run(self, mode: str, scope: dict, budgets: dict, config: dict) -> str:
        rid = _uid()
        self._exec(
            "INSERT INTO runs(id, mode, scope_json, budgets_json, config_json, status, started_at)"
            " VALUES(?,?,?,?,?, 'running', ?)",
            (rid, mode, json.dumps(scope), json.dumps(budgets), json.dumps(config), time.time()),
        )
        return rid

    def set_run_phase(self, run_id: str, phase: str) -> None:
        self._exec("UPDATE runs SET current_phase=? WHERE id=?", (phase, run_id))

    def finish_run(self, run_id: str, status: str) -> None:
        self._exec(
            "UPDATE runs SET status=?, ended_at=? WHERE id=?",
            (status, time.time(), run_id),
        )

    def get_run(self, run_id: str) -> sqlite3.Row | None:
        rows = self._query("SELECT * FROM runs WHERE id=?", (run_id,))
        return rows[0] if rows else None

    # -- assets ----------------------------------------------------------
    def add_asset(
        self,
        run_id: str,
        type_: str,
        value: str,
        source: str = "",
        phase: str = "",
        metadata: dict | None = None,
    ) -> str | None:
        """Insert an asset; returns id, or None if it already existed (dedup)."""
        aid = _uid()
        try:
            self._exec(
                "INSERT INTO assets(id, run_id, type, value, source, discovered_phase, metadata_json, created_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (aid, run_id, type_, value, source, phase, json.dumps(metadata or {}), time.time()),
            )
            return aid
        except sqlite3.IntegrityError:
            return None

    def list_assets(self, run_id: str, type_: str | None = None) -> list[sqlite3.Row]:
        if type_:
            return self._query(
                "SELECT * FROM assets WHERE run_id=? AND type=? ORDER BY created_at", (run_id, type_)
            )
        return self._query("SELECT * FROM assets WHERE run_id=? ORDER BY created_at", (run_id,))

    def count_assets(self, run_id: str) -> int:
        return self._query("SELECT COUNT(*) c FROM assets WHERE run_id=?", (run_id,))[0]["c"]

    # -- actions ---------------------------------------------------------
    def start_action(self, run_id: str, phase: str, tool: str, target: str, cmd: str) -> str:
        aid = _uid()
        self._exec(
            "INSERT INTO actions(id, run_id, phase, tool, target, cmd, status, started_at)"
            " VALUES(?,?,?,?,?,?, 'running', ?)",
            (aid, run_id, phase, tool, target, cmd, time.time()),
        )
        return aid

    def finish_action(
        self,
        action_id: str,
        status: str,
        exit_code: int | None = None,
        output_excerpt: str = "",
        container_id: str | None = None,
    ) -> None:
        self._exec(
            "UPDATE actions SET status=?, exit_code=?, ended_at=?, output_excerpt=?, container_id=? WHERE id=?",
            (status, exit_code, time.time(), output_excerpt[:4000], container_id, action_id),
        )

    def count_actions(self, run_id: str) -> int:
        return self._query("SELECT COUNT(*) c FROM actions WHERE run_id=?", (run_id,))[0]["c"]

    # -- findings --------------------------------------------------------
    def add_finding(
        self,
        run_id: str,
        title: str,
        description: str = "",
        severity: str = "info",
        cvss: float | None = None,
        cve_ids: list[str] | None = None,
        evidence: str = "",
        source_tool: str = "",
        asset_id: str | None = None,
    ) -> str:
        fid = _uid()
        self._exec(
            "INSERT INTO findings(id, run_id, asset_id, title, description, severity, cvss, cve_ids_json, evidence, source_tool, created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (
                fid, run_id, asset_id, title, description, severity, cvss,
                json.dumps(cve_ids or []), evidence, source_tool, time.time(),
            ),
        )
        return fid

    def list_findings(self, run_id: str) -> list[sqlite3.Row]:
        return self._query(
            "SELECT * FROM findings WHERE run_id=? ORDER BY cvss DESC NULLS LAST, created_at", (run_id,)
        )

    def count_findings(self, run_id: str) -> int:
        return self._query("SELECT COUNT(*) c FROM findings WHERE run_id=?", (run_id,))[0]["c"]

    def update_finding_cve(
        self,
        finding_id: str,
        cve_ids: list[str],
        cvss: float | None,
        severity: str,
        epss: float | None = None,
        exploit_available: bool = False,
    ) -> None:
        self._exec(
            "UPDATE findings SET cve_ids_json=?, cvss=?, severity=?, epss=?, exploit_available=? WHERE id=?",
            (json.dumps(cve_ids), cvss, severity, epss, int(exploit_available), finding_id),
        )

    # -- remediations ----------------------------------------------------
    def add_remediation(
        self, finding_id: str, summary: str, steps_md: str, references: list[str], generated_by: str
    ) -> str:
        rid = _uid()
        self._exec(
            "INSERT INTO remediations(id, finding_id, summary, steps_md, references_json, generated_by)"
            " VALUES(?,?,?,?,?,?)",
            (rid, finding_id, summary, steps_md, json.dumps(references), generated_by),
        )
        return rid

    def get_remediation(self, finding_id: str) -> sqlite3.Row | None:
        rows = self._query("SELECT * FROM remediations WHERE finding_id=?", (finding_id,))
        return rows[0] if rows else None

    # -- errors ----------------------------------------------------------
    def add_error(
        self,
        run_id: str,
        kind: str,
        message: str,
        action_id: str | None = None,
        recovery_action: str = "",
        is_coverage_gap: bool = False,
    ) -> str:
        eid = _uid()
        self._exec(
            "INSERT INTO errors(id, run_id, action_id, kind, message, recovery_action, is_coverage_gap, created_at)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (eid, run_id, action_id, kind, message, recovery_action, int(is_coverage_gap), time.time()),
        )
        return eid

    def list_coverage_gaps(self, run_id: str) -> list[sqlite3.Row]:
        return self._query(
            "SELECT * FROM errors WHERE run_id=? AND is_coverage_gap=1 ORDER BY created_at", (run_id,)
        )

    def list_errors(self, run_id: str) -> list[sqlite3.Row]:
        return self._query("SELECT * FROM errors WHERE run_id=? ORDER BY created_at", (run_id,))

    # -- checkpoints -----------------------------------------------------
    def save_checkpoint(self, run_id: str, phase: str, state: dict) -> str:
        cid = _uid()
        self._exec(
            "INSERT INTO checkpoints(id, run_id, phase, state_json, created_at) VALUES(?,?,?,?,?)",
            (cid, run_id, phase, json.dumps(state), time.time()),
        )
        return cid

    def latest_checkpoint(self, run_id: str) -> dict | None:
        rows = self._query(
            "SELECT * FROM checkpoints WHERE run_id=? ORDER BY created_at DESC LIMIT 1", (run_id,)
        )
        if not rows:
            return None
        return {"phase": rows[0]["phase"], "state": json.loads(rows[0]["state_json"])}

    # -- enrichment cache ------------------------------------------------
    def cache_get(self, key: str, max_age: float | None = None) -> dict | None:
        """Return a cached payload, or None. If max_age (seconds) is given, entries older
        than that are treated as a miss so stale intel is refetched."""
        rows = self._query(
            "SELECT payload_json, fetched_at FROM enrichment_cache WHERE key=?", (key,)
        )
        if not rows:
            return None
        if max_age is not None and (time.time() - (rows[0]["fetched_at"] or 0)) > max_age:
            return None
        return json.loads(rows[0]["payload_json"])

    def cache_put(self, key: str, source: str, payload: dict) -> None:
        self._exec(
            "INSERT OR REPLACE INTO enrichment_cache(key, source, payload_json, fetched_at) VALUES(?,?,?,?)",
            (key, source, json.dumps(payload), time.time()),
        )

    # -- credential store -------------------------------------------------
    def add_credential(
        self, run_id: str, host: str, username: str, secret: str = "", service: str = "", source_tool: str = ""
    ) -> str | None:
        cid = _uid()
        try:
            self._exec(
                "INSERT INTO credentials(id, run_id, host, service, username, secret, source_tool, created_at)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (cid, run_id, host, service, username, secret, source_tool, time.time()),
            )
            return cid
        except sqlite3.IntegrityError:
            return None

    def list_credentials(self, run_id: str, host: str | None = None) -> list[sqlite3.Row]:
        if host:
            return self._query("SELECT * FROM credentials WHERE run_id=? AND host=? ORDER BY created_at", (run_id, host))
        return self._query("SELECT * FROM credentials WHERE run_id=? ORDER BY created_at", (run_id,))

    # -- knowledge base (cross-phase memory) ------------------------------
    def kb_set(self, run_id: str, key: str, value: str) -> None:
        self._exec(
            "INSERT OR REPLACE INTO kb_entries(run_id, key, value, updated_at) VALUES(?,?,?,?)",
            (run_id, key, value, time.time()),
        )

    def kb_get(self, run_id: str, key: str) -> str | None:
        rows = self._query("SELECT value FROM kb_entries WHERE run_id=? AND key=?", (run_id, key))
        return rows[0]["value"] if rows else None

    def kb_all(self, run_id: str) -> dict[str, str]:
        rows = self._query("SELECT key, value FROM kb_entries WHERE run_id=?", (run_id,))
        return {r["key"]: r["value"] for r in rows}
