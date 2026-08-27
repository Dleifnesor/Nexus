"""Optional read-only local web dashboard (FastAPI).

Serves findings, assets, and coverage gaps for the current run over localhost. Intended for
convenient browsing on the box; it exposes no mutating endpoints.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path

from ..logging_ import get_logger

log = get_logger(__name__)


def start_web_dashboard(db_path: Path, run_id: str, host: str = "127.0.0.1", port: int = 8787) -> bool:
    """Start the dashboard in a background thread. Returns False if deps are missing."""
    try:
        import uvicorn
        from fastapi import FastAPI
        from fastapi.responses import HTMLResponse
    except Exception as e:
        log.info("Web dashboard deps missing (install nexus-scanner[web]): %s", e)
        return False

    from ..storage.db import Database

    app = FastAPI(title="Nexus Dashboard")

    def _db() -> Database:
        return Database(db_path)

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return (
            "<h1>Nexus Dashboard</h1>"
            f"<p>Run {run_id}</p>"
            "<ul><li><a href='/api/findings'>findings</a></li>"
            "<li><a href='/api/assets'>assets</a></li>"
            "<li><a href='/api/gaps'>coverage gaps</a></li></ul>"
        )

    @app.get("/api/findings")
    def findings() -> list[dict]:
        db = _db()
        try:
            return [
                {**dict(f), "cve_ids": json.loads(f["cve_ids_json"] or "[]")}
                for f in db.list_findings(run_id)
            ]
        finally:
            db.close()

    @app.get("/api/assets")
    def assets() -> list[dict]:
        db = _db()
        try:
            return [dict(a) for a in db.list_assets(run_id)]
        finally:
            db.close()

    @app.get("/api/gaps")
    def gaps() -> list[dict]:
        db = _db()
        try:
            return [dict(g) for g in db.list_coverage_gaps(run_id)]
        finally:
            db.close()

    def _serve() -> None:
        uvicorn.run(app, host=host, port=port, log_level="warning")

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    log.info("Web dashboard at http://%s:%d", host, port)
    return True
