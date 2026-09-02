"""OSV (Open Source Vulnerabilities) enrichment client.

Queries OSV.dev for vulnerabilities affecting a package at a given version. Useful for
software components detected during scanning (e.g., web framework versions).
"""
from __future__ import annotations

import httpx

from ..logging_ import get_logger
from ..storage.db import Database

log = get_logger(__name__)

OSV_QUERY = "https://api.osv.dev/v1/query"


class OSVClient:
    def __init__(self, db: Database):
        self.db = db

    def query(self, name: str, version: str, ecosystem: str = "") -> list[dict]:
        if not name or not version:
            return []
        cache_key = f"osv:{ecosystem}:{name}:{version}".lower()
        cached = self.db.cache_get(cache_key)
        if cached is not None:
            return cached.get("items", [])
        pkg = {"name": name}
        if ecosystem:
            pkg["ecosystem"] = ecosystem
        body = {"version": version, "package": pkg}
        try:
            resp = httpx.post(OSV_QUERY, json=body, timeout=30)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            log.warning("OSV query failed for %s@%s: %s", name, version, e)
            return []
        items = []
        for v in resp.json().get("vulns", []):
            aliases = v.get("aliases", [])
            cves = [a for a in aliases if a.upper().startswith("CVE-")]
            items.append(
                {
                    "id": v.get("id"),
                    "summary": v.get("summary", ""),
                    "cve_ids": cves,
                    "references": [r.get("url") for r in v.get("references", []) if r.get("url")],
                }
            )
        self.db.cache_put(cache_key, "osv", {"items": items})
        return items
