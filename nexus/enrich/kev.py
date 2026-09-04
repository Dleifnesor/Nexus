"""CISA Known Exploited Vulnerabilities (KEV) catalog client.

The KEV catalog lists CVEs that are actively exploited in the wild, which is the
strongest signal that a finding should be prioritized. The full catalog is fetched
once per run and cached in the DB.
"""
from __future__ import annotations

import httpx

from ..logging_ import get_logger
from ..storage.db import Database

log = get_logger(__name__)

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevClient:
    def __init__(self, db: Database):
        self.db = db
        self._catalog: set[str] | None = None

    def _load(self) -> set[str]:
        if self._catalog is not None:
            return self._catalog
        cached = self.db.cache_get("kev:catalog", max_age=86400)
        if cached is not None:
            self._catalog = set(cached.get("cves", []))
            return self._catalog
        cves: set[str] = set()
        try:
            resp = httpx.get(KEV_URL, timeout=30)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            log.warning("KEV catalog fetch failed: %s", e)
            self._catalog = cves
            return cves
        for v in resp.json().get("vulnerabilities", []):
            cid = v.get("cveID")
            if cid:
                cves.add(cid.upper())
        self.db.cache_put("kev:catalog", "kev", {"cves": sorted(cves)})
        self._catalog = cves
        return cves

    def is_known_exploited(self, cve_id: str) -> bool:
        return cve_id.upper() in self._load()
