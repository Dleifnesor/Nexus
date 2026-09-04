"""Vulners.com enrichment client.

Provides extra CVE metadata and exploit-maturity signals (e.g. whether a Metasploit module
or public exploit is referenced). Uses the public lucene search endpoint; an API key enables
higher limits. Responses are cached in the DB.
"""
from __future__ import annotations

import httpx

from ..logging_ import get_logger
from ..storage.db import Database

log = get_logger(__name__)

VULNERS_API = "https://vulners.com/api/v3/search/lucene/"


class VulnersClient:
    def __init__(self, db: Database, api_key: str | None = None):
        self.db = db
        self.api_key = api_key

    def search(self, cve_id: str, limit: int = 5) -> list[dict]:
        cve_id = cve_id.upper()
        cache_key = f"vulners:{cve_id}"
        cached = self.db.cache_get(cache_key, max_age=604800)
        if cached is not None:
            return cached.get("items", [])
        payload: dict = {"query": f"cve:{cve_id}", "size": limit}
        if self.api_key:
            payload["apiKey"] = self.api_key
        try:
            resp = httpx.post(VULNERS_API, json=payload, timeout=30)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            log.warning("Vulners search failed for %s: %s", cve_id, e)
            return []
        items = []
        for doc in resp.json().get("data", {}).get("search", []) or []:
            source = doc.get("_source", {})
            items.append(
                {
                    "title": source.get("title", ""),
                    "href": source.get("href", ""),
                    "cvss": source.get("cvss", {}).get("score"),
                    "bulletin_family": source.get("bulletinFamily", ""),
                }
            )
        self.db.cache_put(cache_key, "vulners", {"items": items})
        return items

    def has_public_exploit(self, cve_id: str) -> bool:
        """True if a Metasploit module or public exploit is referenced for the CVE."""
        for doc in self.search(cve_id):
            family = (doc.get("bulletin_family") or "").lower()
            title = (doc.get("title") or "").lower()
            if family in ("metasploit", "exploit", "exploitdb") or "metasploit" in title:
                return True
        return False
