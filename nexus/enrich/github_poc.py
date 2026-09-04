"""GitHub public proof-of-concept (PoC) search.

Correlates a CVE with public exploit/PoC repositories on GitHub using the unauthenticated
search API (rate-limited) or an optional token. Results are cached in the DB.
"""
from __future__ import annotations

import httpx

from ..logging_ import get_logger
from ..storage.db import Database

log = get_logger(__name__)

GITHUB_SEARCH = "https://api.github.com/search/repositories"


class GitHubPocClient:
    def __init__(self, db: Database, token: str | None = None):
        self.db = db
        self.token = token

    def has_poc(self, cve_id: str) -> bool:
        cve_id = cve_id.upper()
        cache_key = f"github-poc:{cve_id}"
        cached = self.db.cache_get(cache_key, max_age=604800)
        if cached is not None:
            return bool(cached.get("found"))
        found = self._lookup(cve_id)
        self.db.cache_put(cache_key, "github-poc", {"found": found})
        return found

    def _lookup(self, cve_id: str) -> bool:
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            resp = httpx.get(GITHUB_SEARCH, params={"q": cve_id}, headers=headers, timeout=20)
            resp.raise_for_status()
            return int(resp.json().get("total_count", 0)) > 0
        except (httpx.HTTPError, ValueError) as e:
            log.warning("GitHub PoC search failed for %s: %s", cve_id, e)
            return False
