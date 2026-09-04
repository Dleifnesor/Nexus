"""FIRST EPSS (Exploit Prediction Scoring System) client.

EPSS estimates the probability a CVE will be exploited in the next 30 days.
Scores are looked up per CVE and cached in the DB.
"""
from __future__ import annotations

import httpx

from ..logging_ import get_logger
from ..storage.db import Database

log = get_logger(__name__)

EPSS_API = "https://api.first.org/data/v1/epss"


class EpssClient:
    def __init__(self, db: Database):
        self.db = db

    def score(self, cve_id: str) -> dict | None:
        cve_id = cve_id.upper()
        cache_key = f"epss:{cve_id}"
        cached = self.db.cache_get(cache_key)
        if cached is not None:
            return cached
        try:
            resp = httpx.get(EPSS_API, params={"cve": cve_id}, timeout=30)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            log.warning("EPSS lookup failed for %s: %s", cve_id, e)
            return None
        data = resp.json().get("data") or []
        if not data:
            return None
        # The FIRST API returns epss/percentile as strings; coerce to float so downstream
        # numeric comparisons and risk math don't hit str-vs-float TypeErrors.
        result = {
            "epss": _to_float(data[0].get("epss")),
            "percentile": _to_float(data[0].get("percentile")),
        }
        self.db.cache_put(cache_key, "epss", result)
        return result


def _to_float(value) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None
