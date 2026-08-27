"""NVD (National Vulnerability Database) enrichment client.

Looks up CVE details (CVSS, description) and keyword-searches for CVEs matching a
product/version string. Responses are cached in the DB to respect NVD rate limits.
"""
from __future__ import annotations

from typing import Optional

import httpx

from ..logging_ import get_logger
from ..storage.db import Database

log = get_logger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDClient:
    def __init__(self, db: Database, api_key: Optional[str] = None):
        self.db = db
        self.api_key = api_key

    def _headers(self) -> dict:
        return {"apiKey": self.api_key} if self.api_key else {}

    def lookup_cve(self, cve_id: str) -> Optional[dict]:
        cve_id = cve_id.upper()
        cache_key = f"nvd:cve:{cve_id}"
        cached = self.db.cache_get(cache_key)
        if cached is not None:
            return cached
        try:
            resp = httpx.get(NVD_BASE, params={"cveId": cve_id}, headers=self._headers(), timeout=30)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            log.warning("NVD lookup failed for %s: %s", cve_id, e)
            return None
        data = _summarize(resp.json())
        if data:
            self.db.cache_put(cache_key, "nvd", data)
        return data

    def search_product(self, product: str, version: str = "", limit: int = 5) -> list[dict]:
        keyword = f"{product} {version}".strip()
        if not keyword:
            return []
        cache_key = f"nvd:kw:{keyword.lower()}"
        cached = self.db.cache_get(cache_key)
        if cached is not None:
            return cached.get("items", [])
        try:
            resp = httpx.get(
                NVD_BASE,
                params={"keywordSearch": keyword, "resultsPerPage": limit},
                headers=self._headers(),
                timeout=30,
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            log.warning("NVD search failed for %s: %s", keyword, e)
            return []
        items = []
        for vuln in resp.json().get("vulnerabilities", [])[:limit]:
            s = _summarize({"vulnerabilities": [vuln]})
            if s:
                items.append(s)
        self.db.cache_put(cache_key, "nvd", {"items": items})
        return items


def _summarize(payload: dict) -> Optional[dict]:
    vulns = payload.get("vulnerabilities", [])
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})
    cve_id = cve.get("id", "")
    descs = cve.get("descriptions", [])
    description = next((d["value"] for d in descs if d.get("lang") == "en"), "")
    score, severity = _extract_cvss(cve.get("metrics", {}))
    return {"cve_id": cve_id, "description": description, "cvss": score, "severity": severity}


def _extract_cvss(metrics: dict) -> tuple[Optional[float], str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or metrics[key][0].get("baseSeverity") or ""
            return score, (sev or _sev_from_score(score)).lower()
    return None, "unknown"


def _sev_from_score(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"
