"""NVD (National Vulnerability Database) enrichment client.

Looks up CVE details (CVSS, description) and keyword-searches for CVEs matching a
product/version string. Responses are cached in the DB to respect NVD rate limits.
"""
from __future__ import annotations

import httpx

from ..logging_ import get_logger
from ..storage.db import Database
from ._http import RateLimiter, request_with_retry

log = get_logger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_BASE = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

# NVD public limits: ~5 requests / 30s without a key, ~50 / 30s with one.
_INTERVAL_NO_KEY = 6.0
_INTERVAL_KEY = 0.6
_TTL = 7 * 24 * 3600  # CVE records change slowly; refetch weekly


class NVDClient:
    def __init__(self, db: Database, api_key: str | None = None):
        self.db = db
        self.api_key = api_key
        self._limiter = RateLimiter(_INTERVAL_KEY if api_key else _INTERVAL_NO_KEY)

    def _headers(self) -> dict:
        return {"apiKey": self.api_key} if self.api_key else {}

    def _get(self, url: str, params: dict) -> httpx.Response:
        return request_with_retry(
            "GET", url, params=params, headers=self._headers(), timeout=30, limiter=self._limiter
        )

    def lookup_cve(self, cve_id: str) -> dict | None:
        cve_id = cve_id.upper()
        cache_key = f"nvd:cve:{cve_id}"
        cached = self.db.cache_get(cache_key, max_age=_TTL)
        if cached is not None:
            return cached
        try:
            resp = self._get(NVD_BASE, {"cveId": cve_id})
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
        cached = self.db.cache_get(cache_key, max_age=_TTL)
        if cached is not None:
            return cached.get("items", [])
        try:
            resp = self._get(NVD_BASE, {"keywordSearch": keyword, "resultsPerPage": limit})
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

    def search_cpe(self, product: str, version: str = "", limit: int = 5) -> list[dict]:
        """Resolve product/version to CPEs, then return CVEs matching those CPEs."""
        keyword = f"{product} {version}".strip()
        if not keyword:
            return []
        cache_key = f"nvd:cpe:{keyword.lower()}"
        cached = self.db.cache_get(cache_key, max_age=_TTL)
        if cached is not None:
            return cached.get("items", [])
        try:
            resp = self._get(CPE_BASE, {"keywordSearch": keyword, "resultsPerPage": limit})
        except httpx.HTTPError as e:
            log.warning("NVD CPE search failed for %s: %s", keyword, e)
            return []
        items: list[dict] = []
        for prod in resp.json().get("products", [])[:limit]:
            cpe_name = (prod.get("cpe") or {}).get("cpeName")
            if cpe_name:
                items.extend(self._cves_for_cpe(cpe_name, limit))
        self.db.cache_put(cache_key, "nvd", {"items": items})
        return items

    def _cves_for_cpe(self, cpe_name: str, limit: int = 5) -> list[dict]:
        cache_key = f"nvd:cves-for-cpe:{cpe_name}"
        cached = self.db.cache_get(cache_key, max_age=_TTL)
        if cached is not None:
            return cached.get("items", [])
        try:
            resp = self._get(NVD_BASE, {"cpeName": cpe_name, "resultsPerPage": limit})
        except httpx.HTTPError as e:
            log.warning("NVD CPE->CVE lookup failed for %s: %s", cpe_name, e)
            return []
        items = []
        for vuln in resp.json().get("vulnerabilities", [])[:limit]:
            s = _summarize({"vulnerabilities": [vuln]})
            if s:
                items.append(s)
        self.db.cache_put(cache_key, "nvd", {"items": items})
        return items


def _summarize(payload: dict) -> dict | None:
    vulns = payload.get("vulnerabilities", [])
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})
    cve_id = cve.get("id", "")
    descs = cve.get("descriptions", [])
    description = next((d["value"] for d in descs if d.get("lang") == "en"), "")
    score, severity = _extract_cvss(cve.get("metrics", {}))
    return {"cve_id": cve_id, "description": description, "cvss": score, "severity": severity}


def _extract_cvss(metrics: dict) -> tuple[float | None, str]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or metrics[key][0].get("baseSeverity") or ""
            return score, (sev or _sev_from_score(score)).lower()
    return None, "unknown"


def _sev_from_score(score: float | None) -> str:
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
