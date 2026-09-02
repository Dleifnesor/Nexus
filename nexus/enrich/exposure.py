"""Internet exposure lookups (GreyNoise + Shodan InternetDB).

Both endpoints used here are free and keyless:
- GreyNoise Community API classifies an IP as malicious/benign and reports when it was last
  observed scanning.
- Shodan InternetDB (no key) returns open ports, hostnames, tags, and known CVEs for an IP.

Results are cached in the DB. Used during reporting to annotate internet-facing assets.
"""
from __future__ import annotations

import httpx

from ..logging_ import get_logger
from ..storage.db import Database

log = get_logger(__name__)

GREYNOISE_API = "https://api.greynoise.io/v3/community"
SHODAN_INTERNETDB = "https://internetdb.shodan.io"


class ExposureClient:
    def __init__(self, db: Database):
        self.db = db

    def check_ip(self, ip: str) -> dict:
        cache_key = f"exposure:{ip}"
        cached = self.db.cache_get(cache_key)
        if cached is not None:
            return cached
        result = {"ip": ip, "greynoise": self._greynoise(ip), "shodan": self._shodan(ip)}
        self.db.cache_put(cache_key, "exposure", result)
        return result

    def _greynoise(self, ip: str) -> dict:
        try:
            resp = httpx.get(f"{GREYNOISE_API}/{ip}", timeout=20)
            if resp.status_code == 404:
                return {}
            resp.raise_for_status()
            data = resp.json()
            return {
                "classification": data.get("classification"),
                "name": data.get("name"),
                "last_seen": data.get("last_seen"),
                "link": data.get("link"),
            }
        except httpx.HTTPError as e:
            log.warning("GreyNoise lookup failed for %s: %s", ip, e)
            return {}

    def _shodan(self, ip: str) -> dict:
        try:
            resp = httpx.get(f"{SHODAN_INTERNETDB}/{ip}", timeout=20)
            if resp.status_code == 404:
                return {}
            resp.raise_for_status()
            data = resp.json()
            return {
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "tags": data.get("tags", []),
                "vulns": data.get("vulns", []),
            }
        except httpx.HTTPError as e:
            log.warning("Shodan InternetDB lookup failed for %s: %s", ip, e)
            return {}
