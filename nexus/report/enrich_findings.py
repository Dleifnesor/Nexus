"""Attach CVE/CVSS data to findings using NVD and OSV before rendering."""
from __future__ import annotations

import json
import re

from ..enrich.nvd import NVDClient
from ..enrich.osv import OSVClient
from ..logging_ import get_logger
from ..storage.db import Database

log = get_logger(__name__)

_VER_RE = re.compile(r"([A-Za-z][\w .+-]*?)\s+([0-9]+(?:\.[0-9]+)+)")


class FindingEnricher:
    def __init__(self, db: Database, run_id: str, nvd: NVDClient, osv: OSVClient):
        self.db = db
        self.run_id = run_id
        self.nvd = nvd
        self.osv = osv

    def enrich_all(self) -> int:
        enriched = 0
        for f in self.db.list_findings(self.run_id):
            cve_ids = json.loads(f["cve_ids_json"] or "[]")
            best_score = f["cvss"]
            severity = f["severity"] or "info"

            # 1) enrich CVEs already extracted from tool output
            for cve in list(cve_ids):
                data = self.nvd.lookup_cve(cve)
                if data and data.get("cvss") is not None:
                    if best_score is None or data["cvss"] > best_score:
                        best_score = data["cvss"]
                        severity = data.get("severity", severity)

            # 2) try product/version -> CVE discovery from the evidence/title
            product, version = _extract_product_version(f["title"], f["evidence"] or "")
            if product and version:
                for item in self.nvd.search_product(product, version, limit=3):
                    if item.get("cve_id") and item["cve_id"] not in cve_ids:
                        cve_ids.append(item["cve_id"])
                        if item.get("cvss") is not None and (best_score is None or item["cvss"] > best_score):
                            best_score = item["cvss"]
                            severity = item.get("severity", severity)
                for v in self.osv.query(product, version):
                    for c in v.get("cve_ids", []):
                        if c not in cve_ids:
                            cve_ids.append(c)

            if cve_ids != json.loads(f["cve_ids_json"] or "[]") or best_score != f["cvss"]:
                self.db.update_finding_cve(f["id"], cve_ids, best_score, severity)
                enriched += 1
        return enriched


def _extract_product_version(title: str, evidence: str) -> tuple[str, str]:
    for text in (title, evidence):
        m = _VER_RE.search(text or "")
        if m:
            return m.group(1).strip(), m.group(2).strip()
    return "", ""
