"""Attach CVE/CVSS/EPSS/KEV data to findings using NVD, OSV, KEV and EPSS."""
from __future__ import annotations

import json
import re

from ..enrich.epss import EpssClient
from ..enrich.exploitdb import ExploitDBClient
from ..enrich.github_poc import GitHubPocClient
from ..enrich.kev import KevClient
from ..enrich.nvd import NVDClient
from ..enrich.osv import OSVClient
from ..enrich.vulners import VulnersClient
from ..logging_ import get_logger
from ..storage.db import Database

log = get_logger(__name__)

_VER_RE = re.compile(r"([A-Za-z][\w .+-]*?)\s+([0-9]+(?:\.[0-9]+)+)")


class FindingEnricher:
    def __init__(
        self,
        db: Database,
        run_id: str,
        nvd: NVDClient,
        osv: OSVClient,
        kev: KevClient | None = None,
        epss: EpssClient | None = None,
        exploitdb: ExploitDBClient | None = None,
        github: GitHubPocClient | None = None,
        vulners: VulnersClient | None = None,
    ):
        self.db = db
        self.run_id = run_id
        self.nvd = nvd
        self.osv = osv
        self.kev = kev
        self.epss = epss
        self.exploitdb = exploitdb
        self.github = github
        self.vulners = vulners

    def enrich_all(self) -> int:
        enriched = 0
        for f in self.db.list_findings(self.run_id):
            cve_ids = json.loads(f["cve_ids_json"] or "[]")
            best_score = f["cvss"]
            best_epss = f["epss"]
            severity = f["severity"] or "info"
            exploit_available = bool(f["exploit_available"])

            # 1) enrich CVEs already extracted from tool output
            for cve in list(cve_ids):
                data = self.nvd.lookup_cve(cve)
                if data and data.get("cvss") is not None:
                    if best_score is None or data["cvss"] > best_score:
                        best_score = data["cvss"]
                        severity = data.get("severity", severity)
                if self._exploit_signal(cve):
                    exploit_available = True
                ep = self._epss(cve)
                if ep is not None and (best_epss is None or ep > best_epss):
                    best_epss = ep

            # 2) try product/version -> CVE discovery (CPE-first, keyword fallback)
            product, version = _extract_product_version(f["title"], f["evidence"] or "")
            if product and version:
                candidates = self.nvd.search_cpe(product, version, limit=5)
                if not candidates:
                    candidates = self.nvd.search_product(product, version, limit=3)
                for item in candidates:
                    cid = item.get("cve_id")
                    if cid and cid not in cve_ids:
                        cve_ids.append(cid)
                    if item.get("cvss") is not None and (best_score is None or item["cvss"] > best_score):
                        best_score = item["cvss"]
                        severity = item.get("severity", severity)
                for v in self.osv.query(product, version):
                    for c in v.get("cve_ids", []):
                        if c not in cve_ids:
                            cve_ids.append(c)

            # 3) KEV/exploit/EPSS for any newly added CVEs
            for cve in cve_ids:
                if self._exploit_signal(cve):
                    exploit_available = True
                ep = self._epss(cve)
                if ep is not None and (best_epss is None or ep > best_epss):
                    best_epss = ep

            original = json.loads(f["cve_ids_json"] or "[]")
            changed = (
                cve_ids != original
                or best_score != f["cvss"]
                or best_epss != f["epss"]
                or exploit_available != bool(f["exploit_available"])
            )
            if changed:
                self.db.update_finding_cve(
                    f["id"], cve_ids, best_score, severity, best_epss, exploit_available
                )
                enriched += 1
        return enriched

    def _kev(self, cve_id: str) -> bool:
        return bool(self.kev and self.kev.is_known_exploited(cve_id))

    def _exploit_signal(self, cve_id: str) -> bool:
        """True if any source indicates a public/active exploit exists for the CVE."""
        if self._kev(cve_id):
            return True
        if self.exploitdb and self.exploitdb.has_exploit(cve_id):
            return True
        if self.github and self.github.has_poc(cve_id):
            return True
        if self.vulners and self.vulners.has_public_exploit(cve_id):
            return True
        return False

    def _epss(self, cve_id: str) -> float | None:
        if not self.epss:
            return None
        data = self.epss.score(cve_id)
        return data.get("epss") if data else None


def _extract_product_version(title: str, evidence: str) -> tuple[str, str]:
    for text in (title, evidence):
        m = _VER_RE.search(text or "")
        if m:
            return m.group(1).strip(), m.group(2).strip()
    return "", ""
