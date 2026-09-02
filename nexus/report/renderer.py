"""Render findings into HTML, PDF (optional), and JSON deliverables."""
from __future__ import annotations

import json
import time
from pathlib import Path

from jinja2 import Environment

from ..logging_ import get_logger
from ..storage.db import Database
from .risk import (
    _CRITICAL_ROLE_RE,
    _IP_RE,
    _SEVERITY_ORDER,
    attack_techniques,
    build_attack_graph,
    risk_level,
    weighted_risk,
)

log = get_logger(__name__)

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Nexus Report - {{ run.id }}</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;color:#1a1a1a;}
 h1,h2,h3{color:#0b3d5c;}
 .meta{color:#555;font-size:.9rem;}
 .sev{display:inline-block;padding:.1rem .5rem;border-radius:4px;color:#fff;font-size:.8rem;}
 .critical{background:#7b0000}.high{background:#c0392b}.medium{background:#e67e22}
 .low{background:#f1c40f;color:#222}.info{background:#3498db}.unknown{background:#7f8c8d}
 table{border-collapse:collapse;width:100%;margin:1rem 0}
 th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;vertical-align:top}
 th{background:#f4f7f9}
 .finding{border:1px solid #e0e0e0;border-radius:6px;padding:1rem;margin:1rem 0}
 pre{background:#f6f8fa;padding:.6rem;overflow:auto;white-space:pre-wrap}
 .gap{background:#fff7e6;border-left:4px solid #e67e22;padding:.5rem;margin:.4rem 0}
</style></head><body>
<h1>Nexus Vulnerability Assessment Report</h1>
<p class="meta">Run {{ run.id }} &middot; Mode: {{ run.mode }} &middot; Generated {{ generated }}</p>

<h2>Executive Summary</h2>
<p>The engagement discovered <strong>{{ assets|length }}</strong> assets and
<strong>{{ findings|length }}</strong> findings
({{ counts.critical }} critical, {{ counts.high }} high, {{ counts.medium }} medium,
{{ counts.low }} low). {{ gaps|length }} coverage gap(s) were recorded.</p>

<h2>Severity Overview</h2>
<table><tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr>
<tr><td>{{ counts.critical }}</td><td>{{ counts.high }}</td><td>{{ counts.medium }}</td>
<td>{{ counts.low }}</td><td>{{ counts.info }}</td></tr></table>

<h2>Findings</h2>
{% for f in findings %}
<div class="finding">
 <h3><span class="sev {{ f.severity }}">{{ f.severity|upper }}</span> {{ f.title }}</h3>
 <p class="meta">Source: {{ f.source_tool }}{% if f.cvss %} &middot; CVSS {{ f.cvss }}{% endif %}
 {% if f.cve_ids %} &middot; {{ f.cve_ids|join(', ') }}{% endif %}
 {% if f.risk is not none %} &middot; Risk {{ f.risk }} ({{ f.risk_level }}){% endif %}
 {% if f.epss is not none %} &middot; EPSS {{ f.epss }}{% endif %}
 {% if f.criticality and f.criticality > 1.0 %} &middot; Criticality x{{ f.criticality }}{% endif %}
 {% if f.exploit_available %} &middot; <strong>ACTIVELY EXPLOITED</strong>{% endif %}</p>
 {% if f.attack_techniques %}<p class="meta">ATT&amp;CK: {{ f.attack_techniques|join(', ') }}</p>{% endif %}
 {% if f.description %}<p>{{ f.description }}</p>{% endif %}
 {% if f.evidence %}<pre>{{ f.evidence }}</pre>{% endif %}
 {% if f.remediation %}
 <h4>Remediation</h4>
 <p>{{ f.remediation.summary }}</p>
 <pre>{{ f.remediation.steps_md }}</pre>
 {% if f.remediation.references %}<p class="meta">References: {{ f.remediation.references|join(', ') }}</p>{% endif %}
 {% endif %}
</div>
{% endfor %}

<h2>Assets Discovered</h2>
<table><tr><th>Type</th><th>Value</th><th>Source</th><th>Phase</th></tr>
{% for a in assets %}<tr><td>{{ a.type }}</td><td>{{ a.value }}</td><td>{{ a.source }}</td><td>{{ a.discovered_phase }}</td></tr>{% endfor %}
</table>

<h2>Attack Path</h2>
<pre class="mermaid">{{ attack_graph }}</pre>

<h2>Coverage Gaps</h2>
{% if gaps %}{% for g in gaps %}<div class="gap"><strong>{{ g.kind }}</strong>: {{ g.message }}
{% if g.recovery_action %}<em>(recovery: {{ g.recovery_action }})</em>{% endif %}</div>{% endfor %}
{% else %}<p>None recorded.</p>{% endif %}
</body></html>
"""

DIFF_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Nexus Diff - {{ run }} vs {{ other_run }}</title>
<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2rem}
h1,h2{color:#0b3d5c}.added{color:#1a7f37}.removed{color:#c0392b}.changed{color:#b9770e}
.finding{border:1px solid #ddd;border-radius:6px;padding:.6rem;margin:.5rem 0}</style></head><body>
<h1>Finding diff: {{ run }} vs {{ other_run }}</h1>

<h2>Added ({{ added|length }})</h2>
{% for f in added %}<div class="finding added">{{ f.severity|upper }}: {{ f.title }}</div>{% endfor %}

<h2>Removed ({{ removed|length }})</h2>
{% for f in removed %}<div class="finding removed">{{ f.severity|upper }}: {{ f.title }}</div>{% endfor %}

<h2>Changed ({{ changed|length }})</h2>
{% for c in changed %}<div class="finding changed">{{ c.before.title }}:
{{ c.before.severity }}/{{ c.before.cvss }} &rarr; {{ c.after.severity }}/{{ c.after.cvss }}</div>{% endfor %}
</body></html>
"""


class Renderer:
    def __init__(self, db: Database, run_id: str, out_dir: Path):
        self.db = db
        self.run_id = run_id
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def render(self) -> dict[str, str]:
        model = self._build_model()
        outputs: dict[str, str] = {}

        json_path = self.out_dir / f"report-{self.run_id}.json"
        json_path.write_text(json.dumps(model, indent=2, default=str), encoding="utf-8")
        outputs["json"] = str(json_path)

        sarif_path = self.out_dir / f"report-{self.run_id}.sarif"
        sarif_path.write_text(json.dumps(self._build_sarif(model), indent=2), encoding="utf-8")
        outputs["sarif"] = str(sarif_path)

        env = Environment(autoescape=True)
        html = env.from_string(HTML_TEMPLATE).render(**model)
        html_path = self.out_dir / f"report-{self.run_id}.html"
        html_path.write_text(html, encoding="utf-8")
        outputs["html"] = str(html_path)

        pdf_path = self.out_dir / f"report-{self.run_id}.pdf"
        if self._render_pdf(html, pdf_path):
            outputs["pdf"] = str(pdf_path)
        return outputs

    def _build_sarif(self, model: dict) -> dict:
        levels = {"critical": "error", "high": "error", "medium": "warning"}
        results = []
        for f in model["findings"]:
            rule_id = (f["cve_ids"] or [f["title"]])[0]
            results.append(
                {
                    "ruleId": rule_id,
                    "level": levels.get(f["severity"], "note"),
                    "message": {"text": f["title"]},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f["evidence"] or f["source_tool"]}
                            }
                        }
                    ],
                }
            )
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Nexus", "informationUri": "https://github.com/nexus"}},
                    "results": results,
                }
            ],
        }

    def _render_pdf(self, html: str, pdf_path: Path) -> bool:
        try:
            from weasyprint import HTML  # optional dependency
        except Exception:
            log.info("WeasyPrint not installed; skipping PDF (install nexus-scanner[pdf]).")
            return False
        try:
            HTML(string=html).write_pdf(str(pdf_path))
            return True
        except Exception as e:
            log.warning("PDF rendering failed: %s", e)
            return False

    def _build_model(self) -> dict:
        run = self.db.get_run(self.run_id)
        findings_rows = self.db.list_findings(self.run_id)
        counts = {k: 0 for k in ("critical", "high", "medium", "low", "info", "unknown")}
        findings = []
        for f in findings_rows:
            sev = (f["severity"] or "info").lower()
            counts[sev] = counts.get(sev, 0) + 1
            rem_row = self.db.get_remediation(f["id"])
            epss = f["epss"]
            exploit = bool(f["exploit_available"])
            criticality = self._finding_criticality(f)
            score = weighted_risk(f["cvss"], epss, exploit, criticality)
            findings.append(
                {
                    "title": f["title"],
                    "description": f["description"],
                    "severity": sev,
                    "cvss": f["cvss"],
                    "epss": epss,
                    "exploit_available": exploit,
                    "criticality": criticality,
                    "risk": score,
                    "risk_level": risk_level(score),
                    "attack_techniques": attack_techniques(f["title"], f["description"] or "", f["source_tool"]),
                    "cve_ids": json.loads(f["cve_ids_json"] or "[]"),
                    "evidence": f["evidence"],
                    "source_tool": f["source_tool"],
                    "remediation": None
                    if not rem_row
                    else {
                        "summary": rem_row["summary"],
                        "steps_md": rem_row["steps_md"],
                        "references": json.loads(rem_row["references_json"] or "[]"),
                    },
                }
            )
        findings.sort(key=lambda x: _SEVERITY_ORDER.get(x["severity"], 5))
        assets = [dict(a) for a in self.db.list_assets(self.run_id)]
        gaps = [dict(g) for g in self.db.list_coverage_gaps(self.run_id)]
        return {
            "run": {"id": run["id"], "mode": run["mode"]} if run else {"id": self.run_id, "mode": ""},
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
            "counts": counts,
            "findings": findings,
            "assets": assets,
            "gaps": gaps,
            "attack_graph": build_attack_graph(assets, findings),
        }

    def _finding_criticality(self, f) -> float:
        text = f"{f['title']} {f['evidence'] or ''}"
        exposed = False
        for ip in _IP_RE.findall(text):
            exp = self.db.cache_get(f"exposure:{ip}")
            if exp and (
                (exp.get("shodan") or {}).get("tags")
                or (exp.get("greynoise") or {}).get("classification") == "malicious"
            ):
                exposed = True
                break
        critical = bool(_CRITICAL_ROLE_RE.search(text.lower()))
        if critical and exposed:
            return 1.5
        if critical:
            return 1.3
        if exposed:
            return 1.2
        return 1.0

    def render_diff(self, other_run_id: str) -> dict[str, str]:
        """Render a comparison of this run against a previous run."""
        cur = {self._finding_key(f): dict(f) for f in self.db.list_findings(self.run_id)}
        other = {self._finding_key(f): dict(f) for f in self.db.list_findings(other_run_id)}
        added = [v for k, v in cur.items() if k not in other]
        removed = [v for k, v in other.items() if k not in cur]
        changed = []
        for k, v in cur.items():
            if k in other and (v["severity"], v["cvss"]) != (other[k]["severity"], other[k]["cvss"]):
                changed.append({"before": other[k], "after": v})
        model = {
            "run": self.run_id,
            "other_run": other_run_id,
            "added": added,
            "removed": removed,
            "changed": changed,
        }
        json_path = self.out_dir / f"diff-{other_run_id}-{self.run_id}.json"
        json_path.write_text(json.dumps(model, indent=2, default=str), encoding="utf-8")
        html = Environment(autoescape=True).from_string(DIFF_TEMPLATE).render(**model)
        html_path = self.out_dir / f"diff-{other_run_id}-{self.run_id}.html"
        html_path.write_text(html, encoding="utf-8")
        return {"json": str(json_path), "html": str(html_path)}

    @staticmethod
    def _finding_key(f) -> str:
        return (f["title"] or "").strip().lower()
