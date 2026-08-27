"""Render findings into HTML, PDF (optional), and JSON deliverables."""
from __future__ import annotations

import json
import time
from pathlib import Path

from jinja2 import Environment

from ..logging_ import get_logger
from ..storage.db import Database

log = get_logger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

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
 {% if f.cve_ids %} &middot; {{ f.cve_ids|join(', ') }}{% endif %}</p>
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

<h2>Coverage Gaps</h2>
{% if gaps %}{% for g in gaps %}<div class="gap"><strong>{{ g.kind }}</strong>: {{ g.message }}
{% if g.recovery_action %}<em>(recovery: {{ g.recovery_action }})</em>{% endif %}</div>{% endfor %}
{% else %}<p>None recorded.</p>{% endif %}
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

        env = Environment(autoescape=True)
        html = env.from_string(HTML_TEMPLATE).render(**model)
        html_path = self.out_dir / f"report-{self.run_id}.html"
        html_path.write_text(html, encoding="utf-8")
        outputs["html"] = str(html_path)

        pdf_path = self.out_dir / f"report-{self.run_id}.pdf"
        if self._render_pdf(html, pdf_path):
            outputs["pdf"] = str(pdf_path)
        return outputs

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
            findings.append(
                {
                    "title": f["title"],
                    "description": f["description"],
                    "severity": sev,
                    "cvss": f["cvss"],
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
        }
