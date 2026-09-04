"""Distill a reusable skill from a completed run and add it to the library.

After a run, the engine summarizes what was found and which actions produced results, then asks
the LLM to write a transferable playbook. It is upserted by name (updated, not duplicated) so
the library converges instead of accumulating near-duplicates.

The distilled body is model-authored and treated as untrusted reference text: it can only ever
influence which registered tool the planner picks next, never introduce a command or bypass the
scope gate.
"""
from __future__ import annotations

import json

from ..llm.prompts import SYSTEM_SKILL, skill_distill_prompt
from ..llm.provider import BaseProvider, LLMError
from ..llm.schema import SkillDraft
from ..logging_ import get_logger
from ..storage.db import Database
from .store import Skill, SkillStore

log = get_logger(__name__)


class SkillWriter:
    def __init__(self, provider: BaseProvider, db: Database, run_id: str, store: SkillStore):
        self.provider = provider
        self.db = db
        self.run_id = run_id
        self.store = store

    def learn(self, objective: str = "") -> Skill | None:
        findings = self.db.list_findings(self.run_id)
        if not findings:
            return None
        findings_summary = _summarize_findings(findings)
        actions_summary = _summarize_actions(self.db.list_assets(self.run_id))
        prompt = skill_distill_prompt(objective, findings_summary, actions_summary)
        try:
            draft = self.provider.generate_structured(prompt, SkillDraft, system=SYSTEM_SKILL)
        except (LLMError, ValueError) as e:
            log.warning("Skill distillation failed: %s", e)
            return None
        if not draft.name or not draft.body:
            return None
        skill = Skill(
            name=draft.name,
            description=draft.description or draft.name,
            triggers=[t.lower() for t in draft.triggers][:12],
            body=draft.body,
        )
        stored = self.store.upsert(skill)
        if stored:
            log.info("Learned skill '%s' from run %s", stored.name, self.run_id)
        return stored


def _summarize_findings(findings, limit: int = 25) -> str:
    lines = []
    for f in findings[:limit]:
        cves = json.loads(f["cve_ids_json"] or "[]")
        suffix = f" [{' '.join(cves[:3])}]" if cves else ""
        lines.append(f"- {f['severity']}: {f['title']}{suffix} (via {f['source_tool'] or '?'})")
    return "\n".join(lines) or "none"


def _summarize_actions(assets, limit: int = 30) -> str:
    techs = [a["value"] for a in assets if a["type"] == "service"][:limit]
    return ", ".join(techs) or "none"
