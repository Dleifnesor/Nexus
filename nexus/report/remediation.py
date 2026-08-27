"""LLM-generated remediation guidance per finding (including non-CVE findings)."""
from __future__ import annotations

import json

from ..llm.prompts import SYSTEM_REMEDIATION, remediation_prompt
from ..llm.provider import BaseProvider, LLMError
from ..llm.schema import RemediationOutput
from ..logging_ import get_logger
from ..storage.db import Database

log = get_logger(__name__)


class RemediationGenerator:
    def __init__(self, provider: BaseProvider, db: Database, run_id: str):
        self.provider = provider
        self.db = db
        self.run_id = run_id

    def generate_all(self) -> int:
        count = 0
        for f in self.db.list_findings(self.run_id):
            if self.db.get_remediation(f["id"]):
                continue
            cve_ids = json.loads(f["cve_ids_json"] or "[]")
            rem = self._generate(f["title"], f["description"] or "", f["evidence"] or "", cve_ids)
            self.db.add_remediation(
                f["id"], rem.summary, rem.steps_md, rem.references, generated_by=self.provider.cfg.model
            )
            count += 1
        return count

    def _generate(self, title: str, description: str, evidence: str, cve_ids: list[str]) -> RemediationOutput:
        prompt = remediation_prompt(title, description, evidence, cve_ids)
        try:
            return self.provider.generate_structured(prompt, RemediationOutput, system=SYSTEM_REMEDIATION)
        except (LLMError, ValueError) as e:
            log.warning("Remediation generation failed for '%s': %s", title, e)
            return RemediationOutput(
                summary="Automated remediation generation failed; manual review required.",
                steps_md="- Review the finding evidence and apply vendor guidance.",
                references=[f"https://nvd.nist.gov/vuln/detail/{c}" for c in cve_ids],
            )
