"""LLM-driven error recovery.

On a failed action, ask the LLM whether to retry, switch to an alternative tool, or skip.
Recovery attempts are bounded; when exhausted the failure is recorded as a coverage gap so
the report never silently omits attempted-but-failed areas.
"""
from __future__ import annotations

from ..llm.prompts import SYSTEM_RECOVERY, recovery_prompt
from ..llm.provider import BaseProvider, LLMError
from ..llm.schema import RecoveryDecision
from ..logging_ import get_logger
from ..storage.db import Database
from ..tools.registry import Registry

log = get_logger(__name__)


class Recovery:
    def __init__(self, provider: BaseProvider, registry: Registry, db: Database, run_id: str):
        self.provider = provider
        self.registry = registry
        self.db = db
        self.run_id = run_id

    def decide(self, tool: str, target: str, cmd: str, error: str) -> RecoveryDecision:
        tools = self.registry.describe_for_phase("")  # all tools
        prompt = recovery_prompt(tool, target, cmd, error, tools)
        try:
            decision = self.provider.generate_structured(prompt, RecoveryDecision, system=SYSTEM_RECOVERY)
        except (LLMError, ValueError) as e:
            log.warning("Recovery LLM failed (%s); skipping.", e)
            return RecoveryDecision(strategy="skip", reason=f"recovery error: {e}")
        if decision.strategy == "alternative_tool":
            if not decision.alternative_tool or self.registry.get(decision.alternative_tool) is None:
                return RecoveryDecision(strategy="skip", reason="invalid alternative tool")
        return decision

    def record_gap(self, tool: str, target: str, error: str, recovery_action: str) -> None:
        self.db.add_error(
            self.run_id,
            kind="coverage_gap",
            message=f"{tool} on {target}: {error}",
            recovery_action=recovery_action,
            is_coverage_gap=True,
        )
        log.info("Recorded coverage gap: %s on %s", tool, target)
