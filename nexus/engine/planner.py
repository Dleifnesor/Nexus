"""LLM planner: chooses the next action within a phase."""
from __future__ import annotations

from ..llm.prompts import SYSTEM_PLANNER, planner_prompt
from ..llm.provider import BaseProvider, LLMError
from ..llm.schema import ActionProposal
from ..logging_ import get_logger
from ..tools.registry import Registry

log = get_logger(__name__)


class Planner:
    def __init__(self, provider: BaseProvider, registry: Registry, objective: str = ""):
        self.provider = provider
        self.registry = registry
        self.objective = objective

    def next_action(self, phase: str, phase_goal: str, context: str) -> ActionProposal:
        tools = self.registry.describe_for_phase(phase)
        prompt = planner_prompt(phase, phase_goal, tools, context, objective=self.objective)
        try:
            proposal = self.provider.generate_structured(prompt, ActionProposal, system=SYSTEM_PLANNER)
        except (LLMError, ValueError) as e:
            log.warning("Planner failed (%s); finishing phase defensively.", e)
            return ActionProposal(action_type="finish_phase", rationale=f"planner error: {e}")
        # Validate tool references
        if proposal.action_type == "run_tool":
            if not proposal.tool or self.registry.get(proposal.tool) is None:
                log.warning("Planner referenced unknown tool '%s'; finishing phase.", proposal.tool)
                return ActionProposal(action_type="finish_phase", rationale="unknown tool referenced")
            if not proposal.target:
                return ActionProposal(action_type="finish_phase", rationale="no target provided")
        return proposal
