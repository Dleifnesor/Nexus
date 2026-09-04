"""Structured schemas the planner LLM must produce.

The planner never emits free-form shell. It emits an ActionProposal chosen from the
available tool registry; the executor validates it and applies the scope gate before
running anything.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ActionProposal(BaseModel):
    """A single next action proposed by the planner."""

    action_type: Literal["run_tool", "discover_tool", "finish_phase"] = Field(
        description="run_tool to execute a known tool; discover_tool to web-search for a new "
        "tool; finish_phase when nothing useful remains in this phase."
    )
    tool: str | None = Field(default=None, description="Registry tool name for run_tool.")
    target: str | None = Field(default=None, description="Target host/domain/url.")
    args: list[str] = Field(default_factory=list, description="Extra arguments for the tool template.")
    rationale: str = Field(default="", description="Why this action was chosen.")
    discovery_query: str | None = Field(
        default=None, description="Search query when action_type is discover_tool."
    )


class RecoveryDecision(BaseModel):
    """How to recover from a failed action."""

    strategy: Literal["retry", "alternative_tool", "skip"] = "skip"
    alternative_tool: str | None = None
    args: list[str] = Field(default_factory=list)
    reason: str = ""


class RemediationOutput(BaseModel):
    summary: str = ""
    steps_md: str = ""
    references: list[str] = Field(default_factory=list)


class EngagementBrief(BaseModel):
    """Structured engagement parameters extracted from a free-text operator prompt."""

    scope: list[str] = Field(
        default_factory=list,
        description="In-scope targets as IPs, CIDR ranges, or domains, verbatim from the prompt.",
    )
    exclusions: list[str] = Field(
        default_factory=list, description="Targets explicitly excluded from the engagement."
    )
    objective: str = Field(
        default="", description="One or two sentences describing the goal of the assessment."
    )
    focus: list[str] = Field(
        default_factory=list,
        description="Short focus tags implied by the prompt, e.g. web-auth, secrets, ad, tls.",
    )


class SkillDraft(BaseModel):
    """A reusable playbook the engine distills from a completed run."""

    name: str = Field(description="Short kebab-case identifier, e.g. wordpress-enum.")
    description: str = Field(description="One line: when this playbook applies.")
    triggers: list[str] = Field(
        default_factory=list, description="Lowercase keywords that signal this skill is relevant."
    )
    body: str = Field(description="The procedure: which tools, in what order, what to look for.")
