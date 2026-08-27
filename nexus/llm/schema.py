"""Structured schemas the planner LLM must produce.

The planner never emits free-form shell. It emits an ActionProposal chosen from the
available tool registry; the executor validates it and applies the scope gate before
running anything.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class ActionProposal(BaseModel):
    """A single next action proposed by the planner."""

    action_type: Literal["run_tool", "discover_tool", "finish_phase"] = Field(
        description="run_tool to execute a known tool; discover_tool to web-search for a new "
        "tool; finish_phase when nothing useful remains in this phase."
    )
    tool: Optional[str] = Field(default=None, description="Registry tool name for run_tool.")
    target: Optional[str] = Field(default=None, description="Target host/domain/url.")
    args: list[str] = Field(default_factory=list, description="Extra arguments for the tool template.")
    rationale: str = Field(default="", description="Why this action was chosen.")
    discovery_query: Optional[str] = Field(
        default=None, description="Search query when action_type is discover_tool."
    )


class RecoveryDecision(BaseModel):
    """How to recover from a failed action."""

    strategy: Literal["retry", "alternative_tool", "skip"] = "skip"
    alternative_tool: Optional[str] = None
    args: list[str] = Field(default_factory=list)
    reason: str = ""


class RemediationOutput(BaseModel):
    summary: str = ""
    steps_md: str = ""
    references: list[str] = Field(default_factory=list)
