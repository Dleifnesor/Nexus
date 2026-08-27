"""Prompt templates for planning, recovery, and remediation."""
from __future__ import annotations

SYSTEM_PLANNER = (
    "You are Nexus, an autonomous security assessment planner operating on an authorized "
    "engagement. You select the single most useful next action for the current phase using "
    "only the tools listed. You never invent tool names for run_tool. You never suggest "
    "destructive actions. You prefer breadth (discover assets) before depth. When no useful "
    "action remains for the phase, choose finish_phase."
)

SYSTEM_RECOVERY = (
    "You are Nexus's error-recovery advisor. Given a failed action and its error, decide "
    "whether to retry, switch to an alternative tool, or skip. Be concise and practical."
)

SYSTEM_REMEDIATION = (
    "You are a senior security engineer writing clear, actionable remediation guidance for a "
    "client report. Be specific, prioritize by risk, and include concrete configuration or "
    "patch steps. Avoid fluff."
)


def planner_prompt(phase: str, phase_goal: str, tools: str, context: str) -> str:
    return (
        f"Current phase: {phase}\nPhase goal: {phase_goal}\n\n"
        f"Available tools (name: when_to_use):\n{tools}\n\n"
        f"Engagement context so far:\n{context}\n\n"
        "Choose the single best next action. If the phase goal is met or no listed tool "
        "would add value, choose finish_phase. If a needed capability is missing from the "
        "tool list, choose discover_tool with a precise search query."
    )


def recovery_prompt(tool: str, target: str, cmd: str, error: str, tools: str) -> str:
    return (
        f"Failed action:\n  tool={tool}\n  target={target}\n  cmd={cmd}\n\n"
        f"Error:\n{error}\n\nAvailable alternative tools:\n{tools}\n\n"
        "Decide the recovery strategy."
    )


def remediation_prompt(title: str, description: str, evidence: str, cve_ids: list[str]) -> str:
    cves = ", ".join(cve_ids) if cve_ids else "none"
    return (
        f"Finding: {title}\nDescription: {description}\nEvidence:\n{evidence}\n"
        f"Associated CVEs: {cves}\n\n"
        "Write remediation guidance: a one-paragraph summary, ordered concrete steps in "
        "markdown, and reference URLs."
    )
