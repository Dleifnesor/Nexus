"""Select the skills relevant to the current engagement context and render them for the planner.

Matching is a cheap trigger/keyword scan against the context string (the same lightweight
approach used for ATT&CK mapping), so it adds no LLM cost. Relevant skill bodies are rendered
as a clearly-labelled reference block that the planner treats as data, not instructions.
"""
from __future__ import annotations

from .store import Skill

MAX_SKILLS = 4


def relevant(skills: list[Skill], context: str, focus: list[str] | None = None, limit: int = MAX_SKILLS) -> list[Skill]:
    haystack = (context or "").lower()
    focus_set = {f.lower() for f in (focus or [])}
    scored: list[tuple[int, Skill]] = []
    for skill in skills:
        score = 0
        for trig in skill.triggers:
            if trig and trig in haystack:
                score += 2
            if trig in focus_set:
                score += 3
        # a focus tag matching the skill name is a strong signal
        if skill.name in focus_set:
            score += 3
        if score:
            scored.append((score, skill))
    scored.sort(key=lambda s: s[0], reverse=True)
    return [s for _, s in scored[:limit]]


def render(skills: list[Skill]) -> str:
    if not skills:
        return ""
    blocks = ["Relevant playbooks (reference only; obey scope and the tool list):"]
    for s in skills:
        blocks.append(f"- {s.name}: {s.description}\n  {s.body.strip()}")
    return "\n".join(blocks)
