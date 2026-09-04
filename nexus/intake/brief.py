"""Parse a free-text operator prompt into a structured engagement brief.

The operator can describe an engagement in prose ("assess acme.local and 10.0.0.0/24, focus on
auth bypass, leave 10.0.0.5 alone") instead of passing structured --scope-entry flags. The LLM
extracts scope/exclusions/objective/focus; the caller is responsible for re-validating the
scope through the scope parser and confirming it with the operator before anything runs.
"""
from __future__ import annotations

from ..llm.prompts import SYSTEM_INTAKE, intake_prompt
from ..llm.provider import BaseProvider, LLMError
from ..llm.schema import EngagementBrief
from ..logging_ import get_logger

log = get_logger(__name__)


def parse_brief(provider: BaseProvider, text: str) -> EngagementBrief:
    """Extract an EngagementBrief from prose. Returns an empty brief on LLM failure."""
    if not text.strip():
        return EngagementBrief()
    try:
        brief = provider.generate_structured(intake_prompt(text), EngagementBrief, system=SYSTEM_INTAKE)
    except (LLMError, ValueError) as e:
        log.warning("Engagement intake failed (%s); no scope extracted.", e)
        return EngagementBrief()
    # normalize whitespace; de-dupe while preserving order
    brief.scope = _clean(brief.scope)
    brief.exclusions = _clean(brief.exclusions)
    brief.focus = _clean([f.lower() for f in brief.focus])
    brief.objective = (brief.objective or "").strip()
    return brief


def _clean(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        v = (item or "").strip()
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out
