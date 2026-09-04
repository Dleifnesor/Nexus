"""Skill store: a directory of markdown playbooks Nexus loads and grows over time.

Each skill is one `.md` file with simple frontmatter:

    ---
    name: wordpress-enum
    description: When WordPress is detected, enumerate and check known CVEs
    triggers: [wordpress, wp-content, wpscan]
    source: builtin
    ---
    <body: the procedure>

Built-in seed skills ship in this package (``builtin/``); learned skills are written to the
user library (default ``~/.nexus/skills``). Frontmatter is parsed with a tiny purpose-built
parser so the project keeps its lean dependency set (no YAML runtime).

Skill text is untrusted reference material: it is surfaced to the planner as data, and the
planner remains constrained to the tool registry, the scope gate, and the install sanitizer.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..logging_ import audit, get_logger

log = get_logger(__name__)

_BUILTIN_DIR = Path(__file__).parent / "builtin"
MAX_BODY_CHARS = 2000
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,48}$")


@dataclass
class Skill:
    name: str
    description: str = ""
    triggers: list[str] = field(default_factory=list)
    body: str = ""
    source: str = "learned"  # builtin | learned
    path: Path | None = None

    def to_markdown(self) -> str:
        triggers = ", ".join(self.triggers)
        return (
            "---\n"
            f"name: {self.name}\n"
            f"description: {self.description}\n"
            f"triggers: [{triggers}]\n"
            f"source: {self.source}\n"
            "---\n\n"
            f"{self.body.strip()}\n"
        )


class SkillStore:
    def __init__(self, user_dir: Path):
        self.user_dir = Path(user_dir)
        self._skills: dict[str, Skill] = {}
        self.reload()

    def reload(self) -> None:
        self._skills.clear()
        for skill in _load_dir(_BUILTIN_DIR, "builtin"):
            self._skills[skill.name] = skill
        # user skills override built-ins of the same name
        for skill in _load_dir(self.user_dir, "learned"):
            self._skills[skill.name] = skill

    def all(self) -> list[Skill]:
        return list(self._skills.values())

    def get(self, name: str) -> Skill | None:
        return self._skills.get(name)

    def upsert(self, skill: Skill) -> Skill | None:
        """Create or update a learned skill in the user library. Returns the stored skill,
        or None if it was rejected (bad name)."""
        name = _normalize_name(skill.name)
        if not name:
            log.warning("Rejecting skill with invalid name: %r", skill.name)
            return None
        skill.name = name
        skill.body = (skill.body or "").strip()[:MAX_BODY_CHARS]
        skill.source = "learned"
        existing = self._skills.get(name)
        if existing and existing.source == "builtin":
            # don't clobber a shipped skill; store the learned variant alongside it in memory
            log.info("Skill %s shadows a built-in; writing learned override", name)
        self.user_dir.mkdir(parents=True, exist_ok=True)
        skill.path = self.user_dir / f"{name}.md"
        skill.path.write_text(skill.to_markdown(), encoding="utf-8")
        self._skills[name] = skill
        audit("skill.write", name=name, triggers=skill.triggers, source="learned")
        return skill


def _normalize_name(raw: str) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", (raw or "").strip().lower()).strip("-")
    return slug if _NAME_RE.match(slug) else ""


def _load_dir(directory: Path, default_source: str) -> list[Skill]:
    out: list[Skill] = []
    if not directory or not directory.is_dir():
        return out
    for path in sorted(directory.glob("*.md")):
        try:
            out.append(_parse_skill(path.read_text(encoding="utf-8"), path, default_source))
        except Exception as e:
            log.warning("Skipping malformed skill %s: %s", path, e)
    return out


def _parse_skill(text: str, path: Path, default_source: str) -> Skill:
    meta, body = _split_frontmatter(text)
    name = _normalize_name(meta.get("name", path.stem))
    return Skill(
        name=name or path.stem,
        description=meta.get("description", ""),
        triggers=_parse_list(meta.get("triggers", "")),
        body=body.strip()[:MAX_BODY_CHARS],
        source=meta.get("source", default_source),
        path=path,
    )


def _split_frontmatter(text: str) -> tuple[dict[str, str], str]:
    text = text.lstrip("﻿")
    if not text.startswith("---"):
        return {}, text
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}, text
    meta: dict[str, str] = {}
    for line in parts[1].splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            meta[key.strip().lower()] = value.strip()
    return meta, parts[2]


def _parse_list(value: str) -> list[str]:
    value = value.strip().strip("[]")
    return [v.strip().lower() for v in value.split(",") if v.strip()]
