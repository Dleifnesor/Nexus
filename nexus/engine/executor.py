"""Unified action executor.

Responsibilities:
- validate proposed action against the scope gate,
- route to host (built-in) or Docker container (non-built-in) execution,
- apply timeout and retry-with-backoff,
- capture structured errors,
- parse output into normalized assets/findings and persist them.

The executor never runs free-form shell from the LLM: it only executes registry command
templates with the {target}/{args} placeholders substituted.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional

from ..logging_ import audit, get_logger
from ..scope.scope import Scope, ScopeError
from ..storage.db import Database
from ..tools.builtin import RunResult, run_host, tool_available
from ..tools.container import ContainerResult, DockerRunner
from ..tools.parsers import ParseResult, get_parser
from ..tools.registry import Registry, ToolEntry

log = get_logger(__name__)

INTRUSIVE_CATEGORIES = {"vuln", "exploit"}


@dataclass
class ActionOutcome:
    ok: bool
    tool: str
    target: str
    exit_code: int
    parsed: Optional[ParseResult] = None
    error: str = ""
    timed_out: bool = False
    new_assets: int = 0
    new_findings: int = 0


class Executor:
    def __init__(
        self,
        db: Database,
        registry: Registry,
        scope: Scope,
        docker: DockerRunner,
        run_id: str,
        max_retries: int = 2,
    ):
        self.db = db
        self.registry = registry
        self.scope = scope
        self.docker = docker
        self.run_id = run_id
        self.max_retries = max_retries

    def run_tool(self, tool_name: str, target: str, phase: str, extra_args: Optional[list[str]] = None) -> ActionOutcome:
        entry = self.registry.get(tool_name)
        if entry is None:
            return ActionOutcome(False, tool_name, target, 1, error=f"unknown tool: {tool_name}")

        # Scope gate + intrusive audit
        try:
            self.scope.enforce(target, action=f"{tool_name}({entry.category})")
        except ScopeError as e:
            self.db.add_error(self.run_id, "scope", str(e))
            return ActionOutcome(False, tool_name, target, 1, error=str(e))
        if entry.category in INTRUSIVE_CATEGORIES:
            audit("action.intrusive", tool=tool_name, target=target, category=entry.category, phase=phase)

        argv = _build_argv(entry, target, extra_args or [])
        action_id = self.db.start_action(self.run_id, phase, tool_name, target, " ".join(argv))

        outcome = self._run_with_retries(entry, argv, target)

        status = "ok" if outcome.ok else ("timeout" if outcome.timed_out else "error")
        excerpt = (outcome.error or "")[:2000]
        self.db.finish_action(action_id, status, outcome.exit_code, excerpt)

        if not outcome.ok:
            self.db.add_error(
                self.run_id,
                "timeout" if outcome.timed_out else "tool_error",
                outcome.error or f"exit {outcome.exit_code}",
                action_id=action_id,
            )
            return outcome

        # Parse and persist
        try:
            parsed = get_parser(entry.parser)(outcome._raw_stdout, target)  # type: ignore[attr-defined]
            outcome.parsed = parsed
            outcome.new_assets, outcome.new_findings = self._persist(parsed, entry, phase)
        except Exception as e:  # parser failure -> recoverable
            outcome.ok = False
            outcome.error = f"parser '{entry.parser}' failed: {e}"
            self.db.add_error(self.run_id, "parse_error", outcome.error, action_id=action_id)
        return outcome

    def _run_with_retries(self, entry: ToolEntry, argv: list[str], target: str) -> ActionOutcome:
        last: Optional[ActionOutcome] = None
        for attempt in range(self.max_retries + 1):
            if attempt:
                time.sleep(min(2 ** attempt, 8))  # exponential backoff, capped
                log.info("Retry %d for %s", attempt, entry.name)
            outcome = self._run_once(entry, argv, target)
            last = outcome
            if outcome.ok or outcome.timed_out:
                return outcome
        return last  # type: ignore[return-value]

    def _run_once(self, entry: ToolEntry, argv: list[str], target: str) -> ActionOutcome:
        if entry.builtin and tool_available(argv[0]):
            res: RunResult = run_host(argv, entry.timeout)
            oc = ActionOutcome(
                ok=(res.exit_code == 0 and not res.timed_out),
                tool=entry.name,
                target=target,
                exit_code=res.exit_code,
                error=res.stderr if res.exit_code != 0 else "",
                timed_out=res.timed_out,
            )
            oc._raw_stdout = res.stdout  # type: ignore[attr-defined]
            if res.exit_code == 127:
                oc.error = f"binary not found: {argv[0]}"
            return oc

        # non-builtin OR builtin binary missing -> container
        image = entry.image or "kalilinux/kali-rolling"
        cres: ContainerResult = self.docker.run(
            argv, image=image, install=entry.install, timeout=entry.timeout
        )
        oc = ActionOutcome(
            ok=(cres.exit_code == 0 and not cres.timed_out and not cres.error),
            tool=entry.name,
            target=target,
            exit_code=cres.exit_code,
            error=cres.error or (cres.stderr if cres.exit_code != 0 else ""),
            timed_out=cres.timed_out,
        )
        oc._raw_stdout = cres.stdout  # type: ignore[attr-defined]
        return oc

    def _persist(self, parsed: ParseResult, entry: ToolEntry, phase: str) -> tuple[int, int]:
        new_assets = 0
        for a in parsed.assets:
            aid = self.db.add_asset(
                self.run_id, a.type, a.value, source=entry.name, phase=phase, metadata=a.metadata
            )
            if aid:
                new_assets += 1
        new_findings = 0
        for f in parsed.findings:
            self.db.add_finding(
                self.run_id,
                title=f.title,
                description=f.description,
                severity=f.severity,
                cve_ids=f.cve_ids,
                evidence=f.evidence,
                source_tool=entry.name,
            )
            new_findings += 1
        return new_assets, new_findings


def _build_argv(entry: ToolEntry, target: str, extra_args: list[str]) -> list[str]:
    argv: list[str] = []
    for token in entry.cmd_template:
        if token == "{target}":
            argv.append(target)
        elif token == "{args}":
            argv.extend(extra_args)
        else:
            argv.append(token)
    if "{args}" not in entry.cmd_template and extra_args:
        argv.extend(extra_args)
    return argv
