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

import threading
import time
from dataclasses import dataclass

from ..logging_ import audit, get_logger
from ..scope.scope import Scope, ScopeError, _extract_host
from ..storage.db import Database
from ..tools.builtin import RunResult, run_host, run_host_shell, tool_available
from ..tools.container import ContainerResult, DockerRunner
from ..tools.parsers import ParseResult, get_parser
from ..tools.registry import Registry, ToolEntry

log = get_logger(__name__)

INTRUSIVE_CATEGORIES = {"vuln", "exploit"}
INSTALL_TIMEOUT = 1800
MAX_PARSE_BYTES = 8 * 1024 * 1024  # cap tool stdout fed to parsers to bound memory


@dataclass
class ActionOutcome:
    ok: bool
    tool: str
    target: str
    exit_code: int
    parsed: ParseResult | None = None
    error: str = ""
    timed_out: bool = False
    new_assets: int = 0
    new_findings: int = 0
    scope_denied: bool = False  # target was refused by the scope gate (never retryable)


class Executor:
    def __init__(
        self,
        db: Database,
        registry: Registry,
        scope: Scope,
        docker: DockerRunner,
        run_id: str,
        max_retries: int = 2,
        rate_limit_ms: int = 0,
        containerize: bool = True,
        allow_tool_install: bool = False,
    ):
        self.db = db
        self.registry = registry
        self.scope = scope
        self.docker = docker
        self.run_id = run_id
        self.max_retries = max_retries
        self.rate_limit_ms = rate_limit_ms
        self.containerize = containerize
        self.allow_tool_install = allow_tool_install
        self._last_action_at = 0.0
        self._throttle_lock = threading.Lock()
        self._installing: set[str] = set()

    def _throttle(self) -> None:
        if self.rate_limit_ms <= 0:
            return
        with self._throttle_lock:
            now = time.monotonic()
            elapsed_ms = (now - self._last_action_at) * 1000
            wait_ms = self.rate_limit_ms - elapsed_ms
            if wait_ms > 0:
                time.sleep(wait_ms / 1000)
            self._last_action_at = time.monotonic()

    def run_tool(self, tool_name: str, target: str, phase: str, extra_args: list[str] | None = None) -> ActionOutcome:
        entry = self.registry.get(tool_name)
        if entry is None:
            return ActionOutcome(False, tool_name, target, 1, error=f"unknown tool: {tool_name}")

        # Scope gate + intrusive audit
        try:
            self.scope.enforce(target, action=f"{tool_name}({entry.category})")
        except ScopeError as e:
            self.db.add_error(self.run_id, "scope", str(e))
            return ActionOutcome(False, tool_name, target, 1, error=str(e), scope_denied=True)
        if entry.category in INTRUSIVE_CATEGORIES:
            audit("action.intrusive", tool=tool_name, target=target, category=entry.category, phase=phase)

        self._throttle()

        argv = _build_argv(entry, target, extra_args or [], self._credential_args(entry, target))
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
            raw_stdout = outcome._raw_stdout or ""  # type: ignore[attr-defined]
            if len(raw_stdout) > MAX_PARSE_BYTES:
                log.warning(
                    "Truncating %s output from %d to %d bytes before parsing",
                    entry.name, len(raw_stdout), MAX_PARSE_BYTES,
                )
                raw_stdout = raw_stdout[:MAX_PARSE_BYTES]
            parsed = get_parser(entry.parser)(raw_stdout, target)
            outcome.parsed = parsed
            outcome.new_assets, outcome.new_findings = self._persist(parsed, entry, phase)
        except Exception as e:  # parser failure -> recoverable
            outcome.ok = False
            outcome.error = f"parser '{entry.parser}' failed: {e}"
            self.db.add_error(self.run_id, "parse_error", outcome.error, action_id=action_id)
            self.db.finish_action(action_id, "parse_error", outcome.exit_code, outcome.error[:2000])
        return outcome

    def _run_with_retries(self, entry: ToolEntry, argv: list[str], target: str) -> ActionOutcome:
        last: ActionOutcome | None = None
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
        binary = argv[0]
        if entry.builtin and tool_available(binary):
            return self._run_host(entry, argv, target)

        # Discovered (LLM-synthesized) tools are never trusted to install/run on the host by
        # default: their install command and argv originate from web search + the model, so we
        # always confine them to an ephemeral container. If Docker is unavailable we skip the
        # tool (recorded as a failure) rather than shell out on the host. Opt back into host
        # execution explicitly with --allow-tool-install.
        discovered = not entry.builtin and not entry.host_only
        if discovered and not self.allow_tool_install:
            if not self.docker.available():
                return ActionOutcome(
                    False, entry.name, target, 1,
                    error="discovered tool requires Docker (unavailable); skipped for safety",
                )
            return self._run_container(entry, argv, target)

        # Host-native execution for trusted/built-in tools (and, when opted in, discovered
        # tools under --no-docker): never containerize, install on demand.
        if entry.host_only or not self.containerize:
            self._install_host(entry)
            return self._run_host(entry, argv, target)

        # non-builtin OR builtin binary missing -> container
        return self._run_container(entry, argv, target)

    def _run_container(self, entry: ToolEntry, argv: list[str], target: str) -> ActionOutcome:
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

    def _run_host(self, entry: ToolEntry, argv: list[str], target: str) -> ActionOutcome:
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

    def _install_host(self, entry: ToolEntry) -> None:
        """Install a missing host tool on demand (audit-logged, idempotent)."""
        if not entry.install:
            return
        binary = entry.cmd_template[0] if entry.cmd_template else entry.name
        if tool_available(binary):
            return
        if entry.name in self._installing:
            return
        self._installing.add(entry.name)
        try:
            audit("tool.install", tool=entry.name, command=entry.install)
            log.info("Installing %s on host: %s", entry.name, entry.install)
            res = run_host_shell(entry.install, INSTALL_TIMEOUT)
            if res.exit_code != 0:
                log.warning("Install of %s failed: %s", entry.name, res.stderr or res.stdout)
        finally:
            self._installing.discard(entry.name)

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
        for c in parsed.credentials:
            self.db.add_credential(
                self.run_id,
                host=c.host,
                username=c.username,
                secret=c.password,
                service=c.service,
                source_tool=entry.name,
            )
        return new_assets, new_findings

    def _credential_args(self, entry: ToolEntry, target: str) -> list[str]:
        if not entry.uses_creds:
            return []
        host = _extract_host(target)
        if not host:
            return []
        creds = self.db.list_credentials(self.run_id, host)
        if not creds:
            return []
        c = creds[0]
        return ["-u", c["username"], "-p", c["secret"] or ""]


def _build_argv(entry: ToolEntry, target: str, extra_args: list[str], cred_args: list[str] | None = None) -> list[str]:
    argv: list[str] = []
    for token in entry.cmd_template:
        if token == "{target}":
            argv.append(target)
        elif token == "{args}":
            argv.extend(extra_args)
        elif token == "{cred}":
            argv.extend(cred_args or [])
        else:
            argv.append(token)
    if "{args}" not in entry.cmd_template and extra_args:
        argv.extend(extra_args)
    return argv
