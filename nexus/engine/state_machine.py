"""Phased engagement state machine.

Phases run in order. Within each phase the planner proposes actions in a loop until the
phase converges (no new assets/findings for N iterations), the planner finishes, or a budget
is hit. Reach-expansion re-enters recon/enumeration for newly discovered in-scope assets.
Global convergence + budgets bound the whole run.
"""
from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from ..config import Config
from ..llm.provider import BaseProvider
from ..logging_ import audit, get_logger
from ..scope.scope import Scope, _parse_entry
from ..storage.db import Database
from ..tools.discovery import ToolDiscovery
from ..tools.registry import Registry
from .budget import BudgetTracker
from .checkpoint import EngineState
from .checkpoint import save as save_checkpoint
from .executor import Executor
from .planner import Planner
from .recovery import Recovery

log = get_logger(__name__)


@dataclass
class Phase:
    key: str
    goal: str


PHASES: list[Phase] = [
    Phase("preflight", "Verify prerequisites and seed initial assets from scope."),
    Phase("passive_recon", "Discover subdomains, hosts, emails, and technologies passively via OSINT."),
    Phase("active_recon", "Discover live hosts, open ports, and service versions."),
    Phase("vuln_discovery", "Identify vulnerabilities and misconfigurations on discovered services."),
    Phase("exploitation", "Validate exploitable findings and confirm access (non-destructive)."),
    Phase("reach_expansion", "Use validated access and new assets to expand coverage until convergence."),
    Phase("reporting", "Enrich findings and generate the report."),
]

# Progress callback: (phase, message, stats_dict)
ProgressFn = Callable[[str, str, dict], None]


class StateMachine:
    def __init__(
        self,
        cfg: Config,
        db: Database,
        run_id: str,
        scope: Scope,
        provider: BaseProvider,
        registry: Registry,
        executor: Executor,
        planner: Planner,
        recovery: Recovery,
        budget: BudgetTracker,
        discovery: ToolDiscovery,
        progress: ProgressFn | None = None,
        skills=None,  # SkillStore | None
        focus: list[str] | None = None,
    ):
        self.cfg = cfg
        self.db = db
        self.run_id = run_id
        self.scope = scope
        self.provider = provider
        self.registry = registry
        self.executor = executor
        self.planner = planner
        self.recovery = recovery
        self.budget = budget
        self.discovery = discovery
        self.progress = progress or (lambda *a: None)
        self.skills = skills
        self.focus = focus or []
        self.state = EngineState()

    # -- public API ------------------------------------------------------
    def run(self, start_state: EngineState | None = None) -> str:
        if start_state:
            self.state = start_state
        audit("run.start", run_id=self.run_id, mode=self.cfg.mode.value)
        try:
            while self.state.phase_index < len(PHASES):
                phase = PHASES[self.state.phase_index]
                if phase.key in self.state.completed_phases:
                    self.state.phase_index += 1
                    continue
                self.db.set_run_phase(self.run_id, phase.key)
                self._emit(phase.key, f"Entering phase: {phase.key}")

                bstate = self.budget.check()
                if bstate.exhausted():
                    log.info("Budget exhausted before %s: %s", phase.key, bstate.reason)
                    self.db.add_error(self.run_id, "budget", bstate.reason)
                    self._jump_to_reporting()
                    continue

                self._run_phase(phase)
                self.state.completed_phases.append(phase.key)
                self.state.phase_index += 1
                save_checkpoint(self.db, self.run_id, phase.key, self.state)
            self.db.finish_run(self.run_id, "completed")
            audit("run.complete", run_id=self.run_id)
            return "completed"
        except KeyboardInterrupt:
            self.db.finish_run(self.run_id, "interrupted")
            self.db.add_error(self.run_id, "interrupt", "run interrupted by operator")
            return "interrupted"
        except Exception as e:  # never crash the whole run
            log.exception("Fatal engine error")
            self.db.add_error(self.run_id, "fatal", str(e))
            self.db.finish_run(self.run_id, "error")
            return "error"

    # -- phases ----------------------------------------------------------
    def _run_phase(self, phase: Phase) -> None:
        if phase.key == "preflight":
            self._preflight()
            return
        if phase.key == "reporting":
            # reporting is driven by the caller (engine.run) after the machine; no-op here
            return

        stale_iters = 0
        while True:
            bstate = self.budget.check()
            if bstate.exhausted():
                self.db.add_error(self.run_id, "budget", f"{phase.key}: {bstate.reason}")
                self._emit(phase.key, f"Budget hit: {bstate.reason}", extra={"budget": self.budget.snapshot()})
                return

            context = self._build_context(phase.key)

            # Propose up to max_concurrent run_tool actions in this iteration. The planner
            # sees identical context for each call, so dedupe by (tool, target, args) to
            # avoid running the same action several times in one parallel batch.
            proposals = []
            seen: set[tuple] = set()
            for _ in range(max(1, self.cfg.max_concurrent)):
                proposal = self.planner.next_action(phase.key, phase.goal, context)
                if proposal.action_type == "finish_phase":
                    self._emit(phase.key, f"Planner finished phase: {proposal.rationale}")
                    return
                if proposal.action_type == "discover_tool":
                    self._emit(phase.key, f"Discovering tool: {proposal.discovery_query}")
                    self.discovery.discover(proposal.discovery_query or context[:120])
                    break
                key = (proposal.tool, proposal.target, tuple(proposal.args))
                if key in seen:
                    continue
                seen.add(key)
                proposals.append(proposal)

            if not proposals:
                continue

            for proposal in proposals:
                self.budget.record_action()
                self._emit(
                    phase.key,
                    f"{proposal.tool} -> {proposal.target}",
                    extra={"rationale": proposal.rationale},
                )

            before_assets = self.db.count_assets(self.run_id)
            before_findings = self.db.count_findings(self.run_id)

            if len(proposals) == 1:
                p = proposals[0]
                outcomes = [self.executor.run_tool(p.tool, p.target, phase.key, p.args)]
            else:
                with ThreadPoolExecutor(max_workers=self.cfg.max_concurrent) as pool:
                    futures = [
                        pool.submit(self.executor.run_tool, p.tool, p.target, phase.key, p.args)
                        for p in proposals
                    ]
                    outcomes = [f.result() for f in futures]

            for proposal, outcome in zip(proposals, outcomes, strict=False):
                if not outcome.ok:
                    self._handle_failure(
                        phase.key, proposal.tool, proposal.target, outcome.error,
                        scope_denied=outcome.scope_denied,
                    )
                elif outcome.parsed:
                    for a in outcome.parsed.assets:
                        if a.type in ("service", "url", "host", "domain"):
                            self.db.kb_set(self.run_id, f"{a.type}:{a.value}", phase.key)

            gained_assets = self.db.count_assets(self.run_id) - before_assets
            gained_findings = self.db.count_findings(self.run_id) - before_findings
            if gained_assets == 0 and gained_findings == 0:
                stale_iters += 1
            else:
                stale_iters = 0

            self.state.budget = self.budget.snapshot()
            save_checkpoint(self.db, self.run_id, phase.key, self.state)

            if stale_iters >= self.cfg.budgets.convergence_iters:
                self._emit(phase.key, f"Converged after {stale_iters} idle iterations.")
                return

    def _preflight(self) -> None:
        # Seed assets directly from the operator-provided scope.
        seeded = 0
        for entry in self.scope.raw:
            host = entry.strip()
            if not host:
                continue
            # Classify via the same parser the scope gate uses so IPv6 (which contains hex
            # letters) and CIDRs are treated as hosts, not domains.
            parsed = _parse_entry(host)
            type_ = "domain" if isinstance(parsed, str) else "host"
            if self.db.add_asset(self.run_id, type_, host, source="scope", phase="preflight"):
                seeded += 1
        self._emit("preflight", f"Seeded {seeded} assets from scope.")

    # -- helpers ---------------------------------------------------------
    def _handle_failure(
        self, phase: str, tool: str, target: str, error: str, scope_denied: bool = False
    ) -> None:
        # A scope refusal can never succeed on retry or via another tool; record the gap and
        # skip the (wasted) LLM recovery round-trip entirely.
        if scope_denied:
            self.recovery.record_gap(tool, target, error, "out_of_scope")
            return
        decision = self.recovery.decide(tool, target, "", error)
        if decision.strategy == "retry":
            outcome = self.executor.run_tool(tool, target, phase)
            if not outcome.ok:
                self.recovery.record_gap(tool, target, error, "retry_failed")
        elif decision.strategy == "alternative_tool" and decision.alternative_tool:
            self._emit(phase, f"Recovery: switching to {decision.alternative_tool}")
            outcome = self.executor.run_tool(decision.alternative_tool, target, phase, decision.args)
            if not outcome.ok:
                self.recovery.record_gap(tool, target, error, f"alt:{decision.alternative_tool}")
        else:
            self.recovery.record_gap(tool, target, error, "skip")

    def _build_context(self, phase: str) -> str:
        assets = self.db.list_assets(self.run_id)
        findings = self.db.list_findings(self.run_id)
        errors = self.db.list_errors(self.run_id)

        by_type: dict[str, list[str]] = {}
        for a in assets:
            by_type.setdefault(a["type"], []).append(a["value"])

        lines = [f"Phase: {phase}"]
        for t, label in (
            ("host", "Hosts"),
            ("domain", "Domains"),
            ("url", "URLs"),
            ("service", "Services (open ports/versions)"),
            ("email", "Emails"),
        ):
            values = by_type.get(t, [])
            shown = ", ".join(values[:40])
            lines.append(f"{label} ({len(values)}): {shown or 'none'}")

        lines.append(f"Findings ({len(findings)}):")
        for f in findings[:30]:
            cves = json.loads(f["cve_ids_json"] or "[]")
            cve_suffix = f" [{' '.join(cves[:4])}]" if cves else ""
            lines.append(f"  - {f['severity']}: {f['title']}{cve_suffix}")

        creds = self.db.list_credentials(self.run_id)
        if creds:
            lines.append(f"Known credentials ({len(creds)}):")
            for c in creds[:10]:
                lines.append(f"  - {c['host']} {c['service'] or ''} {c['username']}:{c['secret'] or ''}")

        recent_errors = [e for e in errors if not e["is_coverage_gap"]][-10:]
        if recent_errors:
            lines.append("Recent errors:")
            for e in recent_errors:
                lines.append(f"  - [{e['kind']}] {e['message'][:200]}")

        lines.append(
            f"Scope mode: {self.cfg.mode.value}. "
            f"In-scope: {', '.join(self.scope.raw) or 'unrestricted'}"
        )

        skills_block = self._skills_block("\n".join(lines))
        if skills_block:
            lines.append("")
            lines.append(skills_block)
        return "\n".join(lines)

    def _skills_block(self, context_so_far: str) -> str:
        if not self.skills:
            return ""
        try:
            from ..skills.select import relevant, render

            chosen = relevant(self.skills.all(), context_so_far, focus=self.focus)
            return render(chosen)
        except Exception as e:  # skills are best-effort; never break planning
            log.debug("Skill selection failed: %s", e)
            return ""

    def _jump_to_reporting(self) -> None:
        for i, p in enumerate(PHASES):
            if p.key == "reporting":
                self.state.phase_index = i
                return

    def _emit(self, phase: str, msg: str, extra: dict | None = None) -> None:
        stats = {
            "assets": self.db.count_assets(self.run_id),
            "findings": self.db.count_findings(self.run_id),
            "actions": self.db.count_actions(self.run_id),
            **(extra or {}),
        }
        log.info("[%s] %s", phase, msg)
        self.progress(phase, msg, stats)
