"""Phased engagement state machine.

Phases run in order. Within each phase the planner proposes actions in a loop until the
phase converges (no new assets/findings for N iterations), the planner finishes, or a budget
is hit. Reach-expansion re-enters recon/enumeration for newly discovered in-scope assets.
Global convergence + budgets bound the whole run.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional

from ..config import Config
from ..llm.provider import BaseProvider
from ..logging_ import audit, get_logger
from ..scope.scope import Scope
from ..storage.db import Database
from ..tools.discovery import ToolDiscovery
from ..tools.registry import Registry
from .budget import BudgetTracker
from .checkpoint import EngineState, save as save_checkpoint
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
        progress: Optional[ProgressFn] = None,
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
        self.state = EngineState()

    # -- public API ------------------------------------------------------
    def run(self, start_state: Optional[EngineState] = None) -> str:
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
            proposal = self.planner.next_action(phase.key, phase.goal, context)
            self.budget.record_action()

            if proposal.action_type == "finish_phase":
                self._emit(phase.key, f"Planner finished phase: {proposal.rationale}")
                return

            if proposal.action_type == "discover_tool":
                self._emit(phase.key, f"Discovering tool: {proposal.discovery_query}")
                self.discovery.discover(proposal.discovery_query or context[:120])
                continue

            # run_tool
            before_assets = self.db.count_assets(self.run_id)
            before_findings = self.db.count_findings(self.run_id)
            self._emit(
                phase.key,
                f"{proposal.tool} -> {proposal.target}",
                extra={"rationale": proposal.rationale},
            )
            outcome = self.executor.run_tool(
                proposal.tool, proposal.target, phase.key, proposal.args
            )
            if not outcome.ok:
                self._handle_failure(phase.key, proposal.tool, proposal.target, outcome.error)

            gained_assets = self.db.count_assets(self.run_id) - before_assets
            gained_findings = self.db.count_findings(self.run_id) - before_findings
            if gained_assets == 0 and gained_findings == 0:
                stale_iters += 1
            else:
                stale_iters = 0
                self._enqueue_new_scope_assets(phase.key)

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
            type_ = "domain" if any(c.isalpha() for c in host) and "/" not in host else "host"
            if self.db.add_asset(self.run_id, type_, host, source="scope", phase="preflight"):
                seeded += 1
        self._emit("preflight", f"Seeded {seeded} assets from scope.")

    # -- helpers ---------------------------------------------------------
    def _handle_failure(self, phase: str, tool: str, target: str, error: str) -> None:
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

    def _enqueue_new_scope_assets(self, phase: str) -> None:
        """In scope mode, drop any newly discovered out-of-scope assets from consideration."""
        for row in self.db.list_assets(self.run_id):
            if row["discovered_phase"] == "preflight":
                continue
            if row["type"] in ("domain", "host", "url") and not self.scope.contains(row["value"]):
                # Not removed from DB (kept for the report), but will be scope-blocked on use.
                continue

    def _build_context(self, phase: str) -> str:
        assets = self.db.list_assets(self.run_id)
        findings = self.db.list_findings(self.run_id)
        asset_lines = [f"{a['type']}: {a['value']}" for a in assets[:60]]
        finding_lines = [f"{f['severity']}: {f['title']}" for f in findings[:30]]
        return (
            f"Assets ({len(assets)} total, showing up to 60):\n" + "\n".join(asset_lines) +
            f"\n\nFindings ({len(findings)} total, showing up to 30):\n" + "\n".join(finding_lines) +
            f"\n\nScope mode: {self.cfg.mode.value}. In-scope entries: {', '.join(self.scope.raw) or 'unrestricted'}"
        )

    def _jump_to_reporting(self) -> None:
        for i, p in enumerate(PHASES):
            if p.key == "reporting":
                self.state.phase_index = i
                return

    def _emit(self, phase: str, msg: str, extra: Optional[dict] = None) -> None:
        stats = {
            "assets": self.db.count_assets(self.run_id),
            "findings": self.db.count_findings(self.run_id),
            "actions": self.db.count_actions(self.run_id),
            **(extra or {}),
        }
        log.info("[%s] %s", phase, msg)
        self.progress(phase, msg, stats)
