"""Top-level engagement runner: wires all subsystems and executes an engagement.

Order: build/resume run -> state machine (recon through reach-expansion) -> enrichment
(NVD/OSV) -> remediation generation -> multi-format report.
"""
from __future__ import annotations

from typing import Callable, Optional

from ..config import Config
from ..enrich.nvd import NVDClient
from ..enrich.osv import OSVClient
from ..llm.provider import TokenCounter, build_provider
from ..logging_ import get_logger
from ..report.enrich_findings import FindingEnricher
from ..report.remediation import RemediationGenerator
from ..report.renderer import Renderer
from ..scope.scope import Scope
from ..storage.db import Database
from ..tools.container import DockerRunner
from ..tools.discovery import SearchFn, ToolDiscovery
from ..tools.registry import Registry
from .budget import BudgetTracker
from .checkpoint import load as load_checkpoint
from .executor import Executor
from .planner import Planner
from .recovery import Recovery
from .state_machine import StateMachine

log = get_logger(__name__)

ProgressFn = Callable[[str, str, dict], None]


class EngagementRunner:
    def __init__(self, cfg: Config, progress: Optional[ProgressFn] = None, search_fn: Optional[SearchFn] = None):
        self.cfg = cfg
        self.progress = progress or (lambda *a: None)
        self.search_fn = search_fn
        self.db = Database(cfg.db_path)

    def run(self) -> dict:
        cfg = self.cfg
        scope = Scope.parse(cfg.mode, cfg.scope_raw)

        if cfg.resume_run_id:
            run_id = cfg.resume_run_id
            if self.db.get_run(run_id) is None:
                raise ValueError(f"Cannot resume unknown run: {run_id}")
            start_state = load_checkpoint(self.db, run_id)
            log.info("Resuming run %s at phase index %d", run_id, start_state.phase_index)
        else:
            run_id = self.db.create_run(
                cfg.mode.value,
                {"raw": scope.raw},
                cfg.budgets.__dict__,
                cfg.to_dict(),
            )
            start_state = None

        counter = TokenCounter()
        provider = build_provider(cfg.llm, counter)
        registry = Registry()
        docker = DockerRunner(network=cfg.docker_network)
        executor = Executor(self.db, registry, scope, docker, run_id)
        planner = Planner(provider, registry)
        recovery = Recovery(provider, registry, self.db, run_id)
        budget = BudgetTracker(cfg.budgets, counter)
        discovery = ToolDiscovery(registry, provider, cfg.mode, self.search_fn)

        machine = StateMachine(
            cfg, self.db, run_id, scope, provider, registry, executor, planner,
            recovery, budget, discovery, progress=self.progress,
        )
        status = machine.run(start_state)

        # Reporting pipeline (always runs, even after budget/interrupt).
        self.progress("reporting", "Enriching findings with CVE data", self._stats(run_id))
        nvd = NVDClient(self.db, cfg.nvd_api_key)
        osv = OSVClient(self.db)
        try:
            enriched = FindingEnricher(self.db, run_id, nvd, osv).enrich_all()
            log.info("Enriched %d findings", enriched)
        except Exception as e:
            log.warning("Enrichment failed: %s", e)
            self.db.add_error(run_id, "enrichment", str(e))

        self.progress("reporting", "Generating remediations", self._stats(run_id))
        try:
            RemediationGenerator(provider, self.db, run_id).generate_all()
        except Exception as e:
            log.warning("Remediation generation failed: %s", e)
            self.db.add_error(run_id, "remediation", str(e))

        self.progress("reporting", "Rendering report", self._stats(run_id))
        outputs = Renderer(self.db, run_id, cfg.out_dir / "reports").render()

        result = {"run_id": run_id, "status": status, "reports": outputs, "stats": self._stats(run_id)}
        self.progress("done", f"Report ready: {outputs.get('html','')}", result["stats"])
        return result

    def _stats(self, run_id: str) -> dict:
        return {
            "assets": self.db.count_assets(run_id),
            "findings": self.db.count_findings(run_id),
            "actions": self.db.count_actions(run_id),
        }

    def close(self) -> None:
        self.db.close()
