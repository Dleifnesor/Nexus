"""Top-level engagement runner: wires all subsystems and executes an engagement.

Order: build/resume run -> state machine (recon through reach-expansion) -> enrichment
(NVD/OSV) -> remediation generation -> multi-format report.
"""
from __future__ import annotations

from collections.abc import Callable

from ..config import Config
from ..enrich.epss import EpssClient
from ..enrich.exploitdb import ExploitDBClient
from ..enrich.exposure import ExposureClient
from ..enrich.github_poc import GitHubPocClient
from ..enrich.kev import KevClient
from ..enrich.nvd import NVDClient
from ..enrich.osv import OSVClient
from ..enrich.vulners import VulnersClient
from ..llm.provider import TokenCounter, build_provider
from ..logging_ import get_logger
from ..osint.breach import BreachClient
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
    def __init__(self, cfg: Config, progress: ProgressFn | None = None, search_fn: SearchFn | None = None):
        self.cfg = cfg
        self.progress = progress or (lambda *a: None)
        self.search_fn = search_fn
        self.db = Database(cfg.db_path)
        self.run_id: str | None = None
        self._scope: Scope | None = None
        self._start_state = None

    def prepare(self) -> str:
        """Resolve (or create) the run id up front so callers can bind dashboards to the
        real run before execution starts. Idempotent."""
        if self.run_id is not None:
            return self.run_id
        cfg = self.cfg
        self._scope = Scope.parse(cfg.mode, cfg.scope_raw, cfg.scope_exclusions)
        if cfg.resume_run_id:
            run_id = cfg.resume_run_id
            if self.db.get_run(run_id) is None:
                raise ValueError(f"Cannot resume unknown run: {run_id}")
            self._start_state = load_checkpoint(self.db, run_id)
            log.info("Resuming run %s at phase index %d", run_id, self._start_state.phase_index)
        else:
            run_id = self.db.create_run(
                cfg.mode.value,
                {"raw": self._scope.raw},
                cfg.budgets.__dict__,
                cfg.to_dict(),
            )
            self._start_state = None
        self.run_id = run_id
        return run_id

    def run(self) -> dict:
        cfg = self.cfg
        run_id = self.prepare()
        scope = self._scope
        start_state = self._start_state

        counter = TokenCounter()
        provider = build_provider(cfg.llm, counter)
        registry = Registry()
        docker = DockerRunner(network=cfg.docker_network)
        executor = Executor(
            self.db, registry, scope, docker, run_id,
            rate_limit_ms=cfg.rate_limit_ms,
            containerize=cfg.docker_enabled,
            allow_tool_install=cfg.allow_tool_install,
        )
        planner = Planner(provider, registry)
        recovery = Recovery(provider, registry, self.db, run_id)
        budget = BudgetTracker(cfg.budgets, counter)
        if start_state and start_state.budget:
            budget.restore(start_state.budget)
        discovery = ToolDiscovery(registry, provider, cfg.mode, self.search_fn)

        machine = StateMachine(
            cfg, self.db, run_id, scope, provider, registry, executor, planner,
            recovery, budget, discovery, progress=self.progress,
        )
        status = machine.run(start_state)

        # OSINT: breach checks for in-scope domains/emails (mode-gated).
        try:
            self._osint_breach(run_id, scope)
        except Exception as e:
            log.warning("Breach checks failed: %s", e)
            self.db.add_error(run_id, "osint", str(e))

        # OSINT: internet exposure annotations for discovered hosts.
        try:
            self._osint_exposure(run_id, scope)
        except Exception as e:
            log.warning("Exposure checks failed: %s", e)
            self.db.add_error(run_id, "osint", str(e))

        # Reporting pipeline (always runs, even after budget/interrupt).
        self.progress("reporting", "Enriching findings with CVE data", self._stats(run_id))
        nvd = NVDClient(self.db, cfg.nvd_api_key)
        osv = OSVClient(self.db)
        kev = KevClient(self.db)
        epss = EpssClient(self.db)
        exploitdb = ExploitDBClient(self.db)
        github = GitHubPocClient(self.db)
        vulners = VulnersClient(self.db)
        try:
            enriched = FindingEnricher(self.db, run_id, nvd, osv, kev, epss, exploitdb, github, vulners).enrich_all()
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

        try:
            self._notify(run_id, status)
        except Exception as e:
            log.warning("Notification failed: %s", e)

        self.progress("done", f"Report ready: {outputs.get('html','')}", result["stats"])
        return result

    def _notify(self, run_id: str, status: str) -> None:
        import os

        from ..notify import Notifier

        slack = os.environ.get("NEXUS_SLACK_WEBHOOK")
        generic = os.environ.get("NEXUS_WEBHOOK_URL")
        if not (slack or generic):
            return
        counts = {}
        for f in self.db.list_findings(run_id):
            sev = (f["severity"] or "info").lower()
            counts[sev] = counts.get(sev, 0) + 1
        critical = [dict(f) for f in self.db.list_findings(run_id) if (f["severity"] or "").lower() in ("critical", "high")][:5]
        summary = {
            "run_id": run_id,
            "status": status,
            "findings": sum(counts.values()),
            "counts": counts,
            "critical_findings": critical,
        }
        Notifier(slack, generic).notify(summary)

    def _osint_breach(self, run_id: str, scope: Scope) -> None:
        """Query breach data for in-scope domains/emails and record findings."""
        cfg = self.cfg
        breach = BreachClient(scope, cfg.hibp_api_key)
        domains = [r["value"] for r in self.db.list_assets(run_id, "domain")]
        emails = [r["value"] for r in self.db.list_assets(run_id, "email")]

        if not breach.enabled():
            if cfg.hibp_api_key is None and (domains or emails):
                self.db.add_error(
                    run_id,
                    "coverage_gap",
                    "Breach check skipped: no HIBP API key configured",
                    is_coverage_gap=True,
                )
            return

        self.progress("reporting", "Checking breach databases", self._stats(run_id))
        for domain in domains:
            for b in breach.check_domain_breaches(domain):
                title = b.get("Title") or b.get("Name") or domain
                self.db.add_finding(
                    run_id,
                    f"Domain in known breach: {title}",
                    description=f"{domain} appears in breach '{title}' ({b.get('BreachDate') or 'unknown date'})",
                    severity="medium",
                    evidence=str(b.get("Domain") or domain),
                    source_tool="hibp",
                )
        for email in emails:
            for b in breach.check_account(email):
                title = b.get("Name") or b.get("Title") or "unknown breach"
                self.db.add_finding(
                    run_id,
                    f"Email in known breach: {email}",
                    description=f"Account {email} appears in breach '{title}'",
                    severity="high",
                    evidence=str(b.get("BreachDate") or ""),
                    source_tool="hibp",
                )

    def _osint_exposure(self, run_id: str, scope: Scope) -> None:
        """Annotate in-scope hosts with internet exposure (GreyNoise + Shodan InternetDB)."""
        exposure = ExposureClient(self.db)
        hosts = [r["value"] for r in self.db.list_assets(run_id, "host")]
        if not hosts:
            return
        self.progress("reporting", "Checking internet exposure", self._stats(run_id))
        for host in hosts:
            if not scope.contains(host):
                continue
            data = exposure.check_ip(host)
            shodan = data.get("shodan") or {}
            grey = data.get("greynoise") or {}
            tags = shodan.get("tags") or []
            if tags or grey.get("classification") == "malicious":
                self.db.add_finding(
                    run_id,
                    f"Internet-exposed host: {host}",
                    description=(
                        f"{host} appears in public scan data. Shodan tags: {', '.join(tags) or 'none'}. "
                        f"GreyNoise classification: {grey.get('classification') or 'unknown'}."
                    ),
                    severity="info",
                    evidence=str(shodan.get("ports") or grey.get("last_seen") or host),
                    source_tool="exposure",
                )

    def _stats(self, run_id: str) -> dict:
        return {
            "assets": self.db.count_assets(run_id),
            "findings": self.db.count_findings(run_id),
            "actions": self.db.count_actions(run_id),
        }

    def close(self) -> None:
        self.db.close()
