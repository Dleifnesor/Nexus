"""End-to-end engine integration test with fakes (no network / docker / live LLM)."""
from __future__ import annotations

import json

from nexus.config import Budgets, Config, LLMConfig, Mode
from nexus.engine.budget import BudgetTracker
from nexus.engine.executor import Executor
from nexus.engine.planner import Planner
from nexus.engine.recovery import Recovery
from nexus.engine.state_machine import StateMachine
from nexus.llm.provider import BaseProvider, TokenCounter
from nexus.scope.scope import Scope
from nexus.storage.db import Database
from nexus.tools.container import DockerRunner
from nexus.tools.discovery import ToolDiscovery
from nexus.tools.registry import Registry, ToolEntry


class ScriptedProvider(BaseProvider):
    """Returns queued JSON responses for structured calls."""

    def __init__(self, responses):
        super().__init__(LLMConfig())
        self._responses = list(responses)

    def generate(self, prompt: str, system: str = "") -> str:
        if self._responses:
            return self._responses.pop(0)
        return '{"action_type": "finish_phase", "rationale": "done"}'


def _register_echo_tool(registry: Registry):
    # A built-in tool that maps to a cross-platform command producing CVE text.
    registry.add(
        ToolEntry(
            name="echocve",
            category="recon",
            when_to_use="test tool",
            builtin=True,
            cmd_template=["python", "-c", "print('found CVE-2021-4104 on {target}')"],
            parser="generic",
            phases=[],
            timeout=30,
        )
    )


def test_engine_full_run(tmp_path, monkeypatch):
    cfg = Config(
        mode=Mode.SANDBOX,
        scope_raw=["10.0.0.1"],
        llm=LLMConfig(),
        budgets=Budgets(max_time_seconds=60, max_tokens=10_000, max_actions=20, convergence_iters=1),
        out_dir=tmp_path / "out",
        data_dir=tmp_path / "out" / "data",
    )
    cfg.ensure_dirs()
    db = Database(cfg.db_path)
    run_id = db.create_run(cfg.mode.value, {"raw": cfg.scope_raw}, cfg.budgets.__dict__, {})

    scope = Scope.parse(cfg.mode, cfg.scope_raw)
    registry = Registry()
    _register_echo_tool(registry)

    # Planner: run echocve once per non-preflight phase, then finish.
    run_action = json.dumps({"action_type": "run_tool", "tool": "echocve", "target": "10.0.0.1"})
    # 5 active phases (passive/active/vuln/exploit/reach) each: one run then converge (iters=1)
    responses = []
    for _ in range(5):
        responses += [run_action]  # single action, then convergence kicks in
    provider = ScriptedProvider(responses)

    counter = TokenCounter()
    docker = DockerRunner()
    executor = Executor(db, registry, scope, docker, run_id)
    planner = Planner(provider, registry)
    recovery = Recovery(provider, registry, db, run_id)
    budget = BudgetTracker(cfg.budgets, counter)
    discovery = ToolDiscovery(registry, provider, cfg.mode, search_fn=None)

    machine = StateMachine(
        cfg, db, run_id, scope, provider, registry, executor, planner, recovery, budget, discovery
    )
    status = machine.run()

    assert status == "completed"
    # preflight seeded the scope asset
    assert db.count_assets(run_id) >= 1
    # the echo tool produced at least one CVE finding via the generic parser
    findings = db.list_findings(run_id)
    assert any("CVE-2021-4104" in json.loads(f["cve_ids_json"] or "[]") for f in findings)
    db.close()


def test_scope_mode_blocks_out_of_scope_tool(tmp_path):
    cfg = Config(mode=Mode.SCOPE, scope_raw=["example.com"], out_dir=tmp_path / "o", data_dir=tmp_path / "o" / "d")
    cfg.ensure_dirs()
    db = Database(cfg.db_path)
    run_id = db.create_run("scope", {}, {}, {})
    scope = Scope.parse(Mode.SCOPE, ["example.com"])
    registry = Registry()
    _register_echo_tool(registry)
    executor = Executor(db, registry, scope, DockerRunner(), run_id)

    outcome = executor.run_tool("echocve", "8.8.8.8", "active_recon")
    assert not outcome.ok
    assert "out of scope" in outcome.error
    # error recorded
    assert any(e["kind"] == "scope" for e in db.list_errors(run_id))
    db.close()


def test_parallel_execution(tmp_path):
    cfg = Config(
        mode=Mode.SANDBOX,
        scope_raw=["10.0.0.1"],
        llm=LLMConfig(),
        budgets=Budgets(max_time_seconds=60, max_tokens=10_000, max_actions=40, convergence_iters=1),
        out_dir=tmp_path / "out",
        data_dir=tmp_path / "out" / "data",
        max_concurrent=2,
    )
    cfg.ensure_dirs()
    db = Database(cfg.db_path)
    run_id = db.create_run(cfg.mode.value, {"raw": cfg.scope_raw}, cfg.budgets.__dict__, {})

    scope = Scope.parse(cfg.mode, cfg.scope_raw)
    registry = Registry()
    _register_echo_tool(registry)

    run_a = json.dumps({"action_type": "run_tool", "tool": "echocve", "target": "10.0.0.1"})
    run_b = json.dumps({"action_type": "run_tool", "tool": "echocve", "target": "10.0.0.2"})
    provider = ScriptedProvider([run_a, run_b])

    counter = TokenCounter()
    executor = Executor(db, registry, scope, DockerRunner(), run_id)
    machine = StateMachine(
        cfg, db, run_id, scope, provider, registry, executor,
        Planner(provider, registry), Recovery(provider, registry, db, run_id),
        BudgetTracker(cfg.budgets, counter), ToolDiscovery(registry, provider, cfg.mode, search_fn=None),
    )
    status = machine.run()

    assert status == "completed"
    assert db.count_actions(run_id) >= 2
    db.close()
