import sys

import nexus.engine.executor as executor_module
from nexus.config import Config, Mode
from nexus.engine.executor import Executor, _build_argv
from nexus.scope.scope import Scope
from nexus.storage.db import Database
from nexus.tools.builtin import RunResult
from nexus.tools.container import DockerRunner
from nexus.tools.registry import Registry, ToolEntry


def _entry(template):
    return ToolEntry(name="t", category="recon", when_to_use="", cmd_template=template)


def test_build_argv_target():
    assert _build_argv(_entry(["nmap", "-sV", "{target}"]), "10.0.0.1", []) == ["nmap", "-sV", "10.0.0.1"]


def test_build_argv_args_placeholder():
    assert _build_argv(_entry(["tool", "{target}", "{args}"]), "h", ["-a", "-b"]) == ["tool", "h", "-a", "-b"]


def test_build_argv_appends_extra_when_no_placeholder():
    assert _build_argv(_entry(["tool", "{target}"]), "h", ["-x"]) == ["tool", "h", "-x"]


def test_build_argv_cred_placeholder():
    e = ToolEntry(name="t", category="vuln", when_to_use="", cmd_template=["netexec", "smb", "{target}", "{cred}"])
    assert _build_argv(e, "h", [], ["-u", "admin", "-p", "x"]) == ["netexec", "smb", "h", "-u", "admin", "-p", "x"]


def test_unknown_tool(tmp_path):
    cfg = Config(mode=Mode.SANDBOX, out_dir=tmp_path / "o", data_dir=tmp_path / "o" / "d")
    cfg.ensure_dirs()
    db = Database(cfg.db_path)
    rid = db.create_run("sandbox", {}, {}, {})
    ex = Executor(db, Registry(), Scope.parse(Mode.SANDBOX, []), DockerRunner(), rid)
    out = ex.run_tool("nonexistent", "10.0.0.1", "active_recon")
    assert not out.ok
    assert "unknown tool" in out.error


def test_parser_failure_records_error(tmp_path, monkeypatch):
    cfg = Config(mode=Mode.SANDBOX, out_dir=tmp_path / "o", data_dir=tmp_path / "o" / "d")
    cfg.ensure_dirs()
    db = Database(cfg.db_path)
    rid = db.create_run("sandbox", {}, {}, {})
    registry = Registry()
    registry.add(
        ToolEntry(
            name="boomtool",
            category="recon",
            when_to_use="",
            builtin=True,
            cmd_template=[sys.executable, "-c", "print('ok')"],
            parser="generic",
            phases=[],
            timeout=30,
        )
    )

    def bad_parser(raw, target):
        raise RuntimeError("parse boom")

    monkeypatch.setattr(executor_module, "get_parser", lambda key: bad_parser)
    ex = Executor(db, registry, Scope.parse(Mode.SANDBOX, []), DockerRunner(), rid)
    out = ex.run_tool("boomtool", "10.0.0.1", "active_recon")
    assert not out.ok
    assert "parse boom" in out.error
    assert any(e["kind"] == "parse_error" for e in db.list_errors(rid))


def _make_executor(tmp_path, monkeypatch, containerize=True):
    cfg = Config(mode=Mode.SANDBOX, out_dir=tmp_path / "o", data_dir=tmp_path / "o" / "d")
    cfg.ensure_dirs()
    db = Database(cfg.db_path)
    rid = db.create_run("sandbox", {}, {}, {})
    registry = Registry()
    registry.add(
        ToolEntry(
            name="gvm",
            category="vuln",
            when_to_use="",
            builtin=True,
            cmd_template=["gvm-cli", "socket"],
            install="apt-get install -y gvm",
            parser="generic",
            phases=[],
            host_only=True,
        )
    )
    scope = Scope.parse(Mode.SANDBOX, [])
    monkeypatch.setattr(executor_module, "tool_available", lambda b: False)
    return db, rid, registry, Executor(db, registry, scope, DockerRunner(), rid, containerize=containerize)


def test_host_only_runs_native_with_install(tmp_path, monkeypatch):
    db, rid, registry, ex = _make_executor(tmp_path, monkeypatch)

    ran = []
    installed = []
    monkeypatch.setattr(executor_module, "run_host", lambda argv, timeout: (ran.append(argv) or RunResult(0, "ok", "")))
    monkeypatch.setattr(executor_module, "run_host_shell", lambda cmd, timeout: (installed.append(cmd) or RunResult(0, "", "")))

    oc = ex._run_once(registry.get("gvm"), ["gvm-cli", "socket"], "10.0.0.1")
    assert oc.ok
    assert installed == ["apt-get install -y gvm"]
    assert ran == [["gvm-cli", "socket"]]
    db.close()


def test_no_containerize_runs_native_without_docker(tmp_path, monkeypatch):
    db, rid, registry, ex = _make_executor(tmp_path, monkeypatch, containerize=False)

    ran = []
    monkeypatch.setattr(executor_module, "run_host", lambda argv, timeout: (ran.append(argv) or RunResult(0, "ok", "")))
    monkeypatch.setattr(executor_module, "run_host_shell", lambda cmd, timeout: RunResult(0, "", ""))

    oc = ex._run_once(registry.get("gvm"), ["gvm-cli", "socket"], "10.0.0.1")
    assert oc.ok
    assert ran == [["gvm-cli", "socket"]]
    db.close()
