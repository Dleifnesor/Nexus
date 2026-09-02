"""Nexus command-line entrypoint.

Modes:
  --scope    Authorized-engagement mode. Prompts for in-scope IPs/CIDRs/domains and enforces
             them. Intrusive actions and breach validation are limited to in-scope assets.
  --sandbox  Unrestricted mode for isolated/monitored labs ONLY. No scope enforcement. Prints
             a prominent warning and requires confirmation (or --yes).

Exactly one mode must be selected.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import Budgets, Config, LLMConfig, Mode, load_env_overrides
from .engine.runner import EngagementRunner
from .logging_ import audit, setup_logging
from .ui.tui import Dashboard
from .ui.web import start_web_dashboard

SANDBOX_BANNER = """
============================================================
  NEXUS SANDBOX MODE - UNRESTRICTED
  No scope enforcement. Intended for ISOLATED, MONITORED
  lab environments ONLY. Running this against systems you
  are not explicitly authorized to test may be ILLEGAL.
============================================================
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nexus", description="AI-assisted vulnerability & remediation scanner")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--scope", action="store_true", help="Authorized-engagement mode (enforced boundaries)")
    mode.add_argument("--sandbox", action="store_true", help="Unrestricted mode (isolated labs only)")

    p.add_argument("--scope-entry", action="append", default=[], help="Scope entry (repeatable): IP/CIDR/domain")
    p.add_argument("--scope-file", type=Path, help="File with one scope entry per line")
    p.add_argument("--scope-exclude", action="append", default=[], help="Excluded IP/CIDR/domain (repeatable)")

    p.add_argument("--llm-provider", default="ollama", choices=["ollama", "openai", "anthropic"])
    p.add_argument("--model", default="llama3.1:8b", help="LLM model name")
    p.add_argument("--llm-base-url", default=None, help="LLM API base URL")

    p.add_argument("--max-time", type=int, default=3600, help="Max wall-clock seconds")
    p.add_argument("--max-tokens", type=int, default=2_000_000, help="Max LLM tokens")
    p.add_argument("--max-actions", type=int, default=500, help="Max actions")
    p.add_argument("--convergence-iters", type=int, default=3, help="Idle iterations before a phase converges")

    p.add_argument("--out", type=Path, default=Path.cwd() / "nexus-out", help="Output directory")
    p.add_argument("--resume", default=None, help="Resume an existing run by ID")
    p.add_argument("--diff", default=None, help="Render a finding diff against a previous run ID")
    p.add_argument("--web", action="store_true", help="Enable local read-only web dashboard")
    p.add_argument("--no-tui", action="store_true", help="Disable the live TUI dashboard")
    p.add_argument("--docker-network", default=None, help="Docker network for containerized tools")
    p.add_argument("--no-docker", action="store_true", help="Run all tools natively on the host (no containers)")
    p.add_argument("--rate-limit-ms", type=int, default=0, help="Min ms between tool actions (0 = disabled)")
    p.add_argument("--max-concurrent", type=int, default=1, help="Max parallel tool actions per iteration")
    p.add_argument("-y", "--yes", action="store_true", help="Assume yes to confirmations")
    p.add_argument("--check", action="store_true", help="Run prerequisite checks and exit")
    return p


def _collect_scope(args) -> list[str]:
    entries: list[str] = list(args.scope_entry)
    if args.scope_file and args.scope_file.exists():
        entries += [ln.strip() for ln in args.scope_file.read_text(encoding="utf-8").splitlines()]
    if args.scope and not entries and not args.resume:
        # Interactive prompt for scope
        print("Enter scope entries (IPs, CIDRs, domains), one per line. Blank line to finish:")
        while True:
            try:
                line = input("scope> ").strip()
            except EOFError:
                break
            if not line:
                break
            entries.append(line)
    return [e for e in entries if e]


def _confirm_sandbox(assume_yes: bool) -> bool:
    print(SANDBOX_BANNER)
    if assume_yes:
        return True
    try:
        ans = input("Type 'I ACCEPT' to proceed in sandbox mode: ").strip()
    except EOFError:
        return False
    return ans == "I ACCEPT"


def _websearch(query: str) -> str:
    """Best-effort web search backend for tool discovery.

    Uses DuckDuckGo's HTML endpoint if reachable; returns an empty string on failure so the
    discovery module degrades gracefully offline.
    """
    import httpx

    try:
        resp = httpx.get(
            "https://duckduckgo.com/html/",
            params={"q": query},
            headers={"User-Agent": "Mozilla/5.0 nexus-scanner"},
            timeout=20,
        )
        resp.raise_for_status()
        return resp.text[:8000]
    except Exception:
        return ""


def _run_checks(cfg: Config) -> int:
    from .preflight import run_all

    print("Nexus prerequisite checks:")
    all_ok = True
    for r in run_all(cfg):
        status = "OK " if r.ok else "!! "
        if not r.ok and r.name.startswith("tool:"):
            status = ".. "  # missing built-in tools are non-blocking
        elif not r.ok:
            all_ok = False
        print(f"  [{status}] {r.name}: {r.detail}")
    return 0 if all_ok else 1


def _render_diff(cfg: Config, run_id: str, other_run_id: str) -> None:
    from .report.renderer import Renderer
    from .storage.db import Database

    db = Database(cfg.db_path)
    try:
        outputs = Renderer(db, run_id, cfg.out_dir / "reports").render_diff(other_run_id)
    finally:
        db.close()
    for fmt, path in outputs.items():
        print(f"  DIFF {fmt.upper()}: {path}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    mode = Mode.SANDBOX if args.sandbox else Mode.SCOPE

    if args.check:
        cfg = Config(
            mode=mode,
            llm=LLMConfig(provider=args.llm_provider, model=args.model, base_url=args.llm_base_url),
            out_dir=args.out,
            data_dir=args.out / "data",
        )
        cfg = load_env_overrides(cfg)
        return _run_checks(cfg)

    if mode == Mode.SANDBOX and not _confirm_sandbox(args.yes):
        print("Sandbox mode not confirmed; aborting.")
        return 2

    scope_entries = _collect_scope(args)
    if mode == Mode.SCOPE and not scope_entries and not args.resume:
        print("Scope mode requires at least one scope entry.")
        return 2

    cfg = Config(
        mode=mode,
        scope_raw=scope_entries,
        scope_exclusions=list(args.scope_exclude),
        llm=LLMConfig(provider=args.llm_provider, model=args.model, base_url=args.llm_base_url),
        budgets=Budgets(
            max_time_seconds=args.max_time,
            max_tokens=args.max_tokens,
            max_actions=args.max_actions,
            convergence_iters=args.convergence_iters,
        ),
        out_dir=args.out,
        data_dir=args.out / "data",
        enable_web=args.web,
        docker_network=args.docker_network,
        docker_enabled=not args.no_docker,
        rate_limit_ms=args.rate_limit_ms,
        max_concurrent=args.max_concurrent,
        resume_run_id=args.resume,
        assume_yes=args.yes,
    )
    cfg.ensure_dirs()
    cfg = load_env_overrides(cfg)
    setup_logging(cfg.log_dir)
    audit("cli.start", mode=mode.value, scope=scope_entries, resume=args.resume)

    runner = EngagementRunner(cfg, search_fn=_websearch)
    run_id = cfg.resume_run_id or "pending"

    dashboard = Dashboard(run_id, mode.value, enabled=not args.no_tui)
    try:
        with dashboard:
            # rebind progress once we know the run_id (set on first emit)
            runner.progress = dashboard.progress
            if cfg.enable_web:
                start_web_dashboard(cfg.db_path, run_id if run_id != "pending" else "")
            result = runner.run()
            if args.diff:
                _render_diff(cfg, result["run_id"], args.diff)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    finally:
        runner.close()

    print(f"\nRun {result['run_id']} finished with status: {result['status']}")
    for fmt, path in result["reports"].items():
        print(f"  {fmt.upper()}: {path}")
    print(f"  Stats: {result['stats']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
