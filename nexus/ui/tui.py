"""Live TUI dashboard using Rich.

Bound to the engine's progress callback. Shows current phase, latest action, live counts,
budget usage, and a rolling feed of recent events. Designed for a headless Kali box during
long unattended runs.
"""
from __future__ import annotations

import threading
from collections import deque

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


class Dashboard:
    def __init__(self, run_id: str, mode: str, enabled: bool = True):
        self.run_id = run_id
        self.mode = mode
        self.enabled = enabled
        self.console = Console()
        self._lock = threading.Lock()
        self._phase = "starting"
        self._last_msg = ""
        self._stats: dict = {}
        self._feed: deque[str] = deque(maxlen=12)
        self._live: Live | None = None

    def __enter__(self) -> Dashboard:
        if self.enabled:
            self._live = Live(self._render(), console=self.console, refresh_per_second=4, screen=False)
            self._live.__enter__()
        return self

    def __exit__(self, *exc) -> None:
        if self._live:
            self._live.update(self._render())
            self._live.__exit__(*exc)

    def progress(self, phase: str, msg: str, stats: dict) -> None:
        with self._lock:
            self._phase = phase
            self._last_msg = msg
            self._stats = stats
            self._feed.appendleft(f"[{phase}] {msg}")
        if self._live:
            self._live.update(self._render())
        elif self.enabled:
            self.console.log(f"[{phase}] {msg}")

    def _render(self):
        header = Text(f"Nexus  |  run {self.run_id}  |  mode {self.mode}", style="bold cyan")

        stats = Table.grid(padding=(0, 2))
        stats.add_column(justify="right", style="bold")
        stats.add_column()
        stats.add_row("Phase", self._phase)
        stats.add_row("Assets", str(self._stats.get("assets", 0)))
        stats.add_row("Findings", str(self._stats.get("findings", 0)))
        stats.add_row("Actions", str(self._stats.get("actions", 0)))
        budget = self._stats.get("budget")
        if budget:
            stats.add_row(
                "Budget",
                f"{budget.get('elapsed_s',0)}s / {budget.get('actions',0)} actions / {budget.get('tokens',0)} tok",
            )

        feed = Text("\n".join(self._feed) or "(waiting...)", style="dim")
        return Group(
            Panel(header, border_style="cyan"),
            Panel(stats, title="Status", border_style="green"),
            Panel(feed, title="Activity", border_style="blue"),
        )
