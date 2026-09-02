"""Budget accounting and hard stop signals to prevent runaway autonomy."""
from __future__ import annotations

import time
from dataclasses import dataclass

from ..config import Budgets
from ..llm.provider import TokenCounter


@dataclass
class BudgetState:
    reason: str = ""

    def exhausted(self) -> bool:
        return bool(self.reason)


class BudgetTracker:
    def __init__(self, budgets: Budgets, counter: TokenCounter):
        self.budgets = budgets
        self.counter = counter
        self.actions = 0
        self.elapsed_offset = 0.0
        self.start = time.monotonic()

    def restore(self, budget: dict) -> None:
        """Restore accumulated usage from a previous run (resume support)."""
        self.actions = int(budget.get("actions", 0))
        self.elapsed_offset = float(budget.get("elapsed_s", 0.0))
        self.start = time.monotonic()

    def record_action(self) -> None:
        self.actions += 1

    def elapsed(self) -> float:
        return time.monotonic() - self.start + self.elapsed_offset

    def check(self) -> BudgetState:
        if self.elapsed() >= self.budgets.max_time_seconds:
            return BudgetState(f"time budget reached ({self.budgets.max_time_seconds}s)")
        if self.actions >= self.budgets.max_actions:
            return BudgetState(f"action budget reached ({self.budgets.max_actions})")
        if self.counter.total >= self.budgets.max_tokens:
            return BudgetState(f"token budget reached ({self.budgets.max_tokens})")
        return BudgetState()

    def snapshot(self) -> dict:
        return {
            "actions": self.actions,
            "elapsed_s": round(self.elapsed(), 1),
            "tokens": self.counter.total,
            "max_actions": self.budgets.max_actions,
            "max_time_s": self.budgets.max_time_seconds,
            "max_tokens": self.budgets.max_tokens,
        }
