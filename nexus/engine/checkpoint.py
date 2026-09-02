"""Checkpoint helpers for resumable runs."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..storage.db import Database


@dataclass
class EngineState:
    """Serializable engine progress used for resume."""

    phase_index: int = 0
    completed_phases: list[str] = field(default_factory=list)
    iteration: int = 0
    budget: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "phase_index": self.phase_index,
            "completed_phases": self.completed_phases,
            "iteration": self.iteration,
            "budget": self.budget,
        }

    @classmethod
    def from_dict(cls, d: dict) -> EngineState:
        return cls(
            phase_index=d.get("phase_index", 0),
            completed_phases=list(d.get("completed_phases", [])),
            iteration=d.get("iteration", 0),
            budget=dict(d.get("budget", {})),
        )


def save(db: Database, run_id: str, phase: str, state: EngineState) -> None:
    db.save_checkpoint(run_id, phase, state.to_dict())


def load(db: Database, run_id: str) -> EngineState:
    cp = db.latest_checkpoint(run_id)
    if not cp:
        return EngineState()
    return EngineState.from_dict(cp["state"])
