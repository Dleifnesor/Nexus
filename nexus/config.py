"""Configuration and operation-mode resolution for Nexus."""
from __future__ import annotations

import enum
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


class Mode(str, enum.Enum):
    """Operation mode.

    SCOPE:   enforced boundaries. Actions against out-of-scope targets are refused.
             Intrusive actions and credential validation require in-scope targets and
             are audit-logged. Breach data is used only to validate in-scope assets.
    SANDBOX: unrestricted. Isolated/monitored labs only. No scope enforcement.
    """

    SCOPE = "scope"
    SANDBOX = "sandbox"


@dataclass
class LLMConfig:
    provider: str = "ollama"  # ollama | openai | anthropic
    model: str = "llama3.1:8b"
    base_url: str | None = None  # e.g. http://localhost:11434 for ollama
    api_key: str | None = None
    temperature: float = 0.2
    max_output_tokens: int = 2048


@dataclass
class Budgets:
    """Hard stop limits to prevent runaway autonomy."""

    max_time_seconds: int = 3600
    max_tokens: int = 2_000_000
    max_actions: int = 500
    convergence_iters: int = 3  # stop a phase after N iters with no new assets/findings


@dataclass
class Config:
    mode: Mode
    scope_raw: list[str] = field(default_factory=list)  # user-entered IPs/CIDRs/domains
    scope_exclusions: list[str] = field(default_factory=list)  # excluded IPs/CIDRs/domains
    objective: str = ""  # free-text engagement goal (steers the planner and report)
    llm: LLMConfig = field(default_factory=LLMConfig)
    budgets: Budgets = field(default_factory=Budgets)
    out_dir: Path = field(default_factory=lambda: Path.cwd() / "nexus-out")
    data_dir: Path = field(default_factory=lambda: Path.cwd() / "nexus-out" / "data")
    enable_web: bool = False
    docker_network: str | None = None  # container network policy override
    docker_enabled: bool = True  # False = run all tools natively on the host
    tool_search: bool = True  # discover & install new tools via web search when needed
    allow_tool_install: bool = True  # allow installing LLM-discovered tools on the host
    skills_enabled: bool = True  # load reusable playbooks to guide the planner
    skills_learn: bool = True  # distill new playbooks from completed runs
    skills_dir: Path | None = None  # skill library location (default: ~/.nexus/skills)
    skills_focus: list[str] = field(default_factory=list)  # focus tags to prioritize skills
    rate_limit_ms: int = 0  # min milliseconds between actions (0 = disabled)
    max_concurrent: int = 1  # max parallel tool actions per phase iteration
    nvd_api_key: str | None = None
    hibp_api_key: str | None = None
    resume_run_id: str | None = None
    assume_yes: bool = False

    @property
    def db_path(self) -> Path:
        return self.data_dir / "nexus.db"

    @property
    def log_dir(self) -> Path:
        return self.out_dir / "logs"

    def ensure_dirs(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["mode"] = self.mode.value
        d["out_dir"] = str(self.out_dir)
        d["data_dir"] = str(self.data_dir)
        d["skills_dir"] = str(self.skills_dir) if self.skills_dir else None
        # never persist secrets in run metadata
        d["llm"]["api_key"] = bool(self.llm.api_key)
        d.pop("nvd_api_key", None)
        d.pop("hibp_api_key", None)
        return d


def load_env_overrides(cfg: Config) -> Config:
    """Apply environment variables for secrets and endpoints."""
    cfg.llm.api_key = cfg.llm.api_key or os.environ.get("NEXUS_LLM_API_KEY")
    cfg.llm.base_url = cfg.llm.base_url or os.environ.get("NEXUS_LLM_BASE_URL")
    cfg.nvd_api_key = cfg.nvd_api_key or os.environ.get("NEXUS_NVD_API_KEY")
    cfg.hibp_api_key = cfg.hibp_api_key or os.environ.get("NEXUS_HIBP_API_KEY")
    if cfg.llm.provider == "ollama" and not cfg.llm.base_url:
        cfg.llm.base_url = "http://localhost:11434"
    return cfg
