"""Run built-in tools on the host with timeout and output capture."""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class RunResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_host(argv: list[str], timeout: int) -> RunResult:
    """Execute argv on the host. Never uses shell=True to avoid injection."""
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return RunResult(proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        err = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        return RunResult(124, out, err, timed_out=True)
    except FileNotFoundError as e:
        return RunResult(127, "", str(e))
