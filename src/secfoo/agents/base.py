"""Common subprocess execution contract for every agent adapter.

Concrete adapters only need to implement `build_command()` and, optionally,
`extract_report()` for CLIs that wrap their answer in a JSON envelope. All
timeout/kill/binary-detection behavior lives here so it's implemented once
and correctly.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Literal

Status = Literal["success", "failed", "timeout", "binary_not_found"]


def _kill_process_tree(pid: int, *, posix: bool = os.name == "posix") -> None:
    """Kill `pid` and its descendants after a timeout.

    os.killpg/os.getpgid only exist on POSIX (start_new_session=True above
    puts the child in its own process group there). Windows has no process
    group equivalent reachable from the stdlib, so `taskkill /T` (kill
    process tree) is used instead -- both are needed to reliably contain
    Cursor's documented `agent -p` hang bug if it spawns any grandchildren;
    killing just the direct child (e.g. subprocess.run's own timeout
    handling, or Popen.kill()) is not enough.

    `posix` defaults to the real platform and only exists so tests can
    exercise both branches on a single OS -- monkeypatching os.name itself
    is not safe here since pytest's own traceback machinery reads it too.
    """
    try:
        if posix:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        else:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
    except (ProcessLookupError, OSError):
        pass


@dataclass
class AgentResult:
    agent: str
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool
    status: Status
    raw_report: str
    # AI spend for this run, when the agent reports it. None means unknown
    # (the CLI doesn't expose it), not zero.
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None


@dataclass(frozen=True)
class Usage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None


class AgentAdapter(ABC):
    name: ClassVar[str]
    binary: ClassVar[str]
    default_timeout_seconds: ClassVar[int] = 1800

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    @abstractmethod
    def build_command(self, prompt: str, *, workdir: Path) -> list[str]:
        """Return the argv to invoke this agent non-interactively with `prompt`."""

    def extract_report(self, stdout: str) -> str:
        """Pull the report text out of raw stdout. Default: stdout is the report."""
        return stdout

    def extract_usage(self, stdout: str) -> Usage:
        """Pull token counts / cost out of raw stdout. Default: unknown."""
        return Usage()

    def run(self, prompt: str, *, workdir: Path, timeout: int | None = None) -> AgentResult:
        if not self.is_available():
            return AgentResult(
                agent=self.name,
                exit_code=None,
                stdout="",
                stderr=f"binary {self.binary!r} not found on PATH",
                duration_seconds=0.0,
                timed_out=False,
                status="binary_not_found",
                raw_report="",
            )

        cmd = self.build_command(prompt, workdir=workdir)
        effective_timeout = timeout or self.default_timeout_seconds
        started = time.monotonic()

        # Driven via Popen (rather than subprocess.run) so that on timeout we
        # can kill the whole process tree via _kill_process_tree() -- see
        # its docstring for why subprocess.run's own timeout handling isn't
        # enough on its own.
        proc = subprocess.Popen(
            cmd,
            cwd=workdir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = proc.communicate(timeout=effective_timeout)
            duration = time.monotonic() - started
            status: Status = "success" if proc.returncode == 0 else "failed"
            usage = self.extract_usage(stdout)
            return AgentResult(
                agent=self.name,
                exit_code=proc.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=duration,
                timed_out=False,
                status=status,
                raw_report=self.extract_report(stdout) if status == "success" else "",
                input_tokens=usage.input_tokens,
                output_tokens=usage.output_tokens,
                cost_usd=usage.cost_usd,
            )
        except subprocess.TimeoutExpired:
            _kill_process_tree(proc.pid)
            stdout, stderr = proc.communicate()
            duration = time.monotonic() - started
            return AgentResult(
                agent=self.name,
                exit_code=None,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=duration,
                timed_out=True,
                status="timeout",
                raw_report="",
            )
