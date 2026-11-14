"""Detects and safely replaces an existing `secfoo serve` on the same
host/port, instead of `secfoo serve` failing with a raw bind error.

Follows the practitioner consensus for this problem: identify who holds the
port before doing anything, never kill a process we can't positively
identify as our own, stop it gracefully (SIGTERM) before falling back to a
hard kill, and leave everything untouched -- just print the fix -- when we
can't tell what's there. See `secfoo serve --replace`.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass

_PROBE_TIMEOUT = 5.0


@dataclass(frozen=True)
class PortOwner:
    pid: int
    command: str

    @property
    def is_secfoo_serve(self) -> bool:
        lowered = self.command.lower()
        return "secfoo" in lowered and "serve" in lowered


def port_in_use(host: str, port: int) -> bool:
    """A real listen-bind probe (not a connect attempt), so it also catches
    a listener that hasn't accepted a connection yet."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind((host, port))
        except OSError:
            return True
    return False


def find_owner(port: int, *, timeout: float = _PROBE_TIMEOUT) -> PortOwner | None:
    """Who's listening on `port`, if it can be determined at all. Returns
    None rather than guessing -- callers must never kill an unidentified
    owner, even with --replace."""
    try:
        if sys.platform == "win32":
            return _find_owner_windows(port, timeout=timeout)
        return _find_owner_posix(port, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


def _run(args: list[str], *, timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=False, capture_output=True, text=True, timeout=timeout)


def _find_owner_posix(port: int, *, timeout: float) -> PortOwner | None:
    lsof = _run(["lsof", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"], timeout=timeout)
    pids = [int(line) for line in lsof.stdout.split() if line.strip().isdigit()]
    if not pids:
        return None
    pid = pids[0]
    ps = _run(["ps", "-p", str(pid), "-o", "command="], timeout=timeout)
    command = ps.stdout.strip()
    return PortOwner(pid=pid, command=command) if command else None


def _find_owner_windows(port: int, *, timeout: float) -> PortOwner | None:
    netstat = _run(["netstat", "-ano", "-p", "TCP"], timeout=timeout)
    pid = None
    for line in netstat.stdout.splitlines():
        parts = line.split()
        if (
            len(parts) >= 4 and parts[0] == "TCP" and parts[-1].isdigit() and "LISTENING" in line
            and parts[1].endswith(f":{port}")
        ):
            pid = int(parts[-1])
            break
    if pid is None:
        return None
    wmic = _run(["wmic", "process", "where", f"ProcessId={pid}", "get", "CommandLine"], timeout=timeout)
    lines = [line.strip() for line in wmic.stdout.splitlines() if line.strip() and line.strip() != "CommandLine"]
    command = lines[0] if lines else ""
    return PortOwner(pid=pid, command=command) if command else None


def _process_alive(pid: int) -> bool:
    if sys.platform == "win32":
        try:
            result = _run(["tasklist", "/FI", f"PID eq {pid}"], timeout=_PROBE_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired):
            return True  # can't tell -- assume alive rather than proceed carelessly
        return str(pid) in result.stdout
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_until_gone(pid: int, *, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_alive(pid):
            return True
        time.sleep(0.2)
    return not _process_alive(pid)


def stop_gracefully(owner: PortOwner, *, timeout: float = _PROBE_TIMEOUT) -> bool:
    """SIGTERM, wait, then SIGKILL as a fallback. Only ever call this on an
    owner that passed `is_secfoo_serve`. Returns True once it's gone."""
    _signal(owner.pid, force=False)
    if _wait_until_gone(owner.pid, timeout=timeout):
        return True
    _signal(owner.pid, force=True)
    return _wait_until_gone(owner.pid, timeout=timeout)


def _signal(pid: int, *, force: bool) -> None:
    try:
        if sys.platform == "win32":
            args = ["taskkill", "/PID", str(pid)]
            if force:
                args.insert(1, "/F")
            _run(args, timeout=_PROBE_TIMEOUT)
        else:
            os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
    except (OSError, subprocess.TimeoutExpired, ProcessLookupError):
        pass


__all__ = ["PortOwner", "find_owner", "port_in_use", "stop_gracefully"]
