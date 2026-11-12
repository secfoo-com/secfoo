"""`secfoo sensor conformance -- <command>`: checks a runtime probe against #73.

The kit starts a fake sensor on loopback TCP, runs the command once per
step of the sample-app contract (see sample_app.py) with the probe pointed
at it, and checks:

    inert       with SECFOO_SENSOR unset, the probe connects to nothing
    call        a hello, then valid #53 lines, and a hit for the watched symbol (count 3)
    nocall      a session but no hit
    privacy     no argument values, concrete URL paths, query strings, header values
    fail-open   the app keeps working, and exits 0, when the sensor dies mid-run
    overhead    a watched call costs at most --max-call-overhead-us more (marginal, from two loop sizes),
                and the probe's one-time start/exit work stays under --max-startup-seconds

Every line in every step must validate as a protocol message or #53 event.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess  # nosec B404 -- runs the probe author's own sample app
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from secfoo.runtime.protocol import (
    PROTOCOL_VERSION,
    SENTINEL,
    ProtocolError,
    forbidden_data,
    validate_message,
)

DEFAULT_SYMBOL = "secfoo.runtime.conformance.vulnerable.parse"
FINGERPRINT = "conformance-fp"
STEP_TIMEOUT_SECONDS = 60


class FakeSensor:
    """Loopback TCP listener that records every line and answers hello with
    welcome. `kill_after_first_batch` closes everything after the first
    batch, the way a crashed sidecar would."""

    def __init__(self, *, kill_after_first_batch: bool = False) -> None:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(16)
        self._server.settimeout(0.2)
        self.port = self._server.getsockname()[1]
        self.kill = kill_after_first_batch
        self.lines: list[str] = []
        self.connections = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def address(self) -> str:
        return f"tcp://127.0.0.1:{self.port}"

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except (TimeoutError, OSError):
                continue
            self.connections += 1
            threading.Thread(target=self._read, args=(conn,), daemon=True).start()

    def _read(self, conn: socket.socket) -> None:
        conn.settimeout(STEP_TIMEOUT_SECONDS)
        buffer = b""
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buffer += chunk
                *complete, buffer = buffer.split(b"\n")
                for raw in complete:
                    line = raw.decode("utf-8", errors="replace")
                    self.lines.append(line)
                    if line.startswith('{"type":"hello"'):
                        welcome = {"type": "welcome", "protocol": PROTOCOL_VERSION, "flush_interval": 0.1}
                        conn.sendall((json.dumps(welcome) + "\n").encode())
                if self.kill and len(self.lines) > 1:
                    self.close()
                    break
        except OSError:
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self._stop.set()
        try:
            self._server.close()
        except OSError:
            pass


@dataclass
class StepResult:
    name: str
    passed: bool
    detail: str = ""
    lines: list[str] = field(default_factory=list)


def _watchlist(path: Path, symbol: str, ecosystem: str) -> Path:
    path.write_text(json.dumps({"version": 1, "generated_at": "2026-01-01T00:00:00Z", "entries": [{
        "finding_fingerprint": FINGERPRINT, "advisory": None, "ecosystem": ecosystem, "package": "conformance",
        "version": "1.0", "granularity": "symbol", "symbols": [symbol], "source": "osv"}]}), encoding="utf-8")
    return path


def _run(command: list[str], env: dict[str, str]) -> tuple[subprocess.CompletedProcess, float]:
    started = time.perf_counter()
    result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=STEP_TIMEOUT_SECONDS,  # nosec B603
                            check=False)
    return result, time.perf_counter() - started


def _parse(lines: list[str]) -> tuple[list[dict], list[str]]:
    messages, problems = [], []
    for number, line in enumerate(lines, start=1):
        try:
            messages.append(validate_message(json.loads(line)))
        except (json.JSONDecodeError, ProtocolError) as exc:
            problems.append(f"line {number}: {exc}")
    return messages, problems


def _hit_count(messages: list[dict], symbol: str) -> int:
    latest: dict = {}
    for message in messages:
        if message.get("type") == "hit" and message.get("symbol") == symbol:
            latest[(message["session"], message.get("route", ""))] = message["count"]  # running totals
    return sum(latest.values())


def run_kit(command: list[str], *, symbol: str = DEFAULT_SYMBOL, ecosystem: str = "PyPI",
            max_call_overhead_us: float = 50.0, loop_calls: int = 200000,
            max_startup_seconds: float = 5.0) -> list[StepResult]:
    results: list[StepResult] = []
    with tempfile.TemporaryDirectory(prefix="secfoo-conformance-") as tmp:
        watchlist = _watchlist(Path(tmp) / "watchlist.json", symbol, ecosystem)
        base = {k: v for k, v in os.environ.items() if not k.startswith("SECFOO_")}
        base.update(SECFOO_WATCHLIST=str(watchlist), SECFOO_FLUSH_INTERVAL="0.1",
                    SECFOO_CONFORMANCE_SENTINEL=SENTINEL, SECFOO_APP_ROOT=tmp)

        def probe_env(sensor: FakeSensor, step: str, **extra: str) -> dict[str, str]:
            return {**base, "SECFOO_SENSOR": "1", "SECFOO_SENSOR_ADDR": sensor.address,
                    "SECFOO_CONFORMANCE_STEP": step, **extra}

        # inert: the probe must not even connect without SECFOO_SENSOR=1
        sensor = FakeSensor()
        env = {**base, "SECFOO_SENSOR_ADDR": sensor.address, "SECFOO_CONFORMANCE_STEP": "call"}
        proc, _ = _run(command, env)
        sensor.close()
        results.append(StepResult(
            "inert", proc.returncode == 0 and sensor.connections == 0,
            f"exit {proc.returncode}, {sensor.connections} connection(s) with SECFOO_SENSOR unset", sensor.lines))

        for step, check in (("call", "hit"), ("nocall", "nohit"), ("request", "privacy")):
            sensor = FakeSensor()
            proc, _ = _run(command, probe_env(sensor, step))
            time.sleep(0.2)
            sensor.close()
            messages, problems = _parse(sensor.lines)
            if proc.returncode != 0:
                problems.append(f"app exited {proc.returncode}: {proc.stderr.strip()[-300:]}")
            if not messages or messages[0].get("type") != "hello":
                problems.append("the first line must be hello")
            if not any(m.get("type") == "session" for m in messages):
                problems.append("no session line")
            count = _hit_count(messages, symbol)
            if check == "hit" and count != 3:
                problems.append(f"expected 3 calls of {symbol}, got {count}")
            if check == "nohit" and count:
                problems.append(f"expected no hit, got {count}")
            if check == "privacy":
                problems += forbidden_data(sensor.lines)
            name = {"hit": "call", "nohit": "nocall", "privacy": "privacy"}[check]
            results.append(StepResult(name, not problems, "; ".join(problems) or f"{len(sensor.lines)} valid line(s)",
                                      sensor.lines))

        # fail-open: the sensor dies after the first batch; the app must not care
        sensor = FakeSensor(kill_after_first_batch=True)
        proc, elapsed = _run(command, probe_env(sensor, "slow"))
        ok = proc.returncode == 0 and "ok" in proc.stdout
        results.append(StepResult("fail-open", ok, f"exit {proc.returncode} after {elapsed:.1f}s with the sensor killed"))

        # overhead: the MARGINAL cost of a watched call, from two loop sizes,
        # so interpreter start-up and the probe's one-time start/exit work
        # (reported separately) don't swamp the per-call number.
        def timed(n: int, probed: bool) -> float:
            extra = {"SECFOO_CONFORMANCE_N": str(n)}
            if not probed:
                return _run(command, {**base, "SECFOO_CONFORMANCE_STEP": "loop", **extra})[1]
            sensor = FakeSensor()
            try:
                return _run(command, probe_env(sensor, "loop", **extra))[1]
            finally:
                sensor.close()

        small, large = loop_calls, loop_calls * 5
        bare_small, bare_large = timed(small, False), timed(large, False)
        probe_small, probe_large = timed(small, True), timed(large, True)
        bare_per_call = max(bare_large - bare_small, 1e-6) / (large - small)
        probe_per_call = max(probe_large - probe_small, 0.0) / (large - small)
        extra_us = (probe_per_call - bare_per_call) * 1e6
        fixed = max(probe_small - bare_small - probe_per_call * small, 0.0)
        results.append(StepResult(
            "overhead", extra_us <= max_call_overhead_us and fixed <= max_startup_seconds,
            f"watched call {bare_per_call * 1e6:.2f}us bare -> {probe_per_call * 1e6:.2f}us probed "
            f"(+{extra_us:.2f}us per call, budget {max_call_overhead_us:.0f}us); "
            f"one-time start/exit {fixed:.2f}s (budget {max_startup_seconds:.0f}s)"))
    return results
