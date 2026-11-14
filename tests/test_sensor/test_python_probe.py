"""#55: the in-process Python probe."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import textwrap
import threading
from pathlib import Path

import pytest

import secfoo
from secfoo.runtime.evidence import ingest_events
from secfoo.sensor import transport as transport_mod
from secfoo.sensor.probe import Probe
from secfoo.storage.repository import RunRepository

SRC = str(Path(secfoo.__file__).resolve().parent.parent)
BACKENDS = ["profile"] + (["monitoring"] if hasattr(sys, "monitoring") else [])

VULN = "def parse(text):\n    return text.upper()\n\ndef safe(text):\n    return text\n"
APP = textwrap.dedent("""\
    import sys
    import sample_vuln

    def handle(secret):
        return sample_vuln.parse(secret) if "--call" in sys.argv else sample_vuln.safe(secret)

    if __name__ == "__main__":
        for _ in range(5):
            handle("password=hunter2")
        print("served")
    """)
WORKERS_APP = textwrap.dedent("""\
    import multiprocessing as mp
    import sample_vuln

    def work(n):
        return sample_vuln.parse("x" * n)

    if __name__ == "__main__":
        pool = mp.get_context("spawn").Pool(2)
        print(sum(len(r) for r in pool.map(work, range(1, 9), chunksize=4)))
        pool.close()  # workers exit normally, as gunicorn/uvicorn workers do
        pool.join()
    """)


def _watchlist(path: Path, symbols=("sample_vuln.parse",)) -> Path:
    path.write_text(json.dumps({"version": 1, "generated_at": "2026-11-12T00:00:00Z", "entries": [
        {"finding_fingerprint": "fp-1", "advisory": None, "ecosystem": "PyPI", "package": "sample-vuln",
         "version": "1.0", "granularity": "symbol", "symbols": list(symbols), "source": "osv"}]}), encoding="utf-8")
    return path


@pytest.fixture
def app_dir(tmp_path):
    (tmp_path / "sample_vuln.py").write_text(VULN, encoding="utf-8")
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    (tmp_path / "workers.py").write_text(WORKERS_APP, encoding="utf-8")
    _watchlist(tmp_path / "watchlist.json")
    return tmp_path


def _run_instrumented(app_dir: Path, *args: str, backend: str, out: str = "events.ndjson", extra_env=None):
    env = {**os.environ, "PYTHONPATH": SRC, "SECFOO_SENSOR_BACKEND": backend, **(extra_env or {})}
    env.pop("SECFOO_SENSOR_ADDR", None)
    cmd = [sys.executable, "-m", "secfoo.cli", "instrument", "--watchlist", "watchlist.json", "-o", out,
           "--flush-interval", "0.1", "--", sys.executable, *args]
    return subprocess.run(cmd, cwd=app_dir, env=env, capture_output=True, text=True, timeout=120, check=False)


def _events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _latest_hits(events: list[dict]) -> dict:
    hits = {}
    for event in events:
        if event["type"] == "hit":
            hits[(event["session"], event["symbol"])] = event
    return hits


# ---------- calling / not calling the watched function ----------


@pytest.mark.parametrize("backend", BACKENDS)
def test_calling_the_watched_function_is_recorded(app_dir, backend):
    result = _run_instrumented(app_dir, "app.py", "--call", backend=backend)
    assert result.returncode == 0 and "served" in result.stdout, result.stderr
    events = _events(app_dir / "events.ndjson")
    [hit] = _latest_hits(events).values()
    assert hit["finding_fingerprint"] == "fp-1" and hit["symbol"] == "sample_vuln.parse" and hit["count"] == 5
    assert hit["entry_frame"] == "app.py:5"  # the app line that called it
    assert hit["stack_sample"][0].startswith("sample_vuln.py:")
    session = [e for e in events if e["type"] == "session"][-1]  # the final flush's running totals
    assert session["language"] == "python" and session["source"] == "sensor"
    if backend == "monitoring":
        # handle() and parse() ran; safe() didn't.
        assert session["app_functions_executed"] == 2 and session["app_functions_total"] >= 3


@pytest.mark.parametrize("backend", BACKENDS)
def test_not_calling_it_records_a_session_without_hits(app_dir, backend):
    result = _run_instrumented(app_dir, "app.py", backend=backend)
    assert result.returncode == 0, result.stderr
    events = _events(app_dir / "events.ndjson")
    assert any(e["type"] == "session" for e in events)
    assert not any(e["type"] == "hit" for e in events)


@pytest.mark.parametrize("backend", BACKENDS)
def test_argument_values_never_reach_the_events(app_dir, backend):
    _run_instrumented(app_dir, "app.py", "--call", backend=backend)
    assert "hunter2" not in (app_dir / "events.ndjson").read_text(encoding="utf-8")


def test_output_ingests_cleanly_with_the_53_format(app_dir, tmp_path):
    _run_instrumented(app_dir, "app.py", "--call", backend=BACKENDS[-1])
    with RunRepository(db_path=tmp_path / "db.sqlite") as repo:
        pid = repo.upsert_project("/app", "app", "local")
        run_id = repo.get_run(repo.create_run(project_id=pid, skill_id="sca-reachability", skill_name="SCA",
                                              agent_id="claude", confluence_urls=[])).id
        repo.upsert_sca_finding(project_id=pid, fingerprint="fp-1", run_id=run_id, current_ref="D1",
                                package="sample-vuln", severity="High")
        lines = (app_dir / "events.ndjson").read_text(encoding="utf-8").splitlines()
        report = ingest_events(repo.connection, pid, lines)
        assert report.skipped == [] and report.hits >= 1
        assert repo.connection.execute("SELECT count FROM runtime_evidence").fetchone()[0] == 5


# ---------- opt-in only ----------


def test_inert_without_secfoo_sensor(app_dir):
    env = {**os.environ, "PYTHONPATH": SRC, "SECFOO_WATCHLIST": "watchlist.json", "SECFOO_EVENTS_OUT": "events.ndjson"}
    env.pop("SECFOO_SENSOR", None)
    result = subprocess.run([sys.executable, "-m", "secfoo.sensor", "app.py", "--call"], cwd=app_dir, env=env,
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0 and "served" in result.stdout
    assert not (app_dir / "events.ndjson").exists()


def test_importing_the_package_does_nothing(monkeypatch):
    monkeypatch.delenv("SECFOO_SENSOR", raising=False)
    from secfoo import sensor

    assert sensor.start_from_env() is None and sensor.current_probe() is None


# ---------- fail-open ----------


def test_a_broken_watchlist_never_stops_the_app(app_dir):
    (app_dir / "watchlist.json").write_text("{not json", encoding="utf-8")
    result = _run_instrumented(app_dir, "app.py", "--call", backend=BACKENDS[-1])
    assert result.returncode == 0 and "served" in result.stdout
    assert "secfoo sensor" in result.stderr


@pytest.mark.parametrize("backend", BACKENDS)
def test_an_error_inside_the_probe_disables_it_and_the_app_keeps_running(tmp_path, backend, monkeypatch, capsys):
    module = tmp_path / "probe_target_mod.py"
    module.write_text(VULN, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    import probe_target_mod

    probe = Probe(watchlist_path=str(_watchlist(tmp_path / "w.json", ("probe_target_mod.parse",))),
                  transport=transport_mod.NullTransport(), app_root=str(tmp_path), flush_seconds=60, backend=backend)
    probe.start()
    try:
        def boom(*_a, **_k):
            raise RuntimeError("probe bug")

        monkeypatch.setattr(probe, "_record_hit", boom)
        assert probe_target_mod.parse("abc") == "ABC"  # app code still works
        assert probe_target_mod.parse("def") == "DEF"
        assert probe._broken
        assert "disabled after an internal error" in capsys.readouterr().err
    finally:
        probe.stop()
        if backend == "profile":
            sys.setprofile(None)


def test_sensor_dying_mid_run_drops_events_without_blocking(tmp_path):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen()
    port = server.getsockname()[1]
    received = []

    def accept_once():
        conn, _ = server.accept()
        data = b""
        while b"\n" not in data or data.count(b"\n") < 2:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
        received.append(data)
        conn.close()
        server.close()  # the sensor goes away

    thread = threading.Thread(target=accept_once, daemon=True)
    thread.start()
    tcp = transport_mod.SocketTransport(f"tcp://127.0.0.1:{port}")
    assert tcp.send([{"type": "session", "id": "s"}])
    thread.join(5)
    hello = json.loads(received[0].splitlines()[0])
    assert hello["type"] == "hello" and hello["protocol"] == 1 and hello["runtime"] == "python"
    # Sensor gone: sends now fail fast and return False instead of raising or retrying.
    results = [tcp.send([{"type": "session", "id": "s"}]) for _ in range(3)]
    assert results[-1] is False


# ---------- several processes ----------


def test_each_worker_process_is_its_own_session(app_dir):
    result = _run_instrumented(app_dir, "workers.py", backend=BACKENDS[-1])
    assert result.returncode == 0 and result.stdout.strip() == "36", result.stderr
    events = _events(app_dir / "events.ndjson")
    hits = _latest_hits(events)
    sessions = {e["id"] for e in events if e["type"] == "session"}
    assert len(sessions) >= 2  # the parent and its spawned workers are separate sessions
    assert {session for session, _ in hits} < sessions  # hits come from workers, not the parent
    assert sum(h["count"] for h in hits.values()) == 8  # every call counted exactly once


def test_pid_placeholder_gives_each_process_its_own_file(app_dir):
    result = _run_instrumented(app_dir, "workers.py", backend=BACKENDS[-1], out="events-{pid}.ndjson")
    assert result.returncode == 0, result.stderr
    assert len(list(app_dir.glob("events-*.ndjson"))) >= 2


# ---------- transports ----------


@pytest.mark.parametrize("address", ["tcp://10.0.0.5:7461", "tcp://example.com:7461", "tcp://127.0.0.1"])
def test_tcp_sensor_address_must_be_loopback_with_a_port(address):
    with pytest.raises(transport_mod.TransportError):
        transport_mod.SocketTransport(address)


def test_transport_selection(tmp_path):
    assert isinstance(transport_mod.from_env({}), transport_mod.NullTransport)
    assert isinstance(transport_mod.from_env({"SECFOO_EVENTS_OUT": str(tmp_path / "e")}), transport_mod.FileTransport)
    assert isinstance(transport_mod.from_env({"SECFOO_SENSOR_ADDR": "tcp://127.0.0.1:7461"}),
                      transport_mod.SocketTransport)
    assert isinstance(transport_mod.from_env({"SECFOO_SENSOR_ADDR": "npipe:////./pipe/secfoo-sensor"}),
                      transport_mod.PipeTransport)
    with pytest.raises(transport_mod.TransportError):
        transport_mod.from_env({"SECFOO_SENSOR_ADDR": "ftp://x"})


def test_direct_mode_needs_explicit_key_and_project(monkeypatch):
    monkeypatch.delenv("SECFOO_API_KEY", raising=False)
    monkeypatch.delenv("SECFOO_API_KEY_FILE", raising=False)
    from secfoo.runtime.client import SensorConfigError

    with pytest.raises(SensorConfigError):
        transport_mod.from_env({"SECFOO_SENSOR_ADDR": "https://secfoo.internal"})


def test_instrument_requires_a_destination_and_a_command(app_dir):
    env = {**os.environ, "PYTHONPATH": SRC}
    env.pop("SECFOO_SENSOR_ADDR", None)
    env.pop("SECFOO_EVENTS_OUT", None)
    no_out = subprocess.run([sys.executable, "-m", "secfoo.cli", "instrument", "--", sys.executable, "app.py"],
                            cwd=app_dir, env=env, capture_output=True, text=True, timeout=60, check=False)
    assert no_out.returncode == 2 and "-o events.ndjson" in no_out.stderr
