"""#115: the Python probe driven in-process, so coverage sees it.

test_python_probe.py runs the probe in subprocesses (the real deployment
shape), which coverage cannot measure. These tests drive the same `Probe`
directly and assert behaviour: what a watched call records, what is never
recorded, how flushing reacts to a slow or dead sensor, and that shutdown
releases every hook -- including after the probe disabled itself.
"""
from __future__ import annotations

import atexit
import importlib
import json
import os
import runpy
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

from secfoo import sensor as sensor_pkg
from secfoo.runtime.conformance.kit import FakeSensor
from secfoo.runtime.protocol import SENTINEL, forbidden_data, validate_message
from secfoo.sensor import __main__ as sensor_main
from secfoo.sensor import probe as probe_mod
from secfoo.sensor import transport as transport_mod
from secfoo.sensor.probe import Probe, _count_app_functions, _ImportWatcher, _resolve

BACKENDS = ["profile"] + (["monitoring"] if hasattr(sys, "monitoring") else [])

VULN = '''\
import functools


def parse(text):
    return text.upper()


def safe(text):
    return text


def _logged(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)
    return wrapper


@_logged
def decorated(text):
    return text[::-1]


class Codec:
    def encode(self, text):
        return text * 2

    @staticmethod
    def static(text):
        return text

    @classmethod
    def build(cls):
        return cls()
'''

APP = '''\
import {vuln}


def handle(secret):
    return {vuln}.parse(secret)


def harmless(secret):
    return {vuln}.safe(secret)
'''


# ---------- helpers ----------


class RecordingTransport:
    """Records every batch and the order of send/close; `result` is what
    send() returns, `error` makes it raise."""

    def __init__(self, result: bool = True, error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.batches: list[list[dict]] = []
        self.calls: list[str] = []
        self.reopened = 0

    def send(self, events):
        self.calls.append("send")
        if self.error is not None:
            raise self.error
        self.batches.append(events)
        return self.result

    def reopen(self):
        self.reopened += 1
        return self

    def close(self):
        self.calls.append("close")


def _write_watchlist(path: Path, symbols, *, fingerprint: str = "fp-1", ecosystem: str = "PyPI") -> Path:
    path.write_text(json.dumps({"version": 1, "generated_at": "2026-11-12T00:00:00Z", "entries": [
        {"finding_fingerprint": fingerprint, "advisory": None, "ecosystem": ecosystem, "package": "sample-vuln",
         "version": "1.0", "granularity": "symbol", "symbols": list(symbols), "source": "osv"}]}), encoding="utf-8")
    return path


def _hits(events):
    return [e for e in events if e["type"] == "hit"]


def _session(events):
    [session] = [e for e in events if e["type"] == "session"]
    return session


@pytest.fixture
def modules(tmp_path, monkeypatch):
    """Writes a fresh vulnerable module + app module pair under tmp_path.
    Unique names per call: sys.monitoring DISABLE state and sys.modules are
    process-wide, so tests must never share code objects."""
    monkeypatch.syspath_prepend(str(tmp_path))
    created: list[str] = []

    def make() -> tuple[str, str]:
        tag = uuid.uuid4().hex[:8]
        vuln, app = f"vuln_{tag}", f"app_{tag}"
        (tmp_path / f"{vuln}.py").write_text(VULN, encoding="utf-8")
        (tmp_path / f"{app}.py").write_text(APP.format(vuln=vuln), encoding="utf-8")
        importlib.invalidate_caches()
        created.extend([vuln, app])
        return vuln, app

    yield make
    for name in created:
        sys.modules.pop(name, None)


@pytest.fixture
def make_probe(tmp_path):
    """Builds probes rooted at tmp_path and guarantees they are torn down,
    so a failing test can't leave a profiler or monitoring tool installed."""
    probes: list[Probe] = []

    def make(symbols=(), *, backend="profile", transport=None, flush_seconds=60.0, watchlist=True) -> Probe:
        path = str(_write_watchlist(tmp_path / f"w-{uuid.uuid4().hex[:6]}.json", symbols)) if watchlist else None
        probe = Probe(watchlist_path=path, transport=transport or RecordingTransport(),
                      app_root=str(tmp_path), flush_seconds=flush_seconds, backend=backend)
        probes.append(probe)
        return probe

    yield make
    for probe in probes:
        probe.stop()
        atexit.unregister(probe.stop)
        sys.meta_path[:] = [f for f in sys.meta_path if not (isinstance(f, _ImportWatcher) and f.probe is probe)]
    sys.setprofile(None)
    threading.setprofile(None)  # type: ignore[arg-type]


# ---------- what a watched call records ----------


@pytest.mark.parametrize("backend", BACKENDS)
def test_watched_calls_are_counted_with_the_app_frame_that_made_them(modules, make_probe, backend):
    vuln, app = modules()
    app_mod = importlib.import_module(app)
    probe = make_probe([f"{vuln}.parse"], backend=backend)
    probe.start()

    for _ in range(3):
        assert app_mod.handle("abc") == "ABC"  # the app's behaviour is unchanged
    app_mod.harmless("abc")  # unwatched: never a hit

    events = probe.snapshot()
    [hit] = _hits(events)
    assert hit["symbol"] == f"{vuln}.parse" and hit["finding_fingerprint"] == "fp-1"
    assert hit["count"] == 3 and hit["route"] == "unknown"
    assert hit["entry_frame"] == f"{app}.py:5"  # the line in handle() that called parse()
    assert hit["stack_sample"][0].startswith(f"{vuln}.py:")
    assert hit["first_seen"] <= hit["last_seen"]
    session = _session(events)
    assert session["id"] == probe.session_id == hit["session"]
    assert session["language"] == "python" and session["source"] == "sensor"
    if backend == "monitoring":
        # handle(), harmless(), parse() and safe() ran in app code.
        assert session["app_functions_executed"] == 4
        assert session["app_functions_total"] >= session["app_functions_executed"]


@pytest.mark.parametrize("backend", BACKENDS)
def test_one_symbol_shared_by_two_findings_counts_for_both(modules, make_probe, tmp_path, backend):
    vuln, app = modules()
    app_mod = importlib.import_module(app)
    probe = make_probe(backend=backend, watchlist=False)
    probe.watchlist_path = str(tmp_path / "two.json")
    Path(probe.watchlist_path).write_text(json.dumps({"entries": [
        {"finding_fingerprint": fp, "ecosystem": "PyPI", "symbols": [f"{vuln}.parse"]} for fp in ("fp-a", "fp-b")]}),
        encoding="utf-8")
    probe.start()
    app_mod.handle("x")
    app_mod.handle("y")
    assert {(h["finding_fingerprint"], h["count"]) for h in _hits(probe.snapshot())} == {("fp-a", 2), ("fp-b", 2)}


@pytest.mark.parametrize("backend", BACKENDS)
def test_a_module_imported_after_start_is_watched_once_it_loads(modules, make_probe, backend):
    vuln, app = modules()
    probe = make_probe([f"{vuln}.parse"], backend=backend)
    probe.start()
    assert f"{vuln}.parse" in probe._pending_symbols  # not importable yet

    app_mod = importlib.import_module(app)  # imports vuln through the _ImportWatcher
    app_mod.handle("abc")
    assert not probe._pending_symbols
    assert [h["count"] for h in _hits(probe.snapshot())] == [1]


@pytest.mark.parametrize("backend", BACKENDS)
def test_argument_values_never_reach_a_snapshot(modules, make_probe, backend):
    vuln, app = modules()
    app_mod = importlib.import_module(app)
    probe = make_probe([f"{vuln}.parse"], backend=backend)
    probe.start()
    app_mod.handle(f"password={SENTINEL}")
    lines = [json.dumps(e) for e in probe.snapshot()]
    assert SENTINEL not in "".join(lines)
    assert forbidden_data(lines) == []


# ---------- the callbacks themselves ----------
#
# Coverage cannot trace code running inside a profiler or sys.monitoring
# callback, so the tests above exercise the hot path without it showing up.
# These call the callbacks directly, from an app-root module so the stack
# sample has an app frame to find.

TRIGGER = '''\
def via_monitoring(probe, code):
    return probe._on_py_start(code, 0)


def via_profiler(profiler, frame, event):
    return profiler(frame, event, None)
'''


@pytest.fixture
def trigger(tmp_path, monkeypatch):
    name = f"trigger_{uuid.uuid4().hex[:8]}"
    (tmp_path / f"{name}.py").write_text(TRIGGER, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()
    yield importlib.import_module(name)
    sys.modules.pop(name, None)


class _Frame:
    def __init__(self, code):
        self.f_code = code


@pytest.mark.skipif(not hasattr(sys, "monitoring"), reason="sys.monitoring is 3.12+")
def test_monitoring_callback_keeps_watched_code_and_disables_everything_else(modules, make_probe, trigger):
    vuln, app = modules()
    importlib.import_module(app)
    vmod = sys.modules[vuln]
    probe = make_probe([f"{vuln}.parse"], backend="monitoring")
    probe._load_watchlist(force=True)
    probe._resolve_pending()
    watched = vmod.parse.__code__

    assert trigger.via_monitoring(probe, watched) is None  # stays enabled: every call counts
    assert trigger.via_monitoring(probe, watched) is None
    [hit] = _hits(probe.snapshot())
    assert hit["count"] == 2 and hit["stack_sample"][0].startswith(f"{trigger.__name__}.py:2")
    assert watched in probe._seen_app_code

    unwatched = vmod.safe.__code__
    assert trigger.via_monitoring(probe, unwatched) is sys.monitoring.DISABLE  # one event, then free
    assert unwatched in probe._seen_app_code
    module_code = compile("x = 1", str(Path(vmod.__file__)), "exec")
    assert trigger.via_monitoring(probe, module_code) is sys.monitoring.DISABLE
    assert module_code not in probe._seen_app_code  # module bodies aren't functions
    library = json.dumps.__code__
    assert trigger.via_monitoring(probe, library) is sys.monitoring.DISABLE
    assert library not in probe._seen_app_code


@pytest.mark.skipif(not hasattr(sys, "monitoring"), reason="sys.monitoring is 3.12+")
def test_monitoring_callback_error_disables_the_probe(make_probe, capsys):
    probe = make_probe(backend="monitoring")
    probe._active = True
    assert probe._on_py_start(object(), 0) is sys.monitoring.DISABLE  # no co_name: an internal error
    assert probe._broken and "AttributeError" in capsys.readouterr().err


def test_profile_callback_counts_calls_only(modules, make_probe, trigger, capsys):
    vuln, app = modules()
    importlib.import_module(app)
    vmod = sys.modules[vuln]
    probe = make_probe([f"{vuln}.parse"], backend="profile")
    probe.start()
    profiler = sys.getprofile()
    sys.setprofile(None)  # drive it by hand from here
    threading.setprofile(None)  # type: ignore[arg-type]

    trigger.via_profiler(profiler, _Frame(vmod.parse.__code__), "call")
    trigger.via_profiler(profiler, _Frame(vmod.parse.__code__), "return")  # not a call: ignored
    trigger.via_profiler(profiler, _Frame(vmod.safe.__code__), "call")
    [hit] = _hits(probe.snapshot())
    assert hit["count"] == 1 and hit["stack_sample"][0].startswith(f"{trigger.__name__}.py:6")
    assert {vmod.parse.__code__, vmod.safe.__code__} <= probe._seen_app_code

    trigger.via_profiler(profiler, object(), "call")  # no f_code: an internal error
    assert probe._broken and "AttributeError" in capsys.readouterr().err


def test_stack_sample_keeps_app_frames_only_and_caps_its_depth(make_probe, tmp_path, monkeypatch):
    depth = probe_mod.MAX_STACK_FRAMES + 5
    name = f"deep_{uuid.uuid4().hex[:8]}"
    body = "".join(f"def f{i}(probe):\n    return f{i + 1}(probe)\n\n" for i in range(depth))
    body += f"def f{depth}(probe):\n    return probe._record_hit(probe, ('sym', ['fp']))\n"
    (tmp_path / f"{name}.py").write_text(body, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()
    mod = importlib.import_module(name)
    try:
        probe = make_probe()
        # _record_hit -> _stack_sample skips three frames (itself, _record_hit,
        # the callback); here the "callback" is f{depth} itself.
        mod.f0(probe)
        mod.f0(probe)
    finally:
        sys.modules.pop(name, None)
    [hit] = _hits(probe.snapshot())
    assert hit["count"] == 2
    assert len(hit["stack_sample"]) == probe_mod.MAX_STACK_FRAMES
    assert all(frame.startswith(f"{name}.py:") for frame in hit["stack_sample"])  # no pytest / stdlib frames
    assert hit["entry_frame"] == hit["stack_sample"][1]


# ---------- frame and filename filters ----------


def test_app_code_filter(tmp_path):
    probe = Probe(watchlist_path=None, transport=RecordingTransport(), app_root=str(tmp_path))
    assert probe._is_app_code(str(tmp_path / "pkg" / "views.py"))
    assert not probe._is_app_code("")
    assert not probe._is_app_code("<string>")
    assert not probe._is_app_code("<frozen importlib._bootstrap>")
    assert not probe._is_app_code(str(tmp_path.parent / "elsewhere.py"))


def test_stdlib_and_site_packages_are_never_app_code_even_under_the_app_root():
    stdlib = os.path.dirname(os.__file__)
    probe = Probe(watchlist_path=None, transport=RecordingTransport(), app_root=os.path.dirname(stdlib))
    assert not probe._is_app_code(os.__file__)
    assert not probe._is_app_code(pytest.__file__)


def test_app_code_check_is_cached_per_code_object(tmp_path, monkeypatch):
    probe = Probe(watchlist_path=None, transport=RecordingTransport(), app_root=str(tmp_path))
    calls = []
    monkeypatch.setattr(probe, "_is_app_code", lambda filename: calls.append(filename) or True)
    code = compile("pass", str(tmp_path / "x.py"), "exec")
    assert probe._is_app_code_obj(code) and probe._is_app_code_obj(code)
    assert len(calls) == 1


# ---------- watchlist loading ----------


def test_watchlist_keeps_only_pypi_entries(tmp_path):
    path = tmp_path / "w.json"
    path.write_text(json.dumps({"entries": [
        {"finding_fingerprint": "py", "ecosystem": "PyPI", "symbols": ["a.b"]},
        {"finding_fingerprint": "js", "ecosystem": "npm", "symbols": ["lodash.merge"]},
        {"finding_fingerprint": "nosym", "ecosystem": "PyPI"}]}), encoding="utf-8")
    probe = Probe(watchlist_path=str(path), transport=RecordingTransport(), app_root=str(tmp_path))
    probe._load_watchlist(force=True)
    assert [e["finding_fingerprint"] for e in probe._watch_entries] == ["py", "nosym"]
    assert probe._pending_symbols == {"a.b": ["py"]}


def test_no_or_missing_watchlist_watches_nothing(tmp_path):
    for path in (None, str(tmp_path / "absent.json")):
        probe = Probe(watchlist_path=path, transport=RecordingTransport(), app_root=str(tmp_path))
        probe._load_watchlist(force=True)
        assert probe._watch_entries == [] and probe._pending_symbols == {}


def test_watchlist_is_rechecked_on_an_interval_and_reloaded_only_when_it_changes(tmp_path, monkeypatch):
    path = _write_watchlist(tmp_path / "w.json", ["a.first"])
    probe = Probe(watchlist_path=str(path), transport=RecordingTransport(), app_root=str(tmp_path))
    clock = [1000.0]
    monkeypatch.setattr(probe_mod.time, "monotonic", lambda: clock[0])
    probe._load_watchlist(force=True)
    assert set(probe._pending_symbols) == {"a.first"}

    _write_watchlist(path, ["a.second"], fingerprint="fp-2")
    os.utime(path, (time.time() + 5, time.time() + 5))
    probe._load_watchlist()  # inside WATCHLIST_RECHECK_SECONDS: not even stat'ed
    assert "a.second" not in probe._pending_symbols

    clock[0] += probe_mod.WATCHLIST_RECHECK_SECONDS + 1
    probe._load_watchlist()
    assert probe._pending_symbols["a.second"] == ["fp-2"]

    probe._pending_symbols.clear()
    clock[0] += probe_mod.WATCHLIST_RECHECK_SECONDS + 1
    probe._load_watchlist()  # same mtime: not re-read
    assert probe._pending_symbols == {}


# ---------- symbol resolution ----------


def test_resolve_finds_functions_methods_and_unwraps_decorators(modules):
    vuln, _ = modules()
    mod = importlib.import_module(vuln)
    assert _resolve(f"{vuln}.parse") is mod.parse.__code__
    assert _resolve(f"{vuln}.Codec.encode") is mod.Codec.encode.__code__
    assert _resolve(f"{vuln}.Codec.static") is mod.Codec.static.__code__
    assert _resolve(f"{vuln}.Codec.build") is mod.Codec.build.__func__.__code__
    # functools.wraps: the watched code is the original function, not the wrapper.
    assert _resolve(f"{vuln}.decorated") is mod.decorated.__wrapped__.__code__


def test_resolve_returns_none_for_what_it_cannot_find(modules):
    vuln, _ = modules()
    importlib.import_module(vuln)
    assert _resolve("not_imported_module_xyz.func") is None
    assert _resolve(f"{vuln}.missing") is None
    assert _resolve(f"{vuln}.Codec.missing") is None
    assert _resolve("single") is None


# ---------- flushing and backpressure ----------


def test_flush_sends_the_running_totals_and_counts_drops(make_probe):
    transport = RecordingTransport(result=False)
    probe = make_probe(transport=transport)
    probe.flush()
    probe.flush()
    assert len(transport.batches) == 2 and probe.dropped == 2
    assert _session(transport.batches[0])["id"] == probe.session_id
    transport.result = True
    probe.flush()
    assert probe.dropped == 2


def test_a_transport_that_raises_disables_the_probe_once(make_probe, capsys):
    transport = RecordingTransport(error=RuntimeError("boom"))
    probe = make_probe(transport=transport)
    probe.flush()
    probe.flush()  # broken: no second attempt
    assert probe._broken and transport.calls == ["send"]
    assert capsys.readouterr().err.count("disabled after an internal error (RuntimeError)") == 1


def test_flushes_from_two_threads_never_overlap_on_the_transport(make_probe):
    """Regression: stop()'s final flush raced the flusher thread on one
    socket; the loser's sendall failed and the final session line was lost
    (the reference probe's conformance run flaked with 'no session line')."""
    inside = threading.Event()
    overlaps = []

    class SlowTransport(RecordingTransport):
        def send(self, events):
            if inside.is_set():
                overlaps.append(True)
            inside.set()
            time.sleep(0.005)
            inside.clear()
            return super().send(events)

    transport = SlowTransport()
    probe = make_probe(transport=transport)
    threads = [threading.Thread(target=lambda: [probe.flush() for _ in range(10)]) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert overlaps == [] and len(transport.batches) == 40 and not probe._broken


def test_flush_interval_follows_welcome_and_doubles_while_slow(make_probe):
    transport = RecordingTransport()
    probe = make_probe(transport=transport, flush_seconds=4.0)
    assert probe._interval() == 4.0
    transport.flush_interval = 0.5  # what a welcome sets
    assert probe._interval() == 0.5
    transport.slow = True
    assert probe._interval() == 1.0


def test_the_flusher_thread_flushes_periodically_and_stops(make_probe):
    transport = RecordingTransport()
    probe = make_probe(transport=transport, flush_seconds=0.02)
    probe.start()
    deadline = time.monotonic() + 10
    while len(transport.batches) < 3 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(transport.batches) >= 3
    assert probe._thread is not None and probe._thread.daemon
    probe.stop()
    probe._thread.join(5)
    assert not probe._thread.is_alive()


# ---------- through the #73 conformance kit's fake sensor ----------


@pytest.mark.parametrize("backend", BACKENDS)
def test_every_line_sent_to_a_sensor_is_a_valid_protocol_message(modules, make_probe, backend):
    vuln, app = modules()
    app_mod = importlib.import_module(app)
    fake = FakeSensor()
    try:
        transport = transport_mod.SocketTransport(fake.address)
        probe = make_probe([f"{vuln}.parse"], backend=backend, transport=transport)
        probe.start()
        app_mod.handle(f"token={SENTINEL}")
        deadline = time.monotonic() + 10
        while transport.flush_interval is None and time.monotonic() < deadline:
            probe.flush()  # the welcome is read on the flush after it arrives
            time.sleep(0.02)
        assert transport.flush_interval == 0.1  # the sensor's welcome now drives flushing
        assert probe._interval() == 0.1
        probe.stop()
        deadline = time.monotonic() + 10
        while not any('"type":"hit"' in line for line in fake.lines) and time.monotonic() < deadline:
            time.sleep(0.02)
        lines = list(fake.lines)
    finally:
        fake.close()
    assert json.loads(lines[0])["type"] == "hello"
    for line in lines:
        validate_message(json.loads(line))
    assert forbidden_data(lines) == []
    assert any(json.loads(line).get("symbol") == f"{vuln}.parse" for line in lines)


def test_a_dead_sensor_drops_batches_without_disabling_the_probe(make_probe):
    fake = FakeSensor(kill_after_first_batch=True)
    transport = transport_mod.SocketTransport(fake.address)
    probe = make_probe(transport=transport)
    probe.flush()  # hello + first batch; the sensor then dies
    deadline = time.monotonic() + 10
    while probe.dropped == 0 and time.monotonic() < deadline:
        probe.flush()
        time.sleep(0.02)
    fake.close()
    transport.close()
    assert probe.dropped >= 1 and not probe._broken


def test_the_probe_reconnects_when_the_sensor_comes_back(make_probe):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()  # nothing listening yet: the sensor is down
    transport = transport_mod.SocketTransport(f"tcp://127.0.0.1:{port}")
    probe = make_probe(transport=transport)
    probe.flush()
    assert probe.dropped == 1 and not probe._broken

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("127.0.0.1", port))
    except OSError:
        pytest.skip("the ephemeral port was taken in between")
    server.listen(1)
    server.settimeout(10)
    try:
        probe.flush()  # sensor back: reconnects and says hello again
        conn, _ = server.accept()
        conn.settimeout(10)
        data = b""
        while data.count(b"\n") < 2:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
        conn.close()
    finally:
        server.close()
        transport.close()
    first, second = (json.loads(line) for line in data.splitlines()[:2])
    assert first["type"] == "hello" and second["type"] == "session"
    assert probe.dropped == 1


def test_closing_with_an_unread_welcome_still_delivers_the_final_batch(make_probe):
    """Regression: closing a socket with unread inbound data (the sensor's
    welcome) sends RST, and the sensor drops lines it hadn't read yet -- the
    exit flush's session line. The conformance kit flaked on exactly this."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(10)
    received: list[bytes] = []
    errors: list[BaseException] = []

    def slow_sensor():
        conn, _ = server.accept()
        try:
            conn.sendall(b'{"type":"welcome","protocol":1,"flush_interval":0.1}\n')  # never read by the probe
            time.sleep(0.3)  # the probe flushes and closes before the sensor reads anything
            conn.settimeout(10)
            data = b""
            while chunk := conn.recv(65536):
                data += chunk
            received.append(data)
        except OSError as exc:
            errors.append(exc)
        finally:
            conn.close()

    thread = threading.Thread(target=slow_sensor, daemon=True)
    thread.start()
    transport = transport_mod.SocketTransport(f"tcp://127.0.0.1:{server.getsockname()[1]}")
    transport._read_control = lambda: None  # the exit flush never gets to read the welcome
    probe = make_probe(transport=transport)
    probe._active = True  # as at exit: stop() does the final flush, then closes
    probe.stop()
    thread.join(10)
    server.close()
    assert errors == []
    types = [json.loads(line)["type"] for line in received[0].splitlines()]
    assert types[0] == "hello" and "session" in types


# ---------- shutdown ordering ----------


@pytest.mark.parametrize("backend", BACKENDS)
def test_stop_flushes_once_then_closes_and_uninstalls_every_hook(modules, make_probe, backend):
    vuln, app = modules()
    app_mod = importlib.import_module(app)
    transport = RecordingTransport()
    probe = make_probe([f"{vuln}.parse"], backend=backend, transport=transport)
    probe.start()
    tool_id = probe._tool_id
    app_mod.handle("a")
    probe.stop()
    probe.stop()  # idempotent

    assert transport.calls == ["send", "close"]  # final flush strictly before close
    assert [h["count"] for h in _hits(transport.batches[-1])] == [1]
    assert not any(isinstance(f, _ImportWatcher) and f.probe is probe for f in sys.meta_path)
    if backend == "monitoring":
        assert probe._tool_id is None and sys.monitoring.get_tool(tool_id) is None
    else:
        assert sys.getprofile() is None
    app_mod.handle("b")  # after stop nothing is recorded
    assert [h["count"] for h in _hits(probe.snapshot())] == [1]


@pytest.mark.parametrize("backend", BACKENDS)
def test_a_disabled_probe_still_releases_its_hooks_on_stop(modules, make_probe, backend, monkeypatch, capsys):
    """Regression: stop() used to return early once _disable() had cleared
    _active, leaking the sys.monitoring tool id (only four exist), the
    import watcher and the transport."""
    vuln, app = modules()
    app_mod = importlib.import_module(app)
    transport = RecordingTransport()
    probe = make_probe([f"{vuln}.parse"], backend=backend, transport=transport)
    probe.start()
    tool_id = probe._tool_id

    def boom(*_a, **_k):
        raise RuntimeError("probe bug")

    monkeypatch.setattr(probe, "_record_hit", boom)
    assert app_mod.handle("abc") == "ABC"  # fail-open: the app still works
    assert probe._broken and "disabled after an internal error" in capsys.readouterr().err

    probe.stop()
    assert transport.calls == ["close"]  # no flush from a broken probe, but the transport is closed
    assert not any(isinstance(f, _ImportWatcher) and f.probe is probe for f in sys.meta_path)
    if backend == "monitoring":
        assert sys.monitoring.get_tool(tool_id) is None


def test_stopping_a_probe_that_never_started_touches_nothing(make_probe):
    sentinel_profiler = lambda *_a: None
    sys.setprofile(sentinel_profiler)
    try:
        transport = RecordingTransport()
        make_probe(transport=transport).stop()
        assert transport.calls == [] and sys.getprofile() is sentinel_profiler
    finally:
        sys.setprofile(None)


@pytest.mark.skipif(not hasattr(sys, "monitoring"), reason="sys.monitoring is 3.12+")
def test_no_free_monitoring_tool_id_fails_open(make_probe, monkeypatch, capsys):
    monkeypatch.setattr(sys.monitoring, "get_tool", lambda _tool_id: "someone-else")
    probe = make_probe(backend="monitoring")
    probe.start()  # never raises into the app
    assert probe._broken and not probe._active and probe._tool_id is None
    assert "disabled after an internal error (RuntimeError)" in capsys.readouterr().err


# ---------- forked workers ----------


def test_a_forked_child_starts_its_own_session(make_probe):
    transport = RecordingTransport()
    probe = make_probe(transport=transport)
    probe._hits[("fp", "sym")] = [5, 0.0, 0.0, [], None]
    parent_session = probe.session_id
    probe._after_fork()
    try:
        assert probe.session_id != parent_session and probe._hits == {} and probe.dropped == 0
        assert transport.reopened == 1 and probe._thread is not None and probe._thread.is_alive()
    finally:
        probe._stop.set()


def test_a_fork_whose_transport_cannot_reopen_disables_the_probe(make_probe, capsys):
    transport = RecordingTransport()
    transport.reopen = lambda: (_ for _ in ()).throw(OSError("no socket"))
    probe = make_probe(transport=transport)
    probe._after_fork()
    assert probe._broken and "OSError" in capsys.readouterr().err


# ---------- coverage denominator and loaded packages ----------


def test_count_app_functions_counts_nested_code_and_caches_by_mtime(tmp_path, monkeypatch):
    app = tmp_path / "counted.py"
    app.write_text("def a():\n    def inner():\n        pass\n\nclass K:\n    def m(self):\n        pass\n",
                   encoding="utf-8")
    (tmp_path / "broken.py").write_text("def (:\n", encoding="utf-8")
    probe = Probe(watchlist_path=None, transport=RecordingTransport(), app_root=str(tmp_path))
    probe._seen_app_code = {compile("pass", str(app), "exec"), compile("pass", str(tmp_path / "broken.py"), "exec")}
    monkeypatch.setattr(sys, "argv", [str(tmp_path / "gone.py")])  # main script no longer on disk
    # a(), inner(), class body K, m()
    assert _count_app_functions(probe) == 4
    key = os.path.normcase(os.path.abspath(app))
    assert probe_mod._FUNCTION_COUNTS[key][1] == 4

    monkeypatch.setattr(probe_mod, "compile", lambda *_a, **_k: pytest.fail("recompiled"), raising=False)
    assert _count_app_functions(probe) == 4  # cached: same mtime, not compiled again


def test_loads_report_imported_distributions_and_skip_broken_metadata(make_probe, monkeypatch):
    from importlib.metadata import version

    probe = make_probe()
    loads = {e["package"].lower(): e for e in probe._loads()}
    assert loads["pytest"]["version"] == version("pytest")
    assert loads["pytest"]["session"] == probe.session_id and loads["pytest"]["ecosystem"] == "PyPI"

    monkeypatch.setattr(probe_mod, "_DISTRIBUTIONS", {"json": ["no-such-distribution-xyz"], "zz_not_imported": ["x"]})
    monkeypatch.setattr(probe_mod, "_VERSIONS", {})
    assert probe._loads() == []


# ---------- the import watcher ----------


def test_import_watcher_ignores_imports_it_is_not_waiting_for(make_probe):
    probe = make_probe()
    watcher = _ImportWatcher(probe)
    assert watcher.find_spec("json") is None  # nothing pending at all
    probe._pending_symbols["wanted_mod.fn"] = ["fp"]
    assert watcher.find_spec("json") is None  # unrelated module
    assert watcher.find_spec("wanted_mod") is None  # wanted, but not importable
    watcher._busy.on = True
    assert watcher.find_spec("wanted_mod") is None  # re-entrant lookup short-circuits


def test_import_watcher_disables_the_probe_if_resolving_fails(modules, make_probe, monkeypatch, capsys):
    vuln, _ = modules()
    probe = make_probe([f"{vuln}.parse"])
    probe._load_watchlist(force=True)
    spec = _ImportWatcher(probe).find_spec(vuln)
    assert spec is not None
    monkeypatch.setattr(probe, "_resolve_pending", lambda: (_ for _ in ()).throw(RuntimeError("bad")))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # the module still loads
    assert module.parse("a") == "A" and probe._broken
    assert "RuntimeError" in capsys.readouterr().err


# ---------- `secfoo.sensor` entry points ----------


@pytest.fixture
def fresh_package(monkeypatch):
    monkeypatch.setattr(sensor_pkg, "_probe", None)
    for name in ("SECFOO_SENSOR", "SECFOO_WATCHLIST", "SECFOO_EVENTS_OUT", "SECFOO_SENSOR_ADDR",
                 "SECFOO_FLUSH_INTERVAL", "SECFOO_APP_ROOT", "SECFOO_SENSOR_BACKEND"):
        monkeypatch.delenv(name, raising=False)
    yield
    probe = sensor_pkg._probe
    if probe is not None:
        probe.stop()
        atexit.unregister(probe.stop)
    sys.setprofile(None)
    threading.setprofile(None)  # type: ignore[arg-type]


@pytest.mark.parametrize(("value", "expected"), [("1", True), (" 1 ", True), ("0", False), ("true", False), ("", False)])
def test_enabled_only_for_exactly_one(value, expected):
    assert sensor_pkg.enabled({"SECFOO_SENSOR": value}) is expected
    assert sensor_pkg.enabled({}) is False


def test_start_from_env_configures_the_probe_from_secfoo_variables(fresh_package, tmp_path, monkeypatch):
    out = tmp_path / "events.ndjson"
    _write_watchlist(tmp_path / "w.json", ["x.y"])
    monkeypatch.setenv("SECFOO_SENSOR", "1")
    monkeypatch.setenv("SECFOO_WATCHLIST", str(tmp_path / "w.json"))
    monkeypatch.setenv("SECFOO_EVENTS_OUT", str(out))
    monkeypatch.setenv("SECFOO_APP_ROOT", str(tmp_path))
    monkeypatch.setenv("SECFOO_FLUSH_INTERVAL", "0.001")
    monkeypatch.setenv("SECFOO_SENSOR_BACKEND", "profile")

    probe = sensor_pkg.start_from_env()
    assert probe is not None and sensor_pkg.current_probe() is probe
    assert sensor_pkg.start_from_env() is probe  # started once per process
    assert probe.flush_seconds == 0.05  # clamped: a tiny interval can't spin the flusher
    assert probe.backend == "profile" and probe.app_root == os.path.normcase(os.path.abspath(tmp_path))
    assert isinstance(probe.transport, transport_mod.FileTransport)
    assert probe._pending_symbols == {"x.y": ["fp-1"]}
    probe.stop()
    events = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert any(e["type"] == "session" and e["id"] == probe.session_id for e in events)  # the final flush landed


@pytest.mark.parametrize(("name", "value", "reason"), [
    ("SECFOO_FLUSH_INTERVAL", "soon", "could not convert"),
    ("SECFOO_SENSOR_ADDR", "ftp://x", "unsupported SECFOO_SENSOR_ADDR"),
    ("SECFOO_SENSOR_ADDR", "tcp://10.0.0.5:7461", "loopback"),
])
def test_bad_configuration_never_stops_the_app(fresh_package, monkeypatch, capsys, name, value, reason):
    monkeypatch.setenv("SECFOO_SENSOR", "1")
    monkeypatch.setenv(name, value)
    assert sensor_pkg.start_from_env() is None and sensor_pkg.current_probe() is None
    err = capsys.readouterr().err
    assert err.startswith("secfoo sensor: not started") and reason in err


def test_python_dash_m_secfoo_sensor_without_arguments_prints_usage(capsys):
    with pytest.raises(SystemExit) as exc:
        sensor_main.main([])
    assert exc.value.code == 2 and "usage: python -m secfoo.sensor" in capsys.readouterr().err


def test_python_dash_m_secfoo_sensor_runs_a_script_like_python_would(fresh_package, tmp_path, monkeypatch, capsys):
    script = tmp_path / "script.py"
    script.write_text("import sys\nprint('ran', __name__, sys.argv[1:])\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["ignored"])
    sensor_main.main([str(script), "--flag"])
    assert capsys.readouterr().out.strip() == "ran __main__ ['--flag']"
    assert sensor_pkg.current_probe() is None  # SECFOO_SENSOR unset: inert


def test_python_dash_m_secfoo_sensor_runs_a_module(fresh_package, tmp_path, monkeypatch, capsys):
    name = f"mod_{uuid.uuid4().hex[:8]}"
    (tmp_path / f"{name}.py").write_text("import sys\nprint('module', __name__, sys.argv[1:])\n", encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))
    importlib.invalidate_caches()
    monkeypatch.setattr(sys, "argv", ["ignored"])
    try:
        sensor_main.main(["-m", name, "a", "b"])
    finally:
        sys.modules.pop(name, None)
    assert capsys.readouterr().out.strip() == "module __main__ ['a', 'b']"


def test_the_package_runs_as_a_module(fresh_package, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["secfoo.sensor"])
    monkeypatch.delitem(sys.modules, "secfoo.sensor.__main__")  # run it fresh, as `python -m` does
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("secfoo.sensor", run_name="__main__", alter_sys=False)
    assert exc.value.code == 2
