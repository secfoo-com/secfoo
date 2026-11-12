"""In-process Python probe (#55): records which watched vulnerable functions
run, which packages are loaded, and how much app code ran, as #53 events.

Design rules (#51), all enforced here:

- **Inert unless `SECFOO_SENSOR=1`.** `start()` returns without installing a
  hook, thread or connection otherwise.
- **Observe-only, fail-open.** Callbacks only count. Any internal error turns
  the probe off (one stderr line) and the app carries on.
- **No argument values.** Only code identity, counts, timestamps and
  `file:line` frames are recorded. `frame.f_locals`, arguments and return
  values are never read.
- **Never blocks the app.** Aggregation is in memory (bounded by the size of
  the watchlist and the app); a daemon thread flushes running totals, so a
  slow or missing transport only ever drops data.

Backends: `sys.monitoring` (PEP 669, Python 3.12+) with PY_START on the
watched code objects only, or `sys.setprofile` filtered to them on 3.10/3.11
(`SECFOO_SENSOR_BACKEND=profile` forces it, for tests and comparisons).
"""

from __future__ import annotations

import atexit
import importlib.abc
import json
import os
import sys
import sysconfig
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

PROBE_VERSION = "0.1.0"
DEFAULT_FLUSH_SECONDS = 10.0
WATCHLIST_RECHECK_SECONDS = 30.0
MAX_STACK_FRAMES = 10
_TOOL_NAME = "secfoo-sensor"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def _stdlib_and_site_dirs() -> tuple[str, ...]:
    paths = sysconfig.get_paths()
    dirs = {paths.get(k) for k in ("stdlib", "platstdlib", "purelib", "platlib")}
    dirs |= {p for p in sys.path if p and ("site-packages" in p or "dist-packages" in p)}
    return tuple(sorted(os.path.normcase(os.path.abspath(d)) for d in dirs if d))


class Probe:
    def __init__(self, *, watchlist_path: str | None, transport, app_root: str | None = None,
                 flush_seconds: float = DEFAULT_FLUSH_SECONDS, backend: str | None = None) -> None:
        self.watchlist_path = watchlist_path
        self.transport = transport
        self.flush_seconds = flush_seconds
        self.app_root = os.path.normcase(os.path.abspath(app_root or os.getcwd()))
        self.backend = backend or ("monitoring" if hasattr(sys, "monitoring") else "profile")
        self._excluded_dirs = _stdlib_and_site_dirs()
        self._lock = threading.Lock()
        self._active = False
        self._broken = False
        self._reset_session()
        self._watch_entries: list[dict] = []
        self._watchlist_mtime: float | None = None
        self._watchlist_checked = 0.0
        self._watched: dict = {}            # code object -> (symbol, [fingerprints])
        self._pending_symbols: dict = {}    # symbol -> [fingerprints], not resolved yet
        self._seen_app_code: set = set()
        self._app_code_cache: dict = {}  # code object -> is app code
        self._tool_id: int | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ---------- lifecycle ----------

    def _reset_session(self) -> None:
        self.session_id = str(uuid.uuid4())
        self.started_at = _now()
        self._hits: dict[tuple, dict] = {}   # (fingerprint, symbol) -> aggregate
        self._seen_app_code = set()
        self.dropped = 0

    def start(self) -> None:
        try:
            self._load_watchlist(force=True)
            if self.backend == "monitoring":
                self._start_monitoring()
            else:
                self._start_profile()
            sys.meta_path.insert(0, _ImportWatcher(self))
            self._active = True
            self._resolve_pending()
            self._start_flusher()
            atexit.register(self.stop)
            # multiprocessing workers leave through os._exit(), which skips
            # atexit; its own exit hook still runs, so flush there too.
            import multiprocessing.util

            multiprocessing.util.Finalize(None, self.stop, exitpriority=100)
            if hasattr(os, "register_at_fork"):
                os.register_at_fork(after_in_child=self._after_fork)
        except Exception as exc:  # noqa: BLE001 -- fail-open
            self._disable(exc)

    def stop(self) -> None:
        if not self._active:
            return
        self._stop.set()
        self.flush()
        self._active = False
        try:
            if self._tool_id is not None:
                sys.monitoring.register_callback(self._tool_id, sys.monitoring.events.PY_START, None)
                sys.monitoring.set_events(self._tool_id, 0)
                sys.monitoring.free_tool_id(self._tool_id)
                self._tool_id = None
            elif self.backend == "profile":
                sys.setprofile(None)
                threading.setprofile(None)  # type: ignore[arg-type]
            self.transport.close()
        except Exception:  # noqa: BLE001, S110 -- shutting down; never raise into the app
            pass

    def _after_fork(self) -> None:
        """A forked worker (gunicorn, multiprocessing) is its own session."""
        try:
            self._lock = threading.Lock()
            self._reset_session()
            self._stop = threading.Event()
            self.transport = self.transport.reopen()
            self._start_flusher()
        except Exception as exc:  # noqa: BLE001 -- fail-open
            self._disable(exc)

    def _disable(self, exc: BaseException) -> None:
        if self._broken:
            return
        self._broken = True
        self._active = False
        try:
            if self._tool_id is not None:
                sys.monitoring.set_events(self._tool_id, 0)
                for code in list(self._watched):
                    sys.monitoring.set_local_events(self._tool_id, code, 0)
            elif self.backend == "profile":
                sys.setprofile(None)
            print(f"secfoo sensor: disabled after an internal error ({exc.__class__.__name__}); "
                  "the app is unaffected", file=sys.stderr)
        except Exception:  # noqa: BLE001, S110 -- never raise into the app
            pass

    # ---------- watchlist ----------

    def _load_watchlist(self, *, force: bool = False) -> None:
        if not self.watchlist_path:
            return
        now = time.monotonic()
        if not force and now - self._watchlist_checked < WATCHLIST_RECHECK_SECONDS:
            return
        self._watchlist_checked = now
        try:
            mtime = os.path.getmtime(self.watchlist_path)
        except OSError:
            return
        if mtime == self._watchlist_mtime:
            return
        self._watchlist_mtime = mtime
        with open(self.watchlist_path, encoding="utf-8") as handle:
            document = json.load(handle)
        entries = [e for e in document.get("entries", []) if e.get("ecosystem") == "PyPI"]
        self._watch_entries = entries
        for entry in entries:
            for symbol in entry.get("symbols") or []:
                self._pending_symbols.setdefault(symbol, []).append(entry["finding_fingerprint"])

    def _resolve_pending(self) -> None:
        for symbol in list(self._pending_symbols):
            code = _resolve(symbol)
            if code is None:
                continue
            fingerprints = self._pending_symbols.pop(symbol)
            known = self._watched.get(code)
            self._watched[code] = (symbol, sorted(set(fingerprints + (known[1] if known else []))))
            if self._tool_id is not None:
                sys.monitoring.set_local_events(self._tool_id, code, sys.monitoring.events.PY_START)

    # ---------- backends ----------

    def _start_monitoring(self) -> None:
        mon = sys.monitoring
        for tool_id in range(mon.PROFILER_ID, 6):  # first free tool id; 0-1 are debugger/coverage
            if mon.get_tool(tool_id) is None:
                mon.use_tool_id(tool_id, _TOOL_NAME)
                self._tool_id = tool_id
                break
        else:
            raise RuntimeError("no free sys.monitoring tool id")
        mon.register_callback(self._tool_id, mon.events.PY_START, self._on_py_start)
        # Global PY_START for coverage of app code; each location is disabled
        # after its first event, so steady-state cost is ~zero.
        mon.set_events(self._tool_id, mon.events.PY_START)

    def _on_py_start(self, code, _offset):
        try:
            watched = self._watched.get(code)
            if watched is not None:
                self._record_hit(code, watched)
                if code not in self._seen_app_code and self._is_app_code_obj(code):
                    self._seen_app_code.add(code)
                return None  # keep counting watched functions
            if code.co_name != "<module>" and self._is_app_code_obj(code):
                self._seen_app_code.add(code)
            return sys.monitoring.DISABLE
        except Exception as exc:  # noqa: BLE001 -- never raise into the app
            self._disable(exc)
            return sys.monitoring.DISABLE

    def _start_profile(self) -> None:
        def profiler(frame, event, _arg):
            if event != "call":
                return
            try:
                code = frame.f_code
                watched = self._watched.get(code)
                if watched is not None:
                    self._record_hit(code, watched)
                if (code not in self._seen_app_code and code.co_name != "<module>"
                        and self._is_app_code_obj(code)):
                    self._seen_app_code.add(code)
            except Exception as exc:  # noqa: BLE001
                self._disable(exc)

        sys.setprofile(profiler)
        threading.setprofile(profiler)

    # ---------- recording ----------

    def _is_app_code_obj(self, code) -> bool:
        """_is_app_code for a code object, cached: path normalisation is far
        too slow for the per-call path."""
        known = self._app_code_cache.get(code)
        if known is None:
            known = self._app_code_cache[code] = self._is_app_code(code.co_filename)
        return known

    def _is_app_code(self, filename: str) -> bool:
        if not filename or filename.startswith("<"):
            return False
        path = os.path.normcase(os.path.abspath(filename))
        return path.startswith(self.app_root) and not path.startswith(self._excluded_dirs)

    def _record_hit(self, code, watched) -> None:
        """The hot path: one dict lookup and two stores per watched call.
        Timestamps stay raw floats until flush. No lock: under the GIL a
        lost increment between threads is possible but rare, and a running
        total that's off by one is an acceptable price for not serialising
        the app's threads on every call."""
        symbol, fingerprints = watched
        now = time.time()
        hits = self._hits
        for fingerprint in fingerprints:
            agg = hits.get((fingerprint, symbol))
            if agg is not None:
                agg[0] += 1
                agg[2] = now
                continue
            stack = self._stack_sample()
            # stack[0] is the watched function itself; the entry frame is the
            # app code that called it. [count, first_seen, last_seen, stack, entry]
            with self._lock:
                hits.setdefault((fingerprint, symbol), [1, now, now, stack, stack[1] if len(stack) > 1 else None])

    def _stack_sample(self) -> list[str]:
        """file:line of app frames only (plus nothing else): no locals, no args."""
        frames: list[str] = []
        frame = sys._getframe(3)
        while frame is not None and len(frames) < MAX_STACK_FRAMES:
            filename = frame.f_code.co_filename
            if self._is_app_code(filename):
                rel = os.path.relpath(filename, self.app_root).replace(os.sep, "/")
                frames.append(f"{rel}:{frame.f_lineno}")
            frame = frame.f_back
        return frames

    # ---------- output ----------

    def snapshot(self) -> list[dict]:
        """The session's running totals as #53 events."""
        with self._lock:
            hits = {k: list(v) for k, v in self._hits.items()}
            executed = len(self._seen_app_code)
        session = {
            "type": "session", "id": self.session_id, "language": "python",
            "runtime": ".".join(map(str, sys.version_info[:3])), "source": "sensor",
            "started_at": self.started_at, "ended_at": _now(), "sensor_version": PROBE_VERSION,
            "instance": os.environ.get("HOSTNAME") or os.environ.get("COMPUTERNAME") or None,
        }
        if self.backend == "monitoring":
            total = _count_app_functions(self)
            session["app_functions_total"] = max(total, executed)
            session["app_functions_executed"] = executed
        session = {k: v for k, v in session.items() if v is not None}
        events = [session, *self._loads()]
        for (fingerprint, symbol), (count, first, last, stack, entry) in sorted(hits.items()):
            hit = {"type": "hit", "session": self.session_id, "finding_fingerprint": fingerprint,
                   "symbol": symbol, "route": "unknown", "count": count, "first_seen": _iso(first),
                   "last_seen": _iso(last), "stack_sample": stack, "entry_frame": entry}
            events.append({k: v for k, v in hit.items() if v not in (None, [])})
        return events

    def _loads(self) -> list[dict]:
        """`load` lines for installed distributions with an imported top-level module."""
        try:
            from importlib.metadata import packages_distributions, version
        except ImportError:
            return []
        global _DISTRIBUTIONS
        if _DISTRIBUTIONS is None:
            # Installed packages don't change while the app runs: scan their
            # metadata once, not on every flush (it's the slowest part).
            _DISTRIBUTIONS = {top: list(dists) for top, dists in packages_distributions().items()}
        imported = {name.split(".")[0] for name in list(sys.modules)}
        seen: set[str] = set()
        loads = []
        for top, dists in _DISTRIBUTIONS.items():
            if top not in imported:
                continue
            for dist in dists:
                if dist.lower() in seen:
                    continue
                seen.add(dist.lower())
                try:
                    if dist not in _VERSIONS:
                        _VERSIONS[dist] = version(dist)
                    loads.append({"type": "load", "session": self.session_id, "ecosystem": "PyPI",
                                  "package": dist, "version": _VERSIONS[dist], "first_seen": self.started_at})
                except Exception:  # noqa: BLE001, S112 -- broken package metadata: skip it
                    continue
        return loads

    def flush(self) -> None:
        if self._broken:
            return
        try:
            self._load_watchlist()
            self._resolve_pending()
            if not self.transport.send(self.snapshot()):
                self.dropped += 1
        except Exception as exc:  # noqa: BLE001
            self._disable(exc)

    def _interval(self) -> float:
        """The sensor's `welcome` interval if it sent one, doubled while it
        says `slow` (#73 backpressure); otherwise SECFOO_FLUSH_INTERVAL."""
        interval = getattr(self.transport, "flush_interval", None) or self.flush_seconds
        return interval * 2 if getattr(self.transport, "slow", False) else interval

    def _start_flusher(self) -> None:
        def loop():
            while not self._stop.wait(self._interval()):
                self.flush()

        self._thread = threading.Thread(target=loop, name="secfoo-sensor-flush", daemon=True)
        self._thread.start()


def _resolve(symbol: str):
    """The code object for `module.qualname`, once the module is imported."""
    parts = symbol.split(".")
    for split in range(len(parts) - 1, 0, -1):
        module = sys.modules.get(".".join(parts[:split]))
        if module is None:
            continue
        obj = module
        try:
            for attr in parts[split:]:
                obj = getattr(obj, attr)
        except AttributeError:
            return None
        obj = getattr(obj, "__func__", obj)
        while hasattr(obj, "__wrapped__"):
            obj = obj.__wrapped__
        return getattr(obj, "__code__", None)
    return None


def _count_app_functions(probe: Probe) -> int:
    """Function code objects defined in loaded app modules (the coverage
    denominator). Walks co_consts, never module or frame state."""
    total = 0
    files = {getattr(module, "__file__", None) for module in list(sys.modules.values())}
    # __main__ may already be gone from sys.modules at exit; the files of app
    # code that ran, and the main script, still name it.
    files |= {code.co_filename for code in list(probe._seen_app_code)}
    if sys.argv and sys.argv[0]:
        files.add(os.path.abspath(sys.argv[0]))
    for filename in {os.path.normcase(os.path.abspath(f)) for f in files if f}:
        if not probe._is_app_code(filename):
            continue
        try:
            mtime = os.path.getmtime(filename)
        except OSError:
            continue
        cached = _FUNCTION_COUNTS.get(filename)
        if cached is not None and cached[0] == mtime:  # compile each file once, not every flush
            total += cached[1]
            continue
        try:
            source = Path(filename).read_text(encoding="utf-8")
            stack = [compile(source, filename, "exec")]
        except (OSError, SyntaxError, ValueError, UnicodeDecodeError):
            continue
        file_total = 0
        while stack:
            code = stack.pop()
            for const in code.co_consts:
                if hasattr(const, "co_code"):
                    file_total += 1
                    stack.append(const)
        _FUNCTION_COUNTS[filename] = (mtime, file_total)
        total += file_total
    return total


_FUNCTION_COUNTS: dict[str, tuple[float, int]] = {}  # app file -> (mtime, function count)
_DISTRIBUTIONS: dict[str, list[str]] | None = None   # top-level module -> distributions
_VERSIONS: dict[str, str] = {}


class _ImportWatcher(importlib.abc.MetaPathFinder):
    """Resolves watched symbols right after their module is imported. Never
    finds modules itself (find_spec returns None), so imports are unchanged."""

    def __init__(self, probe: Probe) -> None:
        self.probe = probe
        self._busy = threading.local()

    def find_spec(self, fullname, path=None, target=None):
        if getattr(self._busy, "on", False) or not self.probe._pending_symbols:
            return None
        if not any(s == fullname or s.startswith(fullname + ".") for s in self.probe._pending_symbols):
            return None
        self._busy.on = True
        try:
            # Submodules (pkg.mod) arrive with the package's __path__.
            spec = (importlib.util.find_spec(fullname) if path is None
                    else importlib.machinery.PathFinder.find_spec(fullname, path))
        except (ImportError, ValueError):
            spec = None
        finally:
            self._busy.on = False
        if spec is None or spec.loader is None or not hasattr(spec.loader, "exec_module"):
            return None
        original = spec.loader.exec_module
        probe = self.probe

        def exec_module(module):
            original(module)
            try:
                probe._resolve_pending()
            except Exception as exc:  # noqa: BLE001
                probe._disable(exc)

        spec.loader.exec_module = exec_module  # type: ignore[method-assign]
        return spec


import importlib.machinery
import importlib.util
