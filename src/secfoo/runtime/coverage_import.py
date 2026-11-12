"""Import coverage files as runtime evidence (#54).

Many projects already produce coverage from their test suites or staging
runs. This turns it into #53 events, with no sensor:

    secfoo runtime import-coverage coverage.json --watchlist watchlist.json -o events.ndjson
    secfoo runtime import-coverage ./v8-coverage/ --watchlist watchlist.json -o events.ndjson

- **Python:** a coverage.py JSON report (`coverage json`, coverage >= 7.5,
  which records per-function executed lines). Dependencies must have been
  measured (`--source` / `[run] include`), since site-packages are omitted
  by default.
- **Node:** a V8 coverage directory (`NODE_V8_COVERAGE=dir node app.js`) or
  one of its files. Function-level ranges already include node_modules.

A watched symbol is a hit when its function ran. Coverage has no stack
traces or routes, so `entry_frame`/`stack_sample` stay empty and `route` is
"unknown" (shown as Executed). The session id is derived from the file
contents, so importing the same coverage twice never double-counts.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

_DEP_DIRS = ("site-packages", "dist-packages")


class CoverageImportError(ValueError):
    pass


@dataclass
class _Coverage:
    language: str
    started_at: str
    digest: str
    # symbol-candidate -> call count (0 = present but never ran)
    functions: dict[str, int] = field(default_factory=dict)
    app_total: int = 0
    app_executed: int = 0
    dependency_files: int = 0


def _iso(ts) -> str:
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, timezone.utc).isoformat()
    if isinstance(ts, str) and ts:
        try:
            parsed = datetime.fromisoformat(ts)
        except ValueError:
            parsed = None
        if parsed is not None:
            return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).isoformat()
    return datetime.now(timezone.utc).isoformat()


# ---------- Python: coverage.py JSON ----------


def _python_module(path: str) -> str | None:
    """'.../site-packages/yaml/constructor.py' -> 'yaml.constructor'."""
    parts = PurePosixPath(path.replace("\\", "/")).parts
    for marker in _DEP_DIRS:
        if marker in parts:
            rel = list(parts[parts.index(marker) + 1:])
            break
    else:
        return None
    if not rel or not rel[-1].endswith(".py"):
        return None
    rel[-1] = rel[-1][:-3]
    if rel[-1] == "__init__":
        rel = rel[:-1]
    return ".".join(rel) or None


def _load_python(report: dict, digest: str) -> _Coverage:
    cov = _Coverage("python", _iso(report.get("meta", {}).get("timestamp")), digest)
    saw_functions = False
    for path, entry in (report.get("files") or {}).items():
        functions = entry.get("functions")
        if functions is None:
            continue
        saw_functions = True
        module = _python_module(path)
        for qualname, info in functions.items():
            if not qualname:  # module-level code
                continue
            ran = 1 if info.get("executed_lines") else 0
            if module is None:
                cov.app_total += 1
                cov.app_executed += ran
            else:
                cov.functions[f"{module}.{qualname}"] = ran
        if module is not None:
            cov.dependency_files += 1
    if not saw_functions:
        raise CoverageImportError(
            "this coverage.py JSON has no per-function data; regenerate it with coverage >= 7.5 (`coverage json`)"
        )
    if cov.dependency_files == 0:
        raise CoverageImportError(
            "the report contains no dependency files, so nothing can be matched to a vulnerable package. "
            "coverage.py omits site-packages by default: collect with the packages included, e.g. "
            "`coverage run --source=app,yaml,jinja2 ...` or `[run] include = */site-packages/yaml/*` "
            "in .coveragerc, then `coverage json` again"
        )
    return cov


# ---------- Node: V8 coverage ----------

_NODE_MODULES_RE = re.compile(r"node_modules/((?:@[^/]+/)?[^/]+)/")


def _node_package(url: str) -> str | None:
    path = unquote(urlsplit(url).path) if url.startswith("file:") else url
    matches = _NODE_MODULES_RE.findall(path.replace("\\", "/"))
    return matches[-1] if matches else None  # innermost node_modules: nested copies are their own package


def _load_v8(documents: list[dict], digest: str) -> _Coverage:
    timestamps = [d.get("timestamp") for d in documents if d.get("timestamp")]
    cov = _Coverage("node", _iso(min(timestamps) if timestamps else None), digest)
    for document in documents:
        for script in document.get("result") or []:
            url = script.get("url") or ""
            if not url.startswith(("file:", "/")) and ":\\" not in url:
                continue  # node:internal, eval, ...
            package = _node_package(url)
            for function in script.get("functions") or []:
                name = function.get("functionName") or ""
                ranges = function.get("ranges") or []
                count = int(ranges[0].get("count", 0)) if ranges else 0
                if not name:
                    continue
                if package is None:
                    cov.app_total += 1
                    cov.app_executed += 1 if count else 0
                else:
                    key = f"{package}#{name}"
                    cov.functions[key] = max(cov.functions.get(key, 0), count)
            if package is not None:
                cov.dependency_files += 1
    return cov


def _npm_candidates(symbol: str) -> list[str]:
    """'lodash#template' -> ['lodash#template']; 'pkg#a.b' also matches 'pkg#b'
    (V8 records the function's own name, not its export path)."""
    package, _, export = symbol.partition("#")
    return [symbol] + ([f"{package}#{export.rsplit('.', 1)[-1]}"] if "." in export else [])


# ---------- shared ----------


def load_coverage(path: Path) -> _Coverage:
    if path.is_dir():
        files = sorted(path.glob("coverage-*.json")) or sorted(path.glob("*.json"))
        if not files:
            raise CoverageImportError(f"{path}: no V8 coverage files (coverage-*.json) in this folder")
        raw = b"".join(f.read_bytes() for f in files)
        return _load_v8([json.loads(f.read_text(encoding="utf-8")) for f in files], hashlib.sha256(raw).hexdigest())
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CoverageImportError(f"{path}: not JSON ({exc.msg})") from None
    digest = hashlib.sha256(raw).hexdigest()
    if isinstance(document, dict) and "files" in document and "meta" in document:
        return _load_python(document, digest)
    if isinstance(document, dict) and "result" in document:
        return _load_v8([document], digest)
    raise CoverageImportError(f"{path}: not a coverage.py JSON report or a V8 coverage file")


def to_events(cov: _Coverage, watchlist: dict) -> tuple[list[dict], list[str]]:
    """#53 lines for the watched symbols this coverage covers, plus notes."""
    session_id = "coverage-" + cov.digest[:32]
    session = {"type": "session", "id": session_id, "language": cov.language, "source": "coverage",
               "started_at": cov.started_at}
    if cov.app_total:
        session["app_functions_total"] = cov.app_total
        session["app_functions_executed"] = cov.app_executed
    events: list[dict] = [session]
    notes: list[str] = []
    ecosystem = {"python": "PyPI", "node": "npm"}[cov.language]
    entries = [e for e in watchlist.get("entries", []) if e.get("ecosystem") == ecosystem]
    if not entries:
        notes.append(f"the watchlist has no {ecosystem} entries, so nothing in this coverage can match")
    unmatched = 0
    for entry in entries:
        for symbol in entry.get("symbols") or []:
            candidates = _npm_candidates(symbol) if cov.language == "node" else [symbol]
            count = max((cov.functions.get(c, -1) for c in candidates), default=-1)
            if count < 0:
                unmatched += 1  # the function isn't in the report: its package wasn't measured
            elif count > 0:
                events.append({"type": "hit", "session": session_id,
                               "finding_fingerprint": entry["finding_fingerprint"], "symbol": symbol,
                               "route": "unknown", "count": count, "first_seen": cov.started_at,
                               "last_seen": cov.started_at})
    if unmatched:
        notes.append(f"{unmatched} watched symbol(s) weren't in the coverage report (their package wasn't measured)")
    return events, notes
