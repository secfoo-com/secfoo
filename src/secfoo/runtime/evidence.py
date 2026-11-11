"""Runtime evidence events (#53): validate NDJSON lines and store them.

This is the one contract that every producer writes -- the Python and Node
probes (#55, #56), the coverage importer (#54) and the live sensor via the
ingest API (#66/#67). The file format and the live API share it, so both
call `ingest_events()`.

An event file is NDJSON. Each line is one object with a `type`:

    {"type":"session","id":"<uuid>","language":"python","source":"sensor","started_at":"..."}
    {"type":"load","session":"<uuid>","ecosystem":"PyPI","package":"pyyaml","version":"5.3"}
    {"type":"hit","session":"<uuid>","finding_fingerprint":"...","symbol":"yaml.load","count":312}

The full field list is in docs/REFERENCE.md ("Runtime evidence") and in
evidence.schema.json next to this module.

Ingest rules:

- A malformed line is skipped and reported with its line number. It never
  aborts the rest of the file.
- A `hit` whose `finding_fingerprint` isn't an SCA finding of the project is
  skipped with a warning (it can't attach to anything).
- Idempotent: a session is keyed by its own `id`, and a hit by (session,
  fingerprint, symbol, route). A hit's `count` is that session's running
  total for the key, so a re-ingest -- or a later flush of the same session
  -- replaces the row instead of adding to it.
- Privacy (#51 rule 3): only the fields below are stored. Unknown fields
  are ignored, never persisted. Routes that look like concrete URLs (a
  scheme or query string) and stack frames that aren't `file:line` are
  rejected.
"""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

LANGUAGES = frozenset({"python", "node", "jvm", "dotnet", "go", "rust", "ruby", "php", "native"})
SOURCES = frozenset({"sensor", "coverage"})
AUTH_STATES = frozenset({"anonymous", "authenticated"})

MAX_LINE_BYTES = 64 * 1024
MAX_TEXT = 1024
MAX_STACK_FRAMES = 50

_FRAME_RE = re.compile(rf"^\S.{{0,{MAX_TEXT - 8}}}:\d+$")
_CONCRETE_URL_RE = re.compile(r"://|[?#]")


class EvidenceError(ValueError):
    """One line failed validation. The message says which field and why."""


@dataclass
class IngestReport:
    sessions: int = 0
    loads: int = 0
    hits: int = 0
    skipped: list[tuple[int, str]] = field(default_factory=list)  # (line number, reason)
    unknown_fingerprints: set[str] = field(default_factory=set)

    @property
    def stored(self) -> int:
        return self.sessions + self.loads + self.hits


# ---------- validation ----------


def _text(event: dict, key: str, *, required: bool = False) -> str | None:
    value = event.get(key)
    if value is None:
        if required:
            raise EvidenceError(f"missing required field {key!r}")
        return None
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{key!r} must be a non-empty string")
    if len(value) > MAX_TEXT:
        raise EvidenceError(f"{key!r} is longer than {MAX_TEXT} characters")
    return value


def _timestamp(event: dict, key: str, *, required: bool = False) -> str | None:
    value = _text(event, key, required=required)
    if value is None:
        return None
    try:
        # Python 3.10's fromisoformat doesn't accept a trailing "Z".
        datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        raise EvidenceError(f"{key!r} must be an ISO 8601 timestamp, got {value!r}") from None
    return value


def _count(event: dict, key: str, *, required: bool = False, minimum: int = 0) -> int | None:
    value = event.get(key)
    if value is None:
        if required:
            raise EvidenceError(f"missing required field {key!r}")
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise EvidenceError(f"{key!r} must be an integer >= {minimum}")
    return value


def _frame(value: object, key: str) -> str:
    if not isinstance(value, str) or not _FRAME_RE.match(value):
        raise EvidenceError(f"{key!r} frames must be 'file:line', never variables or arguments")
    return value


def validate_event(event: object) -> dict:
    """The stored fields of one event, or EvidenceError. Unknown fields are
    dropped here, so nothing outside the contract can reach the database."""
    if not isinstance(event, dict):
        raise EvidenceError("each line must be a JSON object")
    kind = event.get("type")
    if kind == "session":
        language = _text(event, "language", required=True)
        if language not in LANGUAGES:
            raise EvidenceError(f"'language' must be one of {', '.join(sorted(LANGUAGES))}")
        source = _text(event, "source", required=True)
        if source not in SOURCES:
            raise EvidenceError("'source' must be 'sensor' or 'coverage'")
        total = _count(event, "app_functions_total")
        executed = _count(event, "app_functions_executed")
        if total is not None and executed is not None and executed > total:
            raise EvidenceError("'app_functions_executed' can't exceed 'app_functions_total'")
        return {
            "type": "session",
            "id": _text(event, "id", required=True),
            "language": language,
            "runtime": _text(event, "runtime"),
            "source": source,
            "app": _text(event, "app"),
            "env": _text(event, "env"),
            "instance": _text(event, "instance"),
            "sensor_version": _text(event, "sensor_version"),
            "started_at": _timestamp(event, "started_at", required=True),
            "ended_at": _timestamp(event, "ended_at"),
            "app_functions_total": total,
            "app_functions_executed": executed,
        }
    if kind == "load":
        return {
            "type": "load",
            "session": _text(event, "session", required=True),
            "ecosystem": _text(event, "ecosystem", required=True),
            "package": _text(event, "package", required=True),
            "version": _text(event, "version", required=True),
            "path": _text(event, "path"),
            "first_seen": _timestamp(event, "first_seen"),
        }
    if kind == "hit":
        route = _text(event, "route")
        if route is not None and _CONCRETE_URL_RE.search(route):
            raise EvidenceError("'route' must be a template like 'POST /upload', not a concrete URL")
        auth = _text(event, "auth")
        if auth is not None and auth not in AUTH_STATES:
            raise EvidenceError("'auth' must be 'anonymous' or 'authenticated'")
        stack = event.get("stack_sample")
        if stack is not None:
            if not isinstance(stack, list) or len(stack) > MAX_STACK_FRAMES:
                raise EvidenceError(f"'stack_sample' must be a list of at most {MAX_STACK_FRAMES} frames")
            stack = [_frame(frame, "stack_sample") for frame in stack]
        entry = event.get("entry_frame")
        return {
            "type": "hit",
            "session": _text(event, "session", required=True),
            "finding_fingerprint": _text(event, "finding_fingerprint", required=True),
            "symbol": _text(event, "symbol", required=True),
            "route": route or "",
            "auth": auth,
            "count": _count(event, "count", required=True, minimum=1),
            "first_seen": _timestamp(event, "first_seen"),
            "last_seen": _timestamp(event, "last_seen"),
            "entry_frame": None if entry is None else _frame(entry, "entry_frame"),
            "stack_sample": stack,
        }
    raise EvidenceError("'type' must be 'session', 'load' or 'hit'")


def parse_lines(lines: Iterable[str]) -> Iterator[tuple[int, dict | None, str | None]]:
    """(line number, validated event or None, error or None) per non-blank line."""
    for number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        if len(raw.encode("utf-8", errors="replace")) > MAX_LINE_BYTES:
            yield number, None, f"line is longer than {MAX_LINE_BYTES} bytes"
            continue
        try:
            yield number, validate_event(json.loads(raw)), None
        except json.JSONDecodeError as exc:
            yield number, None, f"not valid JSON ({exc.msg})"
        except EvidenceError as exc:
            yield number, None, str(exc)


# ---------- storage ----------


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _session_id(conn: sqlite3.Connection, project_id: int, session_uuid: str) -> int | None:
    row = conn.execute(
        "SELECT id FROM runtime_sessions WHERE project_id = ? AND session_uuid = ?", (project_id, session_uuid)
    ).fetchone()
    return row[0] if row else None


def _store_session(conn: sqlite3.Connection, project_id: int, event: dict) -> int:
    conn.execute(
        """
        INSERT INTO runtime_sessions (
            project_id, session_uuid, language, runtime, source, app, env, instance, sensor_version,
            started_at, ended_at, app_functions_total, app_functions_executed, ingested_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (project_id, session_uuid) DO UPDATE SET
            language = excluded.language, runtime = excluded.runtime, source = excluded.source,
            app = excluded.app, env = excluded.env, instance = excluded.instance,
            sensor_version = excluded.sensor_version, started_at = excluded.started_at,
            ended_at = excluded.ended_at, app_functions_total = excluded.app_functions_total,
            app_functions_executed = excluded.app_functions_executed, ingested_at = excluded.ingested_at
        """,
        (
            project_id, event["id"], event["language"], event["runtime"], event["source"], event["app"],
            event["env"], event["instance"], event["sensor_version"], event["started_at"], event["ended_at"],
            event["app_functions_total"], event["app_functions_executed"], _now(),
        ),
    )
    session_id = _session_id(conn, project_id, event["id"])
    assert session_id is not None  # nosec B101 -- just upserted
    return session_id


def _store_load(conn: sqlite3.Connection, project_id: int, session_id: int, event: dict) -> None:
    conn.execute(
        """
        INSERT INTO runtime_packages (project_id, session_id, ecosystem, package, version, path, first_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (session_id, ecosystem, package, version) DO UPDATE SET
            path = excluded.path,
            first_seen = COALESCE(MIN(runtime_packages.first_seen, excluded.first_seen),
                                  runtime_packages.first_seen, excluded.first_seen)
        """,
        (project_id, session_id, event["ecosystem"], event["package"], event["version"], event["path"],
         event["first_seen"]),
    )


def _store_hit(conn: sqlite3.Connection, project_id: int, session_id: int, event: dict) -> None:
    conn.execute(
        """
        INSERT INTO runtime_evidence (
            project_id, session_id, finding_fingerprint, symbol, route, auth, count,
            first_seen, last_seen, entry_frame, stack_sample
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (session_id, finding_fingerprint, symbol, route) DO UPDATE SET
            count = excluded.count,
            auth = COALESCE(excluded.auth, runtime_evidence.auth),
            first_seen = COALESCE(MIN(runtime_evidence.first_seen, excluded.first_seen),
                                  runtime_evidence.first_seen, excluded.first_seen),
            last_seen = COALESCE(MAX(runtime_evidence.last_seen, excluded.last_seen),
                                 runtime_evidence.last_seen, excluded.last_seen),
            entry_frame = COALESCE(excluded.entry_frame, runtime_evidence.entry_frame),
            stack_sample = COALESCE(excluded.stack_sample, runtime_evidence.stack_sample)
        """,
        (
            project_id, session_id, event["finding_fingerprint"], event["symbol"], event["route"], event["auth"],
            event["count"], event["first_seen"], event["last_seen"], event["entry_frame"],
            None if event["stack_sample"] is None else json.dumps(event["stack_sample"]),
        ),
    )


def ingest_events(conn: sqlite3.Connection, project_id: int, lines: Iterable[str]) -> IngestReport:
    """Validate and store every line, in one transaction. Bad lines are
    skipped and listed in the report; they never stop the others."""
    report = IngestReport()
    sessions: dict[str, int] = {}
    known_fingerprints: dict[str, bool] = {}

    def session_for(uuid: str) -> int | None:
        if uuid not in sessions:
            found = _session_id(conn, project_id, uuid)  # from an earlier ingest
            if found is None:
                return None
            sessions[uuid] = found
        return sessions[uuid]

    def is_finding(fingerprint: str) -> bool:
        if fingerprint not in known_fingerprints:
            known_fingerprints[fingerprint] = conn.execute(
                "SELECT 1 FROM sca_findings WHERE project_id = ? AND fingerprint = ?", (project_id, fingerprint)
            ).fetchone() is not None
        return known_fingerprints[fingerprint]

    try:
        for number, event, error in parse_lines(lines):
            if event is None:
                report.skipped.append((number, error or "invalid line"))
                continue
            if event["type"] == "session":
                sessions[event["id"]] = _store_session(conn, project_id, event)
                report.sessions += 1
                continue
            session_id = session_for(event["session"])
            if session_id is None:
                report.skipped.append((number, f"unknown session {event['session']!r} (no session line for it)"))
                continue
            if event["type"] == "load":
                _store_load(conn, project_id, session_id, event)
                report.loads += 1
            elif is_finding(event["finding_fingerprint"]):
                _store_hit(conn, project_id, session_id, event)
                report.hits += 1
            else:
                report.unknown_fingerprints.add(event["finding_fingerprint"])
                report.skipped.append(
                    (number, f"finding_fingerprint {event['finding_fingerprint']!r} is not an SCA finding of this project")
                )
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return report


def ingest_file(conn: sqlite3.Connection, project_id: int, path: Path) -> IngestReport:
    with path.open(encoding="utf-8", errors="replace") as handle:
        return ingest_events(conn, project_id, handle)
