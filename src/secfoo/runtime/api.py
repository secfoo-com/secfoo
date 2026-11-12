"""Runtime ingest API on `secfoo serve` (#66).

The contract sensors (#67) and the CLI (#80) speak. All endpoints take
`Authorization: Bearer <api key>` -- the same key the CLI uses -- and a
`project` that must already exist (it was scanned with `secfoo run`):

    GET  /api/runtime/v1/watchlist?project=   the #52 watchlist, with an ETag
    POST /api/runtime/v1/events?project=      a (gzip) NDJSON batch in the #53 format
    POST /api/runtime/v1/heartbeat?project=   sensor id, version, app, env, instances, dropped
    GET  /api/runtime/v1/evidence?project=    runtime state per open SCA finding

Events go through `secfoo.runtime.evidence.ingest_events`, the same code as
`secfoo runtime ingest`, so a retried batch never double-counts. Keys and
event payloads are never logged.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import threading
import time
import zlib
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response

from secfoo.runtime import keys as keys_module
from secfoo.runtime.evidence import ingest_events
from secfoo.runtime.watchlist import build_watchlist
from secfoo.storage.repository import RunRepository

MAX_BODY_BYTES = 5 * 1024 * 1024            # compressed request body
MAX_DECOMPRESSED_BYTES = 20 * 1024 * 1024
MAX_BATCH_LINES = 50_000
RATE_LIMIT_REQUESTS = 120                   # per key, per window
RATE_LIMIT_WINDOW_SECONDS = 60
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

router = APIRouter(prefix="/api/runtime/v1", tags=["runtime"])


class _RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[int, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key_id: int) -> bool:
        now = time.monotonic()
        with self._lock:
            hits = self._hits[key_id]
            while hits and now - hits[0] > RATE_LIMIT_WINDOW_SECONDS:
                hits.popleft()
            if len(hits) >= RATE_LIMIT_REQUESTS:
                return False
            hits.append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


rate_limiter = _RateLimiter()


def _error(status: int, message: str) -> HTTPException:
    return HTTPException(status_code=status, detail=message)


def _require_secure_transport(request: Request) -> None:
    """`secfoo serve` binds loopback by default. On any other address, a key
    must not cross the network in clear text unless the operator opted in."""
    state = request.app.state
    bind_host = getattr(state, "bind_host", "127.0.0.1")
    if bind_host in LOOPBACK_HOSTS or getattr(state, "allow_insecure_runtime", False):
        return
    if request.url.scheme != "https":
        raise _error(403, "refusing an API key over plain HTTP on a non-loopback address; put TLS in front "
                          "(see docs/REFERENCE.md) or start secfoo serve with --allow-insecure-runtime")


class _Caller:
    def __init__(self, repo: RunRepository, key: keys_module.ApiKey, project_id: int) -> None:
        self.repo, self.key, self.project_id = repo, key, project_id


async def caller(request: Request, project: str = Query(..., description="Project identifier as `secfoo run` recorded it")):
    # async, like every route here: sqlite connections are bound to the thread
    # that opened them, and FastAPI runs sync dependencies in a worker pool.
    _require_secure_transport(request)
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise _error(401, "missing Authorization: Bearer <api key>")
    repo = RunRepository()
    try:
        key = keys_module.verify_key(repo.connection, token.strip())
        if key is None:
            raise _error(401, "invalid or revoked API key")
        if not rate_limiter.allow(key.id):
            raise _error(429, "rate limit exceeded for this key; retry later")
        project_id = repo.find_project_id(project)
        if project_id is None:
            # Not auto-created: evidence with no scan has nothing to attach to.
            raise _error(404, f"unknown project {project!r}; run `secfoo run` against it first")
        if not key.can_access(project_id):
            raise _error(403, "this API key has no access to that project")
        yield _Caller(repo, key, project_id)
    finally:
        repo.close()


def _watchlist_etag(document: dict) -> str:
    stable = json.dumps(document["entries"], sort_keys=True).encode("utf-8")
    return '"' + hashlib.sha256(stable).hexdigest()[:32] + '"'


@router.get("/watchlist")
async def get_watchlist(request: Request, who: Annotated[_Caller, Depends(caller)]):
    document, _notes = build_watchlist(who.repo, who.project_id)
    etag = _watchlist_etag(document)
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers={"ETag": etag})
    return Response(
        content=json.dumps(document), media_type="application/json", headers={"ETag": etag, "Cache-Control": "no-cache"}
    )


async def _read_body(request: Request) -> bytes:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise _error(413, f"request body over {MAX_BODY_BYTES} bytes")
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY_BYTES:
            raise _error(413, f"request body over {MAX_BODY_BYTES} bytes")
    if request.headers.get("content-encoding", "").lower() == "gzip" or body[:2] == b"\x1f\x8b":
        try:
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            data = decompressor.decompress(body, MAX_DECOMPRESSED_BYTES + 1)
        except (zlib.error, gzip.BadGzipFile):
            raise _error(400, "body is not valid gzip") from None
        if len(data) > MAX_DECOMPRESSED_BYTES or decompressor.unconsumed_tail:
            raise _error(413, f"decompressed body over {MAX_DECOMPRESSED_BYTES} bytes")
        return data
    return body


def _with_app_env(lines: list[str], app: str | None, env: str | None) -> list[str]:
    """Live sensors send app/env as query params (SECFOO_APP / SECFOO_ENV);
    fill them into session lines that don't name their own."""
    if not (app or env):
        return lines
    out = []
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            out.append(line)  # ingest_events reports it with its line number
            continue
        if isinstance(event, dict) and event.get("type") == "session":
            if app and not event.get("app"):
                event["app"] = app
            if env and not event.get("env"):
                event["env"] = env
            line = json.dumps(event)
        out.append(line)
    return out


@router.post("/events")
async def post_events(
    request: Request,
    who: Annotated[_Caller, Depends(caller)],
    app: str | None = Query(None, max_length=200),
    env: str | None = Query(None, max_length=200),
):
    lines = (await _read_body(request)).decode("utf-8", errors="replace").splitlines()
    if len(lines) > MAX_BATCH_LINES:
        raise _error(413, f"batch over {MAX_BATCH_LINES} lines; flush more often")
    report = ingest_events(who.repo.connection, who.project_id, _with_app_env(lines, app, env))
    return {
        "sessions": report.sessions,
        "loads": report.loads,
        "hits": report.hits,
        "skipped": [{"line": n, "reason": r} for n, r in report.skipped[:100]],
        "skipped_count": len(report.skipped),
        "unknown_fingerprints": sorted(report.unknown_fingerprints)[:100],
    }


def _bounded_text(payload: dict, key: str, *, required: bool = False) -> str | None:
    value = payload.get(key)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise _error(422, f"{key!r} must be a non-empty string of at most 200 characters")
    return value


def _count(payload: dict, key: str) -> int:
    value = payload.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _error(422, f"{key!r} must be a non-negative integer")
    return value


@router.post("/heartbeat")
async def post_heartbeat(request: Request, who: Annotated[_Caller, Depends(caller)]):
    try:
        payload = json.loads(await _read_body(request) or b"{}")
    except json.JSONDecodeError:
        raise _error(400, "heartbeat body must be JSON") from None
    if not isinstance(payload, dict):
        raise _error(400, "heartbeat body must be a JSON object")
    sensor_id = _bounded_text(payload, "sensor_id", required=True)
    now = datetime.now(timezone.utc).isoformat()
    conn = who.repo.connection
    conn.execute(
        """
        INSERT INTO runtime_sensors (project_id, sensor_id, version, app, env, instances, dropped_total,
                                     first_seen_at, last_heartbeat_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (project_id, sensor_id) DO UPDATE SET
            version = excluded.version, app = excluded.app, env = excluded.env, instances = excluded.instances,
            dropped_total = runtime_sensors.dropped_total + excluded.dropped_total,
            last_heartbeat_at = excluded.last_heartbeat_at
        """,
        (who.project_id, sensor_id, _bounded_text(payload, "version"), _bounded_text(payload, "app"),
         _bounded_text(payload, "env"), _count(payload, "instances"), _count(payload, "dropped"), now, now),
    )
    conn.commit()
    return {"ok": True, "received_at": now}


@router.get("/evidence")
async def get_evidence(who: Annotated[_Caller, Depends(caller)]):
    from secfoo.web import sca_runtime

    findings = []
    for finding in who.repo.list_sca_findings(project_id=who.project_id, status="open"):
        status = sca_runtime.status_for(
            who.repo.connection, project_id=who.project_id, fingerprint=finding.fingerprint, package=finding.package,
            ecosystem=finding.ecosystem, scanned_version=finding.version,
        )
        findings.append({
            "finding_fingerprint": finding.fingerprint,
            "package": finding.package,
            "version": finding.version,
            "severity": finding.severity,
            "static_reachability": finding.reachability,
            "runtime_state": status.state,
            "runtime_summary": status.summary,
            "hits": status.hits,
            "routes": status.routes,
            "loaded_versions": status.loaded_versions,
            "version_drift": status.version_drift,
            "coverage_percent": status.coverage.percent,
            "observed_hours": round(status.coverage.observed_hours, 2),
            "conflict": sca_runtime.is_conflict(finding.reachability or "", status),
        })
    return {"project": who.repo.get_project(who.project_id).identifier, "findings": findings}
