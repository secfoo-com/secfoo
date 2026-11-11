"""Runtime evidence for the SCA dashboard (#57), read from #53's tables.

Each (project, SCA finding) gets one state from the evidence ladder in #51,
strongest first:

    reached   -- a watched symbol was called while handling a request route
    executed  -- a watched symbol was called, but with no request context
    loaded    -- the package was in memory, but no watched symbol was called
    not_loaded / not_observed -- sessions exist, nothing seen for this finding
    none      -- no runtime data for the project at all

"Not observed" never means "not reachable" (#51 rule 4): those states always
carry the coverage and observation window they were measured over.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime

# Strongest first; the list row shows the strongest state across projects.
STATES = ("reached", "executed", "loaded", "not_loaded", "not_observed", "none")
_RANK = {state: i for i, state in enumerate(STATES)}
LABELS = {
    "reached": "Reached from traffic",
    "executed": "Executed",
    "loaded": "Loaded",
    "not_loaded": "Not loaded",
    "not_observed": "Not observed",
    "none": "No runtime data",
}
# Existing badge styles only (design-system/components/badges.css).
BADGES = {
    "reached": "badge--error",
    "executed": "badge--warning",
    "loaded": "badge--primary",
    "not_loaded": "badge--teal",
    "not_observed": "badge--neutral",
    "none": "badge--neutral",
}
# A hit on one of these "routes" had no inbound request behind it.
_NO_REQUEST_ROUTES = ("", "unknown", "startup")


def _is_request_route(route: str) -> bool:
    return route not in _NO_REQUEST_ROUTES and not route.startswith("job:")


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts[:-1] + "+00:00" if ts.endswith("Z") else ts)
    except ValueError:
        return None


@dataclass
class Coverage:
    sessions: int = 0
    functions_total: int = 0
    functions_executed: int = 0
    observed_hours: float = 0.0

    @property
    def percent(self) -> int | None:
        if not self.functions_total:
            return None
        return round(self.functions_executed / self.functions_total * 100)

    @property
    def hours_label(self) -> str:
        if self.observed_hours >= 48:
            return f"{self.observed_hours / 24:.0f}d"
        if self.observed_hours >= 1:
            return f"{self.observed_hours:.0f}h"
        return f"{self.observed_hours * 60:.0f}m"


@dataclass
class RuntimeStatus:
    state: str = "none"
    hits: int = 0
    last_seen: str | None = None
    routes: list[dict] = field(default_factory=list)        # route, auth, count -- request routes only
    evidence: list[dict] = field(default_factory=list)      # every hit row, with its session
    loaded_versions: list[str] = field(default_factory=list)
    version_drift: bool = False
    coverage: Coverage = field(default_factory=Coverage)
    sources: list[str] = field(default_factory=list)        # sensor / coverage

    @property
    def label(self) -> str:
        return LABELS[self.state]

    @property
    def badge(self) -> str:
        return BADGES[self.state]

    @property
    def summary(self) -> str:
        """One-line cell text, e.g. 'Reached · POST /upload (anonymous) · 312'."""
        cov = self.coverage
        if self.state == "reached":
            top = self.routes[0]
            more = f" +{len(self.routes) - 1} more" if len(self.routes) > 1 else ""
            auth = f" ({top['auth']})" if top["auth"] else ""
            return f"Reached · {top['route']}{auth} · {top['count']:,}{more}"
        if self.state == "executed":
            return f"Executed · {self.hits:,} hits" + (f" · last {self.last_seen[:10]}" if self.last_seen else "")
        if self.state == "loaded":
            return "Loaded · no watched call" + (" · version drift" if self.version_drift else "")
        if self.state in ("not_loaded", "not_observed"):
            pct = f"{cov.percent}% coverage" if cov.percent is not None else "coverage unknown"
            return f"{LABELS[self.state]} · {pct} · {cov.hours_label}"
        return "No runtime data"


def _coverage(conn, project_id: int) -> tuple[Coverage, list[str], bool]:
    rows = conn.execute(
        "SELECT source, started_at, ended_at, app_functions_total, app_functions_executed, "
        "EXISTS (SELECT 1 FROM runtime_packages p WHERE p.session_id = s.id) AS has_inventory "
        "FROM runtime_sessions s WHERE project_id = ?",
        (project_id,),
    ).fetchall()
    cov = Coverage(sessions=len(rows))
    sources: set[str] = set()
    has_inventory = False
    for source, started, ended, total, executed, inventory in rows:
        sources.add(source)
        has_inventory = has_inventory or bool(inventory)
        if total and executed is not None:
            cov.functions_total += total
            cov.functions_executed += executed
        start, end = _parse(started), _parse(ended)
        if start and end and end > start:
            cov.observed_hours += (end - start).total_seconds() / 3600
    return cov, sorted(sources), has_inventory


def status_for(conn, *, project_id: int, fingerprint: str | None, package: str,
               ecosystem: str | None, scanned_version: str | None) -> RuntimeStatus:
    """The runtime state of one SCA finding in one project."""
    status = RuntimeStatus()
    status.coverage, status.sources, has_inventory = _coverage(conn, project_id)
    if not status.coverage.sessions:
        return status  # "none": no sensor, no import -- SCA works exactly as before

    if fingerprint:
        rows = conn.execute(
            "SELECT e.symbol, e.route, e.auth, e.count, e.first_seen, e.last_seen, e.entry_frame, e.stack_sample, "
            "s.app, s.env, s.instance, s.source, s.language, s.started_at, s.ended_at "
            "FROM runtime_evidence e JOIN runtime_sessions s ON s.id = e.session_id "
            "WHERE e.project_id = ? AND e.finding_fingerprint = ? ORDER BY e.count DESC",
            (project_id, fingerprint),
        ).fetchall()
        routes: dict[tuple[str, str | None], int] = {}
        for (symbol, route, auth, count, first_seen, last_seen, entry_frame, stack, app, env, instance, source,
             language, started_at, ended_at) in rows:
            status.hits += count
            if last_seen and (status.last_seen is None or last_seen > status.last_seen):
                status.last_seen = last_seen
            if _is_request_route(route):
                routes[(route, auth)] = routes.get((route, auth), 0) + count
            status.evidence.append({
                "symbol": symbol, "route": route or "—", "auth": auth, "count": count,
                "first_seen": first_seen, "last_seen": last_seen, "entry_frame": entry_frame,
                "stack_sample": json.loads(stack) if stack else [],
                "app": app, "env": env, "instance": instance, "source": source, "language": language,
                "started_at": started_at, "ended_at": ended_at,
            })
        status.routes = [
            {"route": r, "auth": a, "count": c}
            for (r, a), c in sorted(routes.items(), key=lambda item: -item[1])
        ]
        if status.routes:
            status.state = "reached"
            return status
        if status.hits:
            status.state = "executed"
            return status

    loaded = conn.execute(
        "SELECT DISTINCT version FROM runtime_packages WHERE project_id = ? AND lower(package) = lower(?) "
        "AND (? IS NULL OR ecosystem = ?)",
        (project_id, package, ecosystem, ecosystem),
    ).fetchall()
    status.loaded_versions = sorted(v for (v,) in loaded)
    if status.loaded_versions:
        status.state = "loaded"
        status.version_drift = bool(scanned_version) and scanned_version not in status.loaded_versions
        return status
    status.state = "not_loaded" if has_inventory else "not_observed"
    return status


def strongest(statuses: list[RuntimeStatus]) -> RuntimeStatus:
    return min(statuses, key=lambda s: _RANK[s.state]) if statuses else RuntimeStatus()


def is_conflict(static_reachability: str, status: RuntimeStatus) -> bool:
    """The case runtime evidence exists to catch: the static scan said
    "Not reachable", but the code actually ran."""
    return static_reachability.strip().lower() == "not reachable" and status.state in ("reached", "executed")
