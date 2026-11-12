"""Runtime evidence at the developer stage (#80): the CLI, SARIF and CI gate.

`RuntimeLookup` answers "what did production see for this finding?" for
`secfoo findings list/show/check/export` and the `secfoo run` summary.

Sources, merged (the stronger state wins):

1. the local store -- evidence ingested here (`secfoo runtime ingest`, or a
   self-hosted `secfoo serve` sharing this store). No network.
2. the server the user's API key belongs to (`secfoo cloud login`), via
   `GET /api/runtime/v1/evidence` (#66). Cached under
   $SECFOO_HOME/runtime-cache/, so offline runs reuse the last answer.

Without a key there is no network call at all, and findings show "No
runtime data" -- the normal state when no sensor is deployed, never an error.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from secfoo.web import sca_runtime

# Display / sort order within a severity (#80): strongest evidence first,
# and "not observed" last but never hidden (#51 rule 4).
ORDER = ("reached", "executed", "loaded", "none", "not_loaded", "not_observed")
_RANK = {state: i for i, state in enumerate(ORDER)}
FETCH_TIMEOUT_SECONDS = 5


@dataclass
class Runtime:
    state: str = "none"
    summary: str = "No runtime data"
    routes: list[dict] = field(default_factory=list)
    hits: int = 0
    last_seen: str | None = None
    loaded_versions: list[str] = field(default_factory=list)
    version_drift: bool = False
    source: str = "none"   # local / server / cache / none

    @property
    def rank(self) -> int:
        return _RANK.get(self.state, len(ORDER))

    @property
    def is_reached(self) -> bool:
        return self.state == "reached"

    def label(self) -> str:
        return self.summary

    def as_sarif(self) -> dict:
        return {"state": self.state, "summary": self.summary, "routes": self.routes, "hits": self.hits,
                "last_seen": self.last_seen, "version_drift": self.version_drift}


def _stronger(a: Runtime, b: Runtime) -> Runtime:
    # sca_runtime's ladder: reached > executed > loaded > not_loaded > not_observed > none
    order = sca_runtime.STATES
    return a if order.index(a.state) <= order.index(b.state) else b


def _from_status(status: sca_runtime.RuntimeStatus, source: str) -> Runtime:
    return Runtime(state=status.state, summary=status.summary, routes=status.routes, hits=status.hits,
                   last_seen=status.last_seen, loaded_versions=status.loaded_versions,
                   version_drift=status.version_drift, source=source if status.state != "none" else "none")


def _from_server(row: dict) -> Runtime:
    return Runtime(state=row.get("runtime_state") or "none", summary=row.get("runtime_summary") or "No runtime data",
                   routes=row.get("routes") or [], hits=row.get("hits") or 0,
                   loaded_versions=row.get("loaded_versions") or [], version_drift=bool(row.get("version_drift")),
                   source="server")


class RuntimeLookup:
    def __init__(self, repo, *, enabled: bool = True, fetch=None, cloud_config=None) -> None:
        """`fetch(url, api_key) -> dict` and `cloud_config` are injectable for tests;
        by default the key and URL come from `secfoo cloud login`."""
        self.repo = repo
        self.enabled = enabled
        self._fetch = fetch or _http_get_json
        self._cloud = cloud_config
        self._cloud_loaded = cloud_config is not None
        self._server: dict[int, dict[str, Runtime]] = {}
        self.notes: list[str] = []

    def _cloud_config(self):
        if not self._cloud_loaded:
            self._cloud_loaded = True
            try:
                from secfoo.cloud import load_cloud_config

                self._cloud = load_cloud_config()
            except Exception:  # noqa: BLE001 -- a broken cloud.toml just means "no server"
                self._cloud = None
        return self._cloud

    def _cache_path(self, project_identifier: str):
        from secfoo.config import STORE_DIR

        digest = hashlib.sha256(project_identifier.encode("utf-8")).hexdigest()[:24]
        return STORE_DIR / "runtime-cache" / f"{digest}.json"

    def _server_states(self, project_id: int) -> dict[str, Runtime]:
        if project_id in self._server:
            return self._server[project_id]
        states: dict[str, Runtime] = {}
        config = self._cloud_config()
        project = self.repo.get_project(project_id)
        if config is not None and project is not None:  # no key: no network call, ever
            cache = self._cache_path(project.identifier)
            url = (f"{config.portal_url.rstrip('/')}/api/runtime/v1/evidence?"
                   + urllib.parse.urlencode({"project": project.identifier}))
            payload, source = None, "server"
            try:
                payload = self._fetch(url, config.api_key)
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(json.dumps(payload), encoding="utf-8")
            except (OSError, ValueError, urllib.error.URLError) as exc:
                if cache.is_file():
                    payload, source = json.loads(cache.read_text(encoding="utf-8")), "cache"
                    self.notes.append(f"runtime evidence from cache (server unreachable: {exc.__class__.__name__})")
            for row in (payload or {}).get("findings", []):
                runtime = _from_server(row)
                runtime.source = source
                states[row.get("finding_fingerprint", "")] = runtime
        self._server[project_id] = states
        return states

    def for_finding(self, skill_id: str, row: dict) -> Runtime:
        """Runtime state of one findings row (only SCA findings carry evidence)."""
        if not self.enabled or skill_id != "sca-reachability":
            return Runtime()
        local = _from_status(sca_runtime.status_for(
            self.repo.connection, project_id=row["project_id"], fingerprint=row["fingerprint"],
            package=row.get("package") or "", ecosystem=row.get("ecosystem"), scanned_version=row.get("version"),
        ), "local")
        remote = self._server_states(row["project_id"]).get(row["fingerprint"])
        return _stronger(local, remote) if remote is not None else local


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}


def severity_rank(severity: str | None) -> int:
    return _SEVERITY_RANK.get((severity or "").strip().lower(), 5)


def sort_key(row: dict, runtime: Runtime) -> tuple:
    return (severity_rank(row.get("severity")), runtime.rank, row.get("display_name") or "", row.get("fingerprint") or "")


def remediation_hint(row: dict, runtime: Runtime) -> str | None:
    """For a reached SCA finding: the fixed version and the live routes it protects."""
    if not runtime.is_reached:
        return None
    routes = ", ".join(f"{r['route']}" + (f" ({r['auth']})" if r.get("auth") else "") for r in runtime.routes[:5])
    fixed = (row.get("fixed_in") or "").strip()
    fix = f"upgrade {row.get('package')} to {fixed}" if fixed and fixed.lower() not in ("unknown", "n/a", "-") \
        else f"replace or patch {row.get('package')}"
    return f"{fix}; this protects live route(s): {routes}"


def parse_gate(spec: str) -> tuple[str, int]:
    """`reached[:<min-severity>]` or `executed[:<min-severity>]` -> (state, severity rank)."""
    state, _, severity = spec.partition(":")
    if state not in ("reached", "executed"):
        raise ValueError("--fail-on must be reached[:<severity>] or executed[:<severity>]")
    if severity and severity.lower() not in _SEVERITY_RANK:
        raise ValueError(f"unknown severity {severity!r}; use critical, high, medium, low or info")
    return state, (_SEVERITY_RANK[severity.lower()] if severity else 4)


def trips_gate(gate: tuple[str, int], row: dict, runtime: Runtime) -> bool:
    state, max_rank = gate
    hit = runtime.state == "reached" or (state == "executed" and runtime.state == "executed")
    return hit and severity_rank(row.get("severity")) <= max_rank


def _http_get_json(url: str, api_key: str) -> dict:
    request = urllib.request.Request(  # nosec B310 -- the user's own portal URL from `secfoo cloud login`
        url, headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json", "User-Agent": "secfoo-cli"}
    )
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:  # nosec B310
        return json.loads(response.read().decode("utf-8"))
