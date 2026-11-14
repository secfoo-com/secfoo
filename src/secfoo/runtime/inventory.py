"""Runtime package inventory (#68): what is loaded in production, at which
version, compared with what was scanned.

    | Case                                         | Result                                    |
    |----------------------------------------------|-------------------------------------------|
    | vulnerable package loaded at scanned version | finding shows Loaded (web/sca_runtime.py) |
    | loaded at a different version than scanned   | drift: that version is checked in OSV     |
    | loaded but absent from scanned manifests     | unscanned: OSV checked, finding raised    |
    | vulnerable package never loaded              | Not loaded, with the observation window   |

Plus "new in production" (first seen after a sensor's baseline window),
`recheck()` -- OSV querybatch for every running version, so a newly
published advisory raises a finding with no new scan -- and a CycloneDX
runtime SBOM. Findings raised here live in `runtime_findings`.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from secfoo import osv
from secfoo.report.sca import SKILL_ID, inventory_lookup

DEFAULT_BASELINE_HOURS = 24
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_BATCH_SIZE = 1000

QueryBatch = Callable[[list[tuple[str, str, str]]], list[list[dict]]]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        value = datetime.fromisoformat(ts[:-1] + "+00:00" if ts.endswith("Z") else ts)
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


@dataclass
class LoadedPackage:
    ecosystem: str
    package: str
    version: str
    apps: set[str] = field(default_factory=set)      # "app/env"
    first_seen: str | None = None
    status: str = "scanned"                          # scanned / drift / unscanned
    scanned_versions: list[str] = field(default_factory=list)
    advisories: list[str] = field(default_factory=list)
    new: bool = False


@dataclass
class InventoryReport:
    packages: list[LoadedPackage] = field(default_factory=list)
    not_loaded: list[dict] = field(default_factory=list)     # open SCA findings never loaded
    observed_hours: float = 0.0
    raised: list[dict] = field(default_factory=list)          # runtime findings raised/refreshed now


def _scanned(repo, project_id: int) -> dict[tuple[str, str], set[str]]:
    """(OSV ecosystem, package lower) -> versions the latest SCA scan saw."""
    scanned: dict[tuple[str, str], set[str]] = defaultdict(set)
    for project in repo.activity_summary_by_project(SKILL_ID):
        if project["project_id"] != project_id or not project.get("latest_success_report_path"):
            continue
        path = Path(project["latest_success_report_path"])
        if not path.is_file():
            continue
        for (package, version), ecosystem_raw in inventory_lookup(path.read_text(encoding="utf-8")).items():
            ecosystem = osv.normalize_ecosystem(ecosystem_raw)
            if ecosystem:
                scanned[(ecosystem, package.lower())].add(version)
    for finding in repo.list_sca_findings(project_id=project_id):
        ecosystem = osv.normalize_ecosystem(finding.ecosystem) or finding.ecosystem
        if ecosystem and finding.version:
            scanned[(ecosystem, finding.package.lower())].add(finding.version)
    return scanned


def _loaded(conn, project_id: int, *, app: str | None, env: str | None) -> tuple[dict, dict]:
    rows = conn.execute(
        "SELECT p.ecosystem, p.package, p.version, s.app, s.env, COALESCE(p.first_seen, s.started_at), s.started_at "
        "FROM runtime_packages p JOIN runtime_sessions s ON s.id = p.session_id WHERE p.project_id = ?"
        " AND (? IS NULL OR s.app = ?) AND (? IS NULL OR s.env = ?)",
        (project_id, app, app, env, env),
    ).fetchall()
    loaded: dict[tuple[str, str, str], LoadedPackage] = {}
    app_start: dict[str, datetime] = {}
    for ecosystem, package, version, s_app, s_env, first_seen, started in rows:
        label = f"{s_app or '-'}/{s_env or '-'}"
        start = _parse(started)
        if start and (label not in app_start or start < app_start[label]):
            app_start[label] = start
        key = (ecosystem, package.lower(), version)
        item = loaded.setdefault(key, LoadedPackage(ecosystem, package, version))
        item.apps.add(label)
        if first_seen and (item.first_seen is None or first_seen < item.first_seen):
            item.first_seen = first_seen
    return loaded, app_start


def _advisory_ids(vulns: list[dict]) -> list[str]:
    ids = []
    for vuln in vulns:
        ids.append(next((a for a in sorted(vuln.get("aliases") or []) if a.startswith("GHSA-")), vuln.get("id", "")))
    return sorted({i for i in ids if i})


def _known_advisories(repo, project_id: int) -> dict[tuple[str, str], set[str]]:
    known: dict[tuple[str, str], set[str]] = defaultdict(set)
    lookups = repo.osv_lookup_map()
    for finding in repo.list_sca_findings(project_id=project_id):
        ecosystem = osv.normalize_ecosystem(finding.ecosystem) or finding.ecosystem or ""
        key = (ecosystem, finding.package.lower())
        if finding.cve:
            known[key].add(finding.cve.strip())
        record = lookups.get((ecosystem, finding.package, finding.version or ""))
        for vuln in record.vulns if record else []:
            known[key] |= {vuln.get("id", ""), *(vuln.get("aliases") or [])}
    return known


def _raise(conn, project_id: int, kind: str, item: LoadedPackage, advisory: str) -> dict:
    now = _now()
    conn.execute(
        """
        INSERT INTO runtime_findings (project_id, kind, ecosystem, package, version, advisory, scanned_versions, apps,
                                      first_seen_at, last_seen_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (project_id, kind, ecosystem, package, version, advisory) DO UPDATE SET
            scanned_versions = excluded.scanned_versions, apps = excluded.apps, last_seen_at = excluded.last_seen_at
        """,
        (project_id, kind, item.ecosystem, item.package, item.version, advisory, json.dumps(item.scanned_versions),
         json.dumps(sorted(item.apps)), now, now),
    )
    return {"kind": kind, "ecosystem": item.ecosystem, "package": item.package, "version": item.version,
            "advisory": advisory, "apps": sorted(item.apps), "scanned_versions": item.scanned_versions}


def analyze(repo, project_id: int, *, app: str | None = None, env: str | None = None,
            baseline_hours: float = DEFAULT_BASELINE_HOURS,
            known: dict[tuple[str, str], set[str]] | None = None) -> InventoryReport:
    """Compare the loaded inventory with the scan; raise/refresh runtime findings.

    `known` is the advisories the scan already accounts for, per (ecosystem,
    package). recheck() snapshots it BEFORE refreshing the OSV cache, so an
    advisory OSV publishes later counts as new rather than as known.
    """
    conn = repo.connection
    report = InventoryReport()
    loaded, app_start = _loaded(conn, project_id, app=app, env=env)
    scanned = _scanned(repo, project_id)
    known = _known_advisories(repo, project_id) if known is None else known
    lookups = repo.osv_lookup_map()

    for item in loaded.values():
        versions = scanned.get((item.ecosystem, item.package.lower()))
        record = lookups.get((item.ecosystem, item.package, item.version)) or lookups.get(
            (item.ecosystem, item.package.lower(), item.version))
        item.advisories = _advisory_ids(record.vulns) if record else []
        if versions is None:
            item.status = "unscanned"
            for advisory in item.advisories:
                report.raised.append(_raise(conn, project_id, "unscanned", item, advisory))
        elif item.version not in versions:
            item.status, item.scanned_versions = "drift", sorted(versions)
            for advisory in item.advisories:
                report.raised.append(_raise(conn, project_id, "drift", item, advisory))
        else:
            item.status, item.scanned_versions = "scanned", sorted(versions)
            for advisory in item.advisories:
                if advisory not in known.get((item.ecosystem, item.package.lower()), set()):
                    report.raised.append(_raise(conn, project_id, "new_advisory", item, advisory))
        # New in production: first seen after its app's baseline window.
        seen = _parse(item.first_seen)
        for label in item.apps:
            start = app_start.get(label)
            if seen and start and seen > start + timedelta(hours=baseline_hours):
                item.new = True
    conn.commit()

    loaded_names = {(e, p) for (e, p, _v) in loaded}
    for finding in repo.list_sca_findings(project_id=project_id, status="open"):
        ecosystem = osv.normalize_ecosystem(finding.ecosystem) or finding.ecosystem
        if (ecosystem, finding.package.lower()) not in loaded_names:
            report.not_loaded.append({"package": finding.package, "version": finding.version,
                                      "fingerprint": finding.fingerprint, "severity": finding.severity})
    if app_start:
        rows = conn.execute("SELECT started_at, ended_at FROM runtime_sessions WHERE project_id = ?", (project_id,))
        for started, ended in rows.fetchall():
            start, end = _parse(started), _parse(ended)
            if start and end and end > start:
                report.observed_hours += (end - start).total_seconds() / 3600
    report.packages = sorted(loaded.values(), key=lambda p: ({"unscanned": 0, "drift": 1, "scanned": 2}[p.status],
                                                             p.package.lower(), p.version))
    return report


# ---------- real-time advisories ----------


def osv_querybatch(keys: list[tuple[str, str, str]]) -> list[list[dict]]:
    """OSV /v1/querybatch: one list of {id, modified} per (ecosystem, package, version)."""
    results: list[list[dict]] = []
    for start in range(0, len(keys), OSV_BATCH_SIZE):
        chunk = keys[start:start + OSV_BATCH_SIZE]
        body = json.dumps({"queries": [{"package": {"ecosystem": e, "name": p}, "version": v} for e, p, v in chunk]})
        request = urllib.request.Request(  # nosec B310 -- fixed public OSV.dev URL
            OSV_BATCH_URL, data=body.encode("utf-8"), headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=osv.REQUEST_TIMEOUT_SECONDS * 4) as response:  # nosec B310
                data = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, OSError) as exc:
            raise osv.OsvError(f"Could not reach OSV.dev: {exc}") from exc
        results.extend(r.get("vulns", []) for r in data.get("results", []))
    return results


def recheck(repo, *, project_id: int | None = None, query_batch: QueryBatch = osv_querybatch) -> list[dict]:
    """Query OSV for every package version currently loaded (in one project or
    all), refresh the cache, and return the runtime findings raised."""
    conn = repo.connection
    where, params = ("WHERE project_id = ?", (project_id,)) if project_id is not None else ("", ())
    keys = sorted({tuple(r) for r in conn.execute(
        f"SELECT DISTINCT ecosystem, package, version FROM runtime_packages {where}", params)})  # nosec B608
    if not keys:
        return []
    projects = [project_id] if project_id is not None else [
        r[0] for r in conn.execute("SELECT DISTINCT project_id FROM runtime_packages").fetchall()]
    known_before = {pid: _known_advisories(repo, pid) for pid in projects}
    for key, vulns in zip(keys, query_batch(keys)):
        repo.upsert_osv_lookup(ecosystem=key[0], package=key[1], version=key[2], vulns=vulns)
    raised: list[dict] = []
    for pid in projects:
        raised.extend(analyze(repo, pid, known=known_before[pid]).raised)
    return raised


# ---------- CycloneDX runtime SBOM ----------

_PURL_TYPES = {"PyPI": "pypi", "npm": "npm", "Maven": "maven", "NuGet": "nuget", "Go": "golang",
               "crates.io": "cargo", "RubyGems": "gem", "Packagist": "composer"}


def _purl(item: LoadedPackage) -> str | None:
    kind = _PURL_TYPES.get(item.ecosystem)
    if kind is None:
        return None
    name = item.package
    if kind == "pypi":
        name = name.lower().replace("_", "-")
    elif kind == "npm" and name.startswith("@"):
        name = "%40" + name[1:]
    elif kind == "maven" and ":" in name:
        name = name.replace(":", "/", 1)
    return f"pkg:{kind}/{name}@{item.version}"


def cyclonedx(report: InventoryReport, *, project: str, app: str | None, env: str | None) -> dict:
    components = []
    for item in report.packages:
        component = {"type": "library", "name": item.package, "version": item.version,
                     "properties": [{"name": "secfoo:runtime:status", "value": item.status},
                                    {"name": "secfoo:runtime:apps", "value": ",".join(sorted(item.apps))}]}
        purl = _purl(item)
        if purl:
            component["purl"] = purl
            component["bom-ref"] = purl
        components.append(component)
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"timestamp": _now(), "tools": {"components": [{"type": "application", "name": "secfoo"}]},
                     "component": {"type": "application", "name": app or project,
                                   "properties": [{"name": "secfoo:project", "value": project},
                                                  {"name": "secfoo:env", "value": env or "all"}]}},
        "components": components,
    }
