"""OSV.dev vulnerability lookup client: enriches whatever a `sca-reachability`
report's LLM identified with real CVE/GHSA data from a free, public,
no-auth vulnerability database (https://osv.dev). This is deliberately NOT
a substitute for the LLM inventing a CVE ID itself -- the SCA skill's
prompt contract explicitly forbids that ("never invent a CVE ID -- write
'unverified'"). A package+version either matches a real OSV record or it
doesn't; there is no in-between guessing here either.

Uses stdlib `urllib.request`, same precedent as `secfoo/cloud.py` -- no new
HTTP dependency.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from secfoo.storage.repository import RunRepository

OSV_API_URL = "https://api.osv.dev/v1/query"

# Tighter than cloud.py's 15s -- this can run inside a live dashboard GET
# (the capped top-up pass), not just a background CLI hook, so a single
# slow request shouldn't be allowed to stall a page load for long.
REQUEST_TIMEOUT_SECONDS = 5

# A cached "clean" result can go stale: OSV publishes new advisories
# against old package versions retroactively, so "no vulns last time we
# checked" isn't true forever.
OSV_LOOKUP_TTL_DAYS = 7

# Shared circuit-breaker budget for both callers (runner.py's post-run
# hook and the dashboard's top-up pass) -- caps worst-case latency/failure
# blast radius from a single enrichment pass.
MAX_LOOKUPS_PER_PASS = 25

# Free-text Ecosystem values secfoo's own SCA report contract asks for
# (e.g. "Python", "Node.js") -> OSV's own controlled vocabulary. Anything
# not listed here is unrecognized, not guessed at -- see normalize_ecosystem.
ECOSYSTEM_MAP = {
    "python": "PyPI", "pypi": "PyPI",
    "node.js": "npm", "nodejs": "npm", "npm": "npm", "javascript": "npm", "typescript": "npm", "js": "npm",
    "java": "Maven", "maven": "Maven", "kotlin": "Maven", "scala": "Maven",
    ".net": "NuGet", "dotnet": "NuGet", "c#": "NuGet", "csharp": "NuGet", "nuget": "NuGet",
    "go": "Go", "golang": "Go",
    "rust": "crates.io", "crates.io": "crates.io", "cargo": "crates.io",
    "ruby": "RubyGems", "rubygems": "RubyGems",
    "php": "Packagist", "packagist": "Packagist", "composer": "Packagist",
}


class OsvError(RuntimeError):
    pass


def normalize_ecosystem(raw: str | None) -> str | None:
    """Free-text report Ecosystem value -> OSV's controlled vocabulary.
    Returns None -- never a guess -- for anything unrecognized; callers
    must treat that as "not looked up", the same never-fabricate
    discipline the skill's own CVE rule already applies.
    """
    if not raw:
        return None
    return ECOSYSTEM_MAP.get(raw.strip().lower())


def query_osv(ecosystem: str, package: str, version: str) -> list[dict]:
    """One POST to OSV_API_URL. Returns [] when OSV has no records for this
    exact package+version (a real, cacheable "queried, clean" result, not
    a failure). Raises OsvError on any transport/HTTP failure.
    """
    payload = {"package": {"name": package, "ecosystem": ecosystem}, "version": version}
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        OSV_API_URL, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310  # nosec B310 -- hardcoded public OSV.dev API URL
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise OsvError(f"OSV.dev returned {exc.code}: {detail or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise OsvError(f"Could not reach OSV.dev: {exc.reason}") from exc
    return data.get("vulns", [])


def _is_fresh(queried_at: str, *, now: datetime) -> bool:
    try:
        queried_dt = datetime.fromisoformat(queried_at)
    except ValueError:
        return False
    if queried_dt.tzinfo is None:
        queried_dt = queried_dt.replace(tzinfo=timezone.utc)
    return queried_dt >= now - timedelta(days=OSV_LOOKUP_TTL_DAYS)


def enrich_lookups(
    repo: RunRepository, keys: list[tuple[str, str, str]], *, budget: int = MAX_LOOKUPS_PER_PASS
) -> bool:
    """Looks up and caches whichever of `keys` -- each an already-normalized
    (ecosystem, package, version) triple -- are missing from the cache or
    older than OSV_LOOKUP_TTL_DAYS, up to `budget` queries. Stops the whole
    pass on the first connection-level failure (a timeout/URLError almost
    always means OSV is unreachable this pass, not that this one row is
    special -- spending the remaining budget re-discovering that one
    request at a time only adds latency for no benefit). Never raises.

    Returns True iff it hit a connection failure, so callers can surface
    "OSV unreachable" without inspecting internals.
    """
    if not keys:
        return False

    lookup_map = repo.osv_lookup_map()
    now = datetime.now(timezone.utc)

    to_query: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for key in keys:
        if key in seen:
            continue
        seen.add(key)
        cached = lookup_map.get(key)
        if cached is not None and _is_fresh(cached.queried_at, now=now):
            continue
        to_query.append(key)

    for ecosystem, package, version in to_query[:budget]:
        try:
            vulns = query_osv(ecosystem, package, version)
        except OsvError:
            return True
        repo.upsert_osv_lookup(ecosystem=ecosystem, package=package, version=version, vulns=vulns)

    return False
