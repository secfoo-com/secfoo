"""Vulnerable-function watchlist for runtime probes (#52).

A probe can only tell whether vulnerable code runs if it knows which
function to watch. `build_watchlist()` turns a project's open SCA findings
into that list, from data secfoo already has:

1. OSV records cached in `osv_lookups` (no network):
   - `affected[].ecosystem_specific.imports[].symbols` -- Go advisories
     fill this in well (`{"path": "golang.org/x/net/html", "symbols": ["Parse"]}`);
   - `affected[].ecosystem_specific.affects.functions` -- RustSec writes
     full `crate::path::fn` names here.
2. Optionally, the GitHub advisory API's `vulnerabilities[].vulnerable_functions`
   (often empty; unauthenticated, rate-limited, so off unless asked for).
3. Otherwise the package itself, at `"granularity": "package"`, so the
   probe still records whether it was loaded.

Every symbol is normalised to the per-ecosystem notation the probes match
on (see `NOTATION`). A symbol that doesn't fit the notation is dropped, and
if none fit, the entry falls back to package granularity. An entry is never
dropped. The JSON Schema for the file is watchlist.schema.json.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import datetime, timezone

from secfoo.osv import normalize_ecosystem

WATCHLIST_VERSION = 1
GHSA_API_URL = "https://api.github.com/advisories/{ghsa_id}"
GHSA_TIMEOUT_SECONDS = 5

_IDENT = r"[A-Za-z_$][\w$]*"
# Per-ecosystem symbol notation (#52). Probes in every runtime match these
# exact forms, so anything that doesn't fit is not emitted as a symbol.
NOTATION: dict[str, re.Pattern[str]] = {
    "PyPI": re.compile(rf"^{_IDENT}(\.{_IDENT})+$"),                                   # yaml.load
    "npm": re.compile(rf"^(@[\w.-]+/)?[\w.-]+#{_IDENT}(\.{_IDENT})*$"),                # lodash#template
    "Maven": re.compile(rf"^{_IDENT}(\.{_IDENT})+#{_IDENT}$"),                         # a.b.Class#method
    "NuGet": re.compile(rf"^{_IDENT}(\.{_IDENT})+#{_IDENT}$"),                         # Ns.Type#Method
    "Go": re.compile(r"^[\w.~-]+(/[\w.~-]+)*\.[A-Za-z_]\w*(\.[A-Za-z_]\w*)?$"),        # import/path.Func[.Method]
    "crates.io": re.compile(rf"^{_IDENT}(::{_IDENT})+$"),                              # crate::path::fn
    "RubyGems": re.compile(rf"^{_IDENT}(::{_IDENT})*[#.]{_IDENT}[?!=]?$"),              # Nokogiri::XML::Document.parse
    "Packagist": re.compile(rf"^({_IDENT}(\\{_IDENT})*::{_IDENT}|{_IDENT})$"),          # Ns\Class::method or function
}

FetchJson = Callable[[str], dict]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def normalize_symbol(ecosystem: str, symbol: str) -> str | None:
    """`symbol` if it already fits the ecosystem's notation, else None."""
    pattern = NOTATION.get(ecosystem)
    symbol = symbol.strip()
    return symbol if pattern and pattern.match(symbol) else None


def _osv_symbols(vuln: dict, ecosystem: str, package: str) -> list[str]:
    """Raw symbols an OSV record lists for this package, before normalising."""
    symbols: list[str] = []
    for affected in vuln.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("name") != package or (pkg.get("ecosystem") or "").split(":")[0] != ecosystem:
            continue
        specific = affected.get("ecosystem_specific") or {}
        for imported in specific.get("imports") or []:  # Go
            path = imported.get("path") or package
            symbols.extend(f"{path}.{name}" for name in imported.get("symbols") or [])
        symbols.extend((specific.get("affects") or {}).get("functions") or [])  # RustSec
    return symbols


def _advisory_ids(vuln: dict) -> set[str]:
    return {vuln.get("id", ""), *(vuln.get("aliases") or [])} - {""}


def _ghsa_id(vuln: dict) -> str | None:
    return next((i for i in sorted(_advisory_ids(vuln)) if i.startswith("GHSA-")), None)


def _matching_vulns(vulns: list[dict], cve: str | None) -> list[dict]:
    """The advisories a finding refers to. A finding that names an advisory
    (by id or alias) gets only that one; one that doesn't ("unverified")
    gets every advisory OSV has for its package and version."""
    wanted = (cve or "").strip()
    if wanted and wanted.lower() != "unverified":
        named = [v for v in vulns if wanted in _advisory_ids(v)]
        if named:
            return named
    return list(vulns)


def fetch_github_advisory(url: str) -> dict:
    """GET one advisory from the GitHub REST API (no token: public data)."""
    request = urllib.request.Request(  # nosec B310 -- fixed https URL from GHSA_API_URL
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": "secfoo-watchlist"}
    )
    with urllib.request.urlopen(request, timeout=GHSA_TIMEOUT_SECONDS) as response:  # nosec B310
        return json.loads(response.read().decode("utf-8"))


class _GithubSource:
    """Optional GHSA lookups. Stops for the rest of the build at the first
    rate-limit (403/429) or network error, instead of retrying."""

    def __init__(self, fetch: FetchJson | None) -> None:
        self.fetch = fetch
        self.stopped_reason: str | None = None
        self._cache: dict[str, dict | None] = {}

    def symbols(self, ghsa_id: str, ecosystem: str, package: str) -> list[str]:
        if self.fetch is None or self.stopped_reason:
            return []
        if ghsa_id not in self._cache:
            try:
                self._cache[ghsa_id] = self.fetch(GHSA_API_URL.format(ghsa_id=ghsa_id))
            except urllib.error.HTTPError as exc:
                self._cache[ghsa_id] = None
                if exc.code in (403, 429):
                    self.stopped_reason = f"GitHub advisory API rate limit (HTTP {exc.code}); skipped the rest"
            except (urllib.error.URLError, OSError, ValueError) as exc:
                self._cache[ghsa_id] = None
                self.stopped_reason = f"GitHub advisory API unavailable ({exc.__class__.__name__}); skipped the rest"
        advisory = self._cache[ghsa_id] or {}
        found: list[str] = []
        for vulnerability in advisory.get("vulnerabilities") or []:
            pkg = vulnerability.get("package") or {}
            if (pkg.get("name") or "").lower() == package.lower():
                found.extend(vulnerability.get("vulnerable_functions") or [])
        return found


def _entry(*, fingerprint: str, advisory: str | None, ecosystem: str, package: str, version: str | None,
           symbols: list[str], source: str) -> dict:
    unique = sorted(set(symbols))
    return {
        "finding_fingerprint": fingerprint,
        "advisory": advisory,
        "ecosystem": ecosystem,
        "package": package,
        "version": version,
        "granularity": "symbol" if unique else "package",
        "symbols": unique,
        "source": source if unique else "package",
    }


def build_watchlist(repo, project_id: int, *, github_fetch: FetchJson | None = None) -> tuple[dict, list[str]]:
    """(watchlist document, notes) for the project's open SCA findings.

    `github_fetch` enables the optional GHSA source; tests pass a fake.
    Notes explain anything a user should know (unrecognised ecosystems,
    symbols that didn't fit the notation, a GHSA rate limit).
    """
    lookups = repo.osv_lookup_map()
    github = _GithubSource(github_fetch)
    entries: list[dict] = []
    notes: list[str] = []
    unnormalised = 0

    def keep(ecosystem: str, raw: list[str]) -> list[str]:
        nonlocal unnormalised
        kept = [s for s in (normalize_symbol(ecosystem, r) for r in raw) if s]
        unnormalised += len(raw) - len(kept)
        return kept

    for finding in repo.list_sca_findings(project_id=project_id, status="open"):
        ecosystem = normalize_ecosystem(finding.ecosystem)
        if ecosystem is None:
            notes.append(f"{finding.package}: ecosystem {finding.ecosystem!r} isn't recognised; watching the package")
            entries.append(_entry(fingerprint=finding.fingerprint, advisory=None, ecosystem=finding.ecosystem or "unknown",
                                  package=finding.package, version=finding.version, symbols=[], source="package"))
            continue
        record = lookups.get((ecosystem, finding.package, finding.version or ""))
        vulns = _matching_vulns(record.vulns, finding.cve) if record else []
        if not vulns:
            named = (finding.cve or "").strip()
            advisory = named if named and named.lower() != "unverified" else None
            entries.append(_entry(fingerprint=finding.fingerprint, advisory=advisory, ecosystem=ecosystem,
                                  package=finding.package, version=finding.version, symbols=[], source="package"))
            continue
        for vuln in vulns:
            symbols, source = keep(ecosystem, _osv_symbols(vuln, ecosystem, finding.package)), "osv"
            ghsa_id = _ghsa_id(vuln)
            if not symbols and ghsa_id:
                symbols, source = keep(ecosystem, github.symbols(ghsa_id, ecosystem, finding.package)), "ghsa"
            entries.append(_entry(fingerprint=finding.fingerprint, advisory=ghsa_id or vuln.get("id"),
                                  ecosystem=ecosystem, package=finding.package, version=finding.version,
                                  symbols=symbols, source=source))

    if unnormalised:
        notes.append(f"{unnormalised} advisory symbol(s) didn't fit their ecosystem's notation and were left out")
    if github.stopped_reason:
        notes.append(github.stopped_reason)
    entries.sort(key=lambda e: (e["finding_fingerprint"], e["advisory"] or ""))
    return {"version": WATCHLIST_VERSION, "generated_at": _now(), "entries": entries}, notes
