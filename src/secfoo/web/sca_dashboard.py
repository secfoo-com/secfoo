"""Computes the SCA Reachability activity page's extended dashboard:
coverage, a severity/reachability breakdown, an ecosystem breakdown, and a
cross-project vulnerability register — each row backed by a real OSV.dev
match when one exists, or the report's own "unverified" finding when it
doesn't. Never fabricates a CVE ID; that is the SCA skill's prompt-contract
rule, extended honestly here rather than worked around.

Derived fresh from report text and the osv_lookups cache on every request —
no persistent per-vulnerability lifecycle.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field

from secfoo import osv
from secfoo.report.sca import SKILL_ID
from secfoo.report.sca import (
    extract_cve_by_dependency_id,
    extract_narrative_by_dependency_id,
    extract_risk_register_rows,
    inventory_lookup,
    resolve_ecosystem,
)
from secfoo.storage.repository import RunRepository
from secfoo.web.dashboard_common import read_report

_read = read_report

_REACHABILITY_RANK = {"not reachable": 0, "conditionally reachable": 1, "reachable": 2}
_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def _vulnerability_key(ecosystem: str | None, package: str, version: str, cve_or_issue: str) -> str:
    """One opaque hashed routing key, whether or not a real OSV id exists
    -- package names aren't safe URL segments (scoped npm `@scope/pkg`,
    Maven groupIds, and Go module paths all contain literal "/"), so a
    composite path would either break routing or need per-consumer
    percent-encoding. Same (ecosystem, package, version, cve) always
    collapses to the same key across projects; two LLM-only "unverified"
    findings only collapse if their issue text actually matches -- there's
    no stable identity to merge unverified narratives by otherwise.
    """
    raw = f"{ecosystem or 'unknown'}|{package}|{version}|{cve_or_issue}"
    return hashlib.blake2b(raw.encode("utf-8"), digest_size=8).hexdigest()


@dataclass
class ScaVulnerability:
    key: str
    package: str
    version: str
    ecosystem_raw: str | None = None
    ecosystem_osv: str | None = None
    cve_id: str | None = None
    is_llm_reported: bool = True
    llm_cve_text: str | None = None
    issue: str = ""
    severity: str = ""
    reachability: str = ""
    fixed_in: str = ""
    osv_summary: str | None = None
    osv_published: str | None = None
    reachability_evidence: str | None = None
    recommendation: str | None = None
    affected_projects: list[dict] = field(default_factory=list)


@dataclass
class ScaDashboard:
    coverage_reviewed: int = 0
    coverage_in_scope: int = 0
    coverage_pct: float = 0.0
    severity_counts: dict[str, int] = field(default_factory=dict)
    reachability_counts: dict[str, int] = field(default_factory=dict)
    ecosystem_counts: list[tuple[str, int]] = field(default_factory=list)
    vulnerabilities: list[ScaVulnerability] = field(default_factory=list)
    vulnerabilities_by_key: dict[str, ScaVulnerability] = field(default_factory=dict)
    unmapped_ecosystem_count: int = 0
    osv_unreachable: bool = False


def _is_worse_reachability(candidate: str, current: str) -> bool:
    return _REACHABILITY_RANK.get(candidate.strip().lower(), -1) > _REACHABILITY_RANK.get(current.strip().lower(), -1)


def _is_worse_severity(candidate: str, current: str) -> bool:
    return _SEVERITY_RANK.get(candidate.strip().lower(), -1) > _SEVERITY_RANK.get(current.strip().lower(), -1)


def build(repo: RunRepository) -> ScaDashboard:
    dash = ScaDashboard()

    reviewed, in_scope = repo.architecture_coverage(SKILL_ID)
    dash.coverage_reviewed, dash.coverage_in_scope = reviewed, in_scope
    dash.coverage_pct = round(reviewed / in_scope * 100, 1) if in_scope else 0.0

    projects = repo.activity_summary_by_project(SKILL_ID)

    # Pass 1: collect every risk-register row across every project's latest
    # report, resolving each one's ecosystem by joining back against that
    # same report's Dependency Inventory table (Risk Register itself has
    # no Ecosystem column).
    raw_findings: list[dict] = []
    keys_to_enrich: set[tuple[str, str, str]] = set()
    unmapped_ecosystem_count = 0

    for project in projects:
        text = _read(project.get("latest_success_report_path"))
        if not text:
            continue

        inventory_by_package_version = inventory_lookup(text)
        cve_by_id = extract_cve_by_dependency_id(text)
        narrative_by_id = extract_narrative_by_dependency_id(text)

        for row in extract_risk_register_rows(text):
            package = row["package"].strip()
            version = row["version"].strip()
            ecosystem_raw, ecosystem_osv = resolve_ecosystem(package, version, inventory_by_package_version)
            if ecosystem_raw is None or ecosystem_osv is None:
                unmapped_ecosystem_count += 1
            if ecosystem_osv:
                keys_to_enrich.add((ecosystem_osv, package, version))

            raw_findings.append(
                {
                    "project_id": project["project_id"],
                    "project_display_name": project["project_display_name"],
                    "dependency_id": row["id"],
                    "package": package,
                    "version": version,
                    "issue": row["issue"].strip(),
                    "severity": row["severity"].strip(),
                    "reachability": row["reachability"].strip(),
                    "fixed_in": row["fixed_in"].strip(),
                    "ecosystem_raw": ecosystem_raw,
                    "ecosystem_osv": ecosystem_osv,
                    "llm_cve_text": cve_by_id.get(row["id"]),
                    "reachability_evidence": narrative_by_id.get(row["id"], {}).get("reachability_evidence"),
                    "recommendation": narrative_by_id.get(row["id"], {}).get("recommendation"),
                }
            )

    dash.unmapped_ecosystem_count = unmapped_ecosystem_count

    # Enrich (or top up) the OSV cache for everything this pass needs, then
    # read it back fresh -- enrich_lookups itself decides what's actually
    # missing/stale, so no need to duplicate that check here.
    dash.osv_unreachable = osv.enrich_lookups(repo, list(keys_to_enrich))
    lookup_map = repo.osv_lookup_map()

    # Pass 2: turn raw findings into deduplicated, cross-project
    # vulnerability rows.
    vulnerabilities: dict[str, ScaVulnerability] = {}

    for finding in raw_findings:
        cached = None
        if finding["ecosystem_osv"]:
            cached = lookup_map.get((finding["ecosystem_osv"], finding["package"], finding["version"]))
        osv_vulns = cached.vulns if cached else []

        # One OSV-matched entry per real vuln OSV returned for this exact
        # package+version (there can be several), or exactly one LLM-only
        # entry when there's no real match -- same finding, different
        # table rows, since each real CVE deserves its own identity.
        entries = (
            [(v.get("id"), v.get("summary") or v.get("details"), v.get("published")) for v in osv_vulns]
            if osv_vulns
            else [(None, None, None)]
        )

        for cve_id, osv_summary, osv_published in entries:
            key = _vulnerability_key(
                finding["ecosystem_osv"] or finding["ecosystem_raw"],
                finding["package"],
                finding["version"],
                cve_id or f"llm:{finding['issue']}",
            )
            vuln = vulnerabilities.get(key)
            if vuln is None:
                vuln = ScaVulnerability(
                    key=key,
                    package=finding["package"],
                    version=finding["version"],
                    ecosystem_raw=finding["ecosystem_raw"],
                    ecosystem_osv=finding["ecosystem_osv"],
                    cve_id=cve_id,
                    is_llm_reported=cve_id is None,
                    llm_cve_text=finding["llm_cve_text"],
                    issue=finding["issue"],
                    severity=finding["severity"],
                    reachability=finding["reachability"],
                    fixed_in=finding["fixed_in"],
                    osv_summary=osv_summary,
                    osv_published=osv_published,
                    reachability_evidence=finding["reachability_evidence"],
                    recommendation=finding["recommendation"],
                )
                vulnerabilities[key] = vuln
            else:
                # Row-level severity/reachability is the worst observed
                # across every project that hit this same vulnerability --
                # the true per-project values are never lost, they're
                # exactly what affected_projects (below) carries.
                if _is_worse_severity(finding["severity"], vuln.severity):
                    vuln.severity = finding["severity"]
                if _is_worse_reachability(finding["reachability"], vuln.reachability):
                    vuln.reachability = finding["reachability"]

            vuln.affected_projects.append(
                {
                    "project_id": finding["project_id"],
                    "project_display_name": finding["project_display_name"],
                    "dependency_id": finding["dependency_id"],
                    "severity": finding["severity"],
                    "reachability": finding["reachability"],
                    "fixed_in": finding["fixed_in"],
                }
            )

    dash.vulnerabilities = sorted(
        vulnerabilities.values(),
        key=lambda v: (-_SEVERITY_RANK.get(v.severity.strip().lower(), -1), v.package.lower()),
    )
    dash.vulnerabilities_by_key = vulnerabilities

    severity_counter: Counter[str] = Counter()
    reachability_counter: Counter[str] = Counter()
    ecosystem_counter: Counter[str] = Counter()
    for vuln in dash.vulnerabilities:
        if vuln.severity:
            severity_counter[vuln.severity] += 1
        if vuln.reachability:
            reachability_counter[vuln.reachability] += 1
        if vuln.ecosystem_raw:
            ecosystem_counter[vuln.ecosystem_raw] += 1

    dash.severity_counts = {
        "high": severity_counter.get("High", 0),
        "medium": severity_counter.get("Medium", 0),
        "low": severity_counter.get("Low", 0),
    }
    dash.reachability_counts = {
        "reachable": reachability_counter.get("Reachable", 0),
        "conditionally_reachable": reachability_counter.get("Conditionally reachable", 0),
        "not_reachable": reachability_counter.get("Not reachable", 0),
    }
    dash.ecosystem_counts = ecosystem_counter.most_common()

    return dash
