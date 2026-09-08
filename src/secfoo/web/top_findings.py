"""Computes the main dashboard's "Top Findings" panel: the highest-
severity items pulled from every specialized sub-dashboard this app has
(SAST, SCA, Third-Party vendor assessments, Secret Scanning, Security
Architecture exceptions, Threat Modeling gaps), normalized into one shape
and sorted together -- so landing on `/` answers "what actually needs my
attention right now across the whole program," not just per-activity
coverage percentages.

Deliberately read-only and best-effort per source: a source with nothing
urgent (or nothing run yet) simply contributes zero rows rather than
erroring, matching every other dashboard builder's "degrade gracefully"
discipline in this app.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from secfoo import cvss
from secfoo.report.architecture import _extract_section, extract_threat_register_rows
from secfoo.storage.repository import RunRepository
from secfoo.web import sast_dashboard, sca_dashboard, secret_scanning_dashboard, third_party_dashboard
from secfoo.web.dashboard_common import read_report

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Third-Party Risk Assessment's Findings Register:
# | ID | Finding | Severity | CCM Domain | Evidence |
_THIRD_PARTY_FINDING_ROW_RE = re.compile(
    r"^\|\s*(?P<id>V\d+)\s*\|(?P<finding>[^|]*)\|(?P<severity>[^|]*)\|"
    r"(?P<domain>[^|]*)\|(?P<evidence>[^|]*)\|\s*$",
    re.MULTILINE,
)

# Only urgent items belong on a cross-program "top findings" panel --
# medium/low findings still matter, but belong on their own activity's
# dashboard, not competing for space here.
_INCLUDED_SEVERITIES = {"critical", "high"}


@dataclass(frozen=True)
class TopFinding:
    source: str
    title: str
    project: str
    severity: str
    detail: str
    url: str


def _extract_third_party_findings(report_markdown: str) -> list[dict[str, str]]:
    section = _extract_section(report_markdown, "Findings")
    rows = []
    for match in _THIRD_PARTY_FINDING_ROW_RE.finditer(section):
        rows.append({key: value.strip() for key, value in match.groupdict().items()})
    return rows


def _sast_findings(repo: RunRepository) -> list[TopFinding]:
    dash = sast_dashboard.build(repo)
    results = []
    for f in dash.open_findings:
        band = cvss.rating(f.cvss_score) if f.cvss_score is not None else f.severity.strip().lower()
        if band not in _INCLUDED_SEVERITIES:
            continue
        detail = f"CVSS {f.cvss_score:.1f}" if f.cvss_score is not None else f.severity
        results.append(
            TopFinding(
                source="SAST",
                title=f.title,
                project=f.project_display_name or "-",
                severity=band,
                detail=detail,
                url=f"/activities/sast/findings/{f.fingerprint}",
            )
        )
    return results


def _sca_findings(repo: RunRepository) -> list[TopFinding]:
    dash = sca_dashboard.build(repo)
    results = []
    for v in dash.vulnerabilities:
        severity = v.severity.strip().lower()
        if severity not in _INCLUDED_SEVERITIES:
            continue
        project = v.affected_projects[0]["project_display_name"] if v.affected_projects else "-"
        if len(v.affected_projects) > 1:
            project += f" (+{len(v.affected_projects) - 1} more)"
        results.append(
            TopFinding(
                source="SCA",
                title=f"{v.cve_id or v.issue} in {v.package}",
                project=project,
                severity=severity,
                detail=v.cve_id or "unverified",
                url=f"/activities/sca-reachability/vulnerabilities/{v.key}",
            )
        )
    return results


def _third_party_findings(repo: RunRepository) -> list[TopFinding]:
    assessments = repo.list_assessments(assessment_type="third_party", limit=10_000)
    results = []
    for assessment in assessments:
        runs = repo.list_runs(
            assessment_id=assessment.id, skill_id=third_party_dashboard.SKILL_ID, status="success", limit=1
        )
        if not runs or not runs[0].report_path:
            continue
        text = read_report(runs[0].report_path)
        if not text:
            continue
        for row in _extract_third_party_findings(text):
            severity = row["severity"].strip().lower()
            if severity not in _INCLUDED_SEVERITIES:
                continue
            results.append(
                TopFinding(
                    source="Third-Party",
                    title=row["finding"],
                    project=assessment.project_display_name or "-",
                    severity=severity,
                    detail=f"CCM: {row['domain']}",
                    url=f"/assessments/{assessment.id}",
                )
            )
    return results


def _secret_scanning_findings(repo: RunRepository) -> list[TopFinding]:
    dash = secret_scanning_dashboard.build(repo)
    results = []
    for f in dash.findings:
        severity = f.severity.strip().lower()
        if severity not in _INCLUDED_SEVERITIES:
            continue
        detail = f.validity if f.validity.strip().lower() == "looks live" else f.source
        results.append(
            TopFinding(
                source="Secret Scanning",
                title=f"{f.secret_type} in {f.location}",
                project=f.project_display_name,
                severity=severity,
                detail=detail,
                url=f"/activities/secret-scanning/findings/{f.key}",
            )
        )
    return results


def _architecture_findings(repo: RunRepository) -> list[TopFinding]:
    now = datetime.now(timezone.utc)
    results = []
    for exception in repo.list_exceptions(status="active"):
        try:
            expires = datetime.fromisoformat(exception.expires_at)
        except ValueError:
            continue
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires >= now:
            continue
        results.append(
            TopFinding(
                source="Architecture",
                title=f"Exception past due: {exception.title}",
                project=exception.project_display_name or "-",
                severity="high",
                detail=f"Expired {exception.expires_at[:10]}",
                url=f"/projects/{exception.project_id}",
            )
        )
    return results


def _threat_modeling_findings(repo: RunRepository) -> list[TopFinding]:
    results = []
    for project in repo.activity_summary_by_project("threat-modeling"):
        text = read_report(project.get("latest_success_report_path"))
        if not text:
            continue
        for row in extract_threat_register_rows(text):
            severity = row["severity"].strip().lower()
            if severity not in _INCLUDED_SEVERITIES or row["disposition"].strip().lower() != "gap":
                continue
            results.append(
                TopFinding(
                    source="Threat Modeling",
                    title=row["threat"],
                    project=project["project_display_name"],
                    severity=severity,
                    detail=f"STRIDE: {row['stride']}",
                    url=f"/runs/{project['latest_run_uuid']}" if project.get("latest_run_uuid") else "/activities/threat-modeling",
                )
            )
    return results


def build_top_findings(repo: RunRepository, *, limit: int = 15) -> list[TopFinding]:
    findings = [
        *_sast_findings(repo),
        *_sca_findings(repo),
        *_third_party_findings(repo),
        *_secret_scanning_findings(repo),
        *_architecture_findings(repo),
        *_threat_modeling_findings(repo),
    ]
    findings.sort(key=lambda f: _SEVERITY_RANK.get(f.severity, 0), reverse=True)
    return findings[:limit]
