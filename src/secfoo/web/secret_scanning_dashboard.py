"""Computes the Secret Scanning activity page's extended dashboard: a
findings funnel (emphasizing "Looks live" as the most urgent bucket),
a severity breakdown, a source breakdown (code/config/history/docs), and
the full findings register across every project.

Recomputed fresh from report text on every request — no persistent
per-finding lifecycle (unlike SAST's sast_findings table).
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field

from secfoo.report.secret_scanning import SKILL_ID, findings_with_narrative
from secfoo.storage.repository import RunRepository
from secfoo.web.dashboard_common import read_report

_read = read_report

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2}


def _strip_inline_code(value: str) -> str:
    """Remove Markdown backticks from a table cell value."""
    value = value.strip()
    if len(value) >= 2 and value[0] == "`" and value[-1] == "`":
        return value[1:-1]
    return value


def _key(project_id: int, finding_id: str, secret_type: str, location: str) -> str:
    """Opaque hashed routing key — stable within a request, not persisted."""
    raw = f"{project_id}|{finding_id}|{secret_type}|{location}"
    return hashlib.blake2b(raw.encode("utf-8"), digest_size=8).hexdigest()


@dataclass
class SecretFinding:
    key: str
    finding_id: str
    project_id: int
    project_display_name: str
    secret_type: str
    location: str
    source: str
    validity: str
    severity: str
    evidence: str = ""
    exposure: str = ""
    remediation: str = ""


@dataclass
class SecretScanningDashboard:
    total: int = 0
    looks_live_count: int = 0
    history_count: int = 0
    docs_count: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    source_counts: dict[str, int] = field(default_factory=dict)
    findings: list[SecretFinding] = field(default_factory=list)
    findings_by_key: dict[str, SecretFinding] = field(default_factory=dict)


def build(repo: RunRepository) -> SecretScanningDashboard:
    dash = SecretScanningDashboard()
    projects = repo.activity_summary_by_project(SKILL_ID)

    findings: list[SecretFinding] = []
    for project in projects:
        text = _read(project.get("latest_success_report_path"))
        if not text:
            continue
        for row in findings_with_narrative(text):
            location = _strip_inline_code(row["location"])
            finding = SecretFinding(
                key=_key(project["project_id"], row["id"], row["secret_type"], location),
                finding_id=row["id"],
                project_id=project["project_id"],
                project_display_name=project["project_display_name"],
                secret_type=row["secret_type"],
                location=location,
                source=row["source"],
                validity=row["validity"],
                severity=row["severity"],
                evidence=row["evidence"],
                exposure=row["exposure"],
                remediation=row["remediation"],
            )
            findings.append(finding)

    findings.sort(key=lambda f: _SEVERITY_RANK.get(f.severity.strip().lower(), -1), reverse=True)
    dash.findings = findings
    dash.findings_by_key = {f.key: f for f in findings}
    dash.total = len(findings)

    severity_counter: Counter[str] = Counter()
    source_counter: Counter[str] = Counter()
    validity_counter: Counter[str] = Counter()
    for f in findings:
        if f.severity:
            severity_counter[f.severity.strip().lower()] += 1
        if f.source:
            source_counter[f.source.strip().lower()] += 1
        if f.validity:
            validity_counter[f.validity.strip().lower()] += 1

    # High/Medium/Low only — matches the skill contract and _SCA_SEVERITY_COLORS.
    dash.severity_counts = {
        "high": severity_counter.get("high", 0),
        "medium": severity_counter.get("medium", 0),
        "low": severity_counter.get("low", 0),
    }
    dash.source_counts = {
        "code": source_counter.get("code", 0),
        "config": source_counter.get("config", 0),
        "history": source_counter.get("history", 0),
        "docs": source_counter.get("docs", 0),
    }
    dash.looks_live_count = validity_counter.get("looks live", 0)
    dash.history_count = dash.source_counts["history"]
    dash.docs_count = dash.source_counts["docs"]

    return dash
