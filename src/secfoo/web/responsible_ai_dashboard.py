"""Builds the Responsible AI program dashboard data (#131).

The only persisted Responsible AI data is a per-run snapshot of the
report's own structures (`rai_dimensions`, `rai_findings`). This builder
reads the newest successful run for each project and turns those rows into
the four questions the program page answers: which dimension is failing,
for which system, at what stakes, and under which framework. Reports from
before the contract (no structured rows) are parsed once here as a
fallback, so upgrading never blanks an existing dashboard.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from secfoo.report.responsible_ai import (
    DIMENSIONS,
    SKILL_ID,
    AIProfile,
    ai_bom_diff,
    parse_responsible_ai_report,
)
from secfoo.storage.repository import RunRepository
from secfoo.web.dashboard_common import read_report

# Worst status wins when more than one row exists for a project/dimension.
STATUS_RANK = {"adequate": 0, "not applicable": 1, "partial": 2, "missing": 3}


@dataclass
class ResponsibleAiDashboard:
    coverage_reviewed: int = 0
    coverage_in_scope: int = 0
    coverage_pct: float = 0.0
    systems: list[dict] = field(default_factory=list)
    dimension_rows: list[dict] = field(default_factory=list)
    heatmap: list[dict] = field(default_factory=list)
    findings_by_dimension: dict[str, list[dict]] = field(default_factory=dict)
    finding_count: int = 0
    framework_rows: list[dict] = field(default_factory=list)
    stakes_rows: list[dict] = field(default_factory=list)
    bom_diff_rows: list[dict] = field(default_factory=list)
    missing_dimensions: list[str] = field(default_factory=list)
    unparsable_reports: list[str] = field(default_factory=list)


def _profile_from_json(raw: str) -> AIProfile:
    try:
        data = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return AIProfile()
    if not isinstance(data, dict):
        return AIProfile()
    return AIProfile(
        models=tuple(str(name) for name in data.get("models", [])),
        providers=tuple(str(name) for name in data.get("providers", [])),
        decides=str(data.get("decides") or ""),
        affected=str(data.get("affected") or ""),
        stakes_tier=str(data.get("stakes_tier") or ""),
    )


def _rows_from_report(project: dict, text: str) -> list[dict]:
    """Legacy fallback: re-derive dimension rows from a stored report that
    predates the structured contract. Kept deliberately separate from the
    persisted path so new reports always win.
    """
    parsed = parse_responsible_ai_report(text)
    rows = []
    for dimension in parsed.dimensions:
        rows.append(
            {
                "dimension": dimension.dimension,
                "status": dimension.status,
                "evidence": dimension.evidence,
                "finding_ids": json.dumps(list(dimension.finding_ids)),
                "stakes_tier": parsed.profile.stakes_tier,
                "profile_json": json.dumps(parsed.profile.as_dict()),
                "project_id": project["project_id"],
                "project_display_name": project["project_display_name"],
                "assessment_id": project.get("latest_assessment_id"),
                "run_uuid": project.get("latest_success_run_uuid"),
                "overall_rating": parsed.overall_rating,
                "report_path": project.get("latest_success_report_path"),
            }
        )
    return rows


def build(repo: RunRepository) -> ResponsibleAiDashboard:
    dash = ResponsibleAiDashboard()
    reviewed, in_scope = repo.architecture_coverage(SKILL_ID)
    dash.coverage_reviewed, dash.coverage_in_scope = reviewed, in_scope
    dash.coverage_pct = round(reviewed / in_scope * 100, 1) if in_scope else 0.0

    projects = repo.activity_summary_by_project(SKILL_ID)
    dimension_rows = repo.responsible_ai_dimensions()
    findings = repo.responsible_ai_findings()
    stored_project_ids = {row["project_id"] for row in dimension_rows}

    for project in projects:
        if project["project_id"] in stored_project_ids:
            continue
        text = read_report(project.get("latest_success_report_path"), errors=dash.unparsable_reports)
        if not text:
            continue
        legacy_rows = _rows_from_report(project, text)
        if legacy_rows:
            dimension_rows.extend(legacy_rows)
            stored_project_ids.add(project["project_id"])
            # The legacy path has no persisted findings; read them from the
            # same report so the dimension view still has real rows.
            parsed = parse_responsible_ai_report(text)
            for finding in parsed.findings:
                findings.append(
                    {
                        "finding_ref": finding.finding_id,
                        "title": finding.title,
                        "severity": finding.severity,
                        "dimension": finding.dimension,
                        "framework": finding.framework,
                        "stakes": finding.stakes,
                        "description": finding.description,
                        "recommendation": finding.recommendation,
                        "project_id": project["project_id"],
                        "project_display_name": project["project_display_name"],
                        "assessment_id": project.get("latest_assessment_id"),
                        "run_uuid": project.get("latest_success_run_uuid"),
                        "report_path": project.get("latest_success_report_path"),
                    }
                )

    # Templates must not have to know that finding_ids is stored as JSON.
    for row in dimension_rows:
        raw_ids = row.get("finding_ids") or "[]"
        try:
            ids = json.loads(raw_ids)
        except (TypeError, ValueError):
            ids = []
        row["finding_id_list"] = [str(value) for value in ids] if isinstance(ids, list) else []
    dash.dimension_rows = dimension_rows

    # One row per system (the newest successful run's profile), not one per
    # dimension row -- the latter would repeat the same stakes seven times.
    by_project: dict[int, dict] = {}
    for row in dimension_rows:
        project_id = row["project_id"]
        if project_id not in by_project:
            profile = _profile_from_json(row.get("profile_json") or "")
            by_project[project_id] = {
                "project_id": project_id,
                "project_display_name": row.get("project_display_name") or str(project_id),
                "assessment_id": row.get("assessment_id"),
                "run_uuid": row.get("run_uuid"),
                "report_path": row.get("report_path"),
                "overall_rating": row.get("overall_rating"),
                "stakes_tier": profile.stakes_tier or row.get("stakes_tier") or "",
                "models": profile.models,
                "providers": profile.providers,
                "decides": profile.decides,
                "affected": profile.affected,
                "dimension_count": 0,
                "missing_count": 0,
            }
        system = by_project[project_id]
        system["dimension_count"] += 1
        if row["status"] == "missing":
            system["missing_count"] += 1
    dash.systems = sorted(by_project.values(), key=lambda row: row["project_display_name"].lower())

    # Dimension x project heat map. Cells carry the worst status seen for
    # that system/dimension; a "--" cell means the report didn't cover it.
    statuses: dict[tuple[int, str], str] = {}
    for row in dimension_rows:
        key = (row["project_id"], row["dimension"])
        previous = statuses.get(key)
        if previous is None or STATUS_RANK.get(row["status"], 0) > STATUS_RANK.get(previous, 0):
            statuses[key] = row["status"]
    dash.heatmap = [
        {
            "dimension": dimension,
            "cells": [
                {
                    "project_id": system["project_id"],
                    "project_display_name": system["project_display_name"],
                    "status": statuses.get((system["project_id"], dimension), ""),
                }
                for system in dash.systems
            ],
        }
        for dimension in DIMENSIONS
    ]
    dash.missing_dimensions = [
        dimension
        for dimension in DIMENSIONS
        if not any(statuses.get((system["project_id"], dimension)) for system in dash.systems)
    ]

    grouped: dict[str, list[dict]] = defaultdict(list)
    framework_counter: Counter[str] = Counter()
    stakes_counter: Counter[str] = Counter()
    for finding in findings:
        dimension = finding.get("dimension") or "Unspecified dimension"
        grouped[dimension].append(finding)
        framework = (finding.get("framework") or "").strip()
        if framework and framework.lower() not in {"--", "n/a", "none"}:
            framework_counter[framework] += 1
        stakes = (finding.get("stakes") or "").strip().lower()
        if stakes in {"high", "moderate", "low"}:
            stakes_counter[stakes] += 1
    dash.findings_by_dimension = dict(grouped)
    dash.finding_count = sum(len(rows) for rows in grouped.values())
    dash.framework_rows = [
        {"framework": name, "count": count} for name, count in framework_counter.most_common()
    ]
    dash.stakes_rows = [
        {"stakes": tier, "count": stakes_counter.get(tier, 0)}
        for tier in ("high", "moderate", "low")
    ]

    # Code-vs-AI-BOM diff, shown once per system that actually has a BOM.
    for system in dash.systems:
        if not system["assessment_id"]:
            continue
        items = repo.list_ai_bom_items(system["assessment_id"])
        if not items:
            continue
        diff = ai_bom_diff(AIProfile(models=tuple(system["models"])), items)
        if diff["code_only"] or diff["bom_only"]:
            dash.bom_diff_rows.append({"system": system["project_display_name"], **diff})

    return dash
