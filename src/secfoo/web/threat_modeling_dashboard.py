"""Computes the Threat Modeling activity page's extended dashboard:
coverage, models needing rework, a per-project STRIDE x asset-class
coverage matrix, threat disposition (including tested-vs-untested
mitigations), recorded risk acceptances, recurring threat archetypes,
model-depth mix, and post-build misses.

Same ground rules as architecture_dashboard.py: no persistent per-threat
lifecycle and no separate system registry were introduced. Everything here
is derived fresh from report text each request, from run history, and from
the post_build_findings / threat_acceptances tables (the two things
genuinely un-derivable from a report -- a model can't know what it missed,
and a report's own "Accepted" disposition carries no named human owner).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from secfoo.report.architecture import (
    extract_falsified_assumptions,
    extract_model_depth,
    extract_threat_register_rows,
)
from secfoo.storage.repository import RunRepository
from secfoo.web.dashboard_common import append_boundary_changed_projects, percentile, read_report

SKILL_ID = "threat-modeling"

# A Gap-disposition threat is "past due" once its most recent model is
# older than this -- the same coarse, run-level proxy used for the
# Security Architecture dashboard's "past due" tile, for the same reason
# (no per-threat due date exists).
PAST_DUE_SLA_DAYS = 30

# A project is "stale" if its most recent successful model predates this.
STALE_DAYS = 365

# How far back "threats found post-build" counts as a recent trend signal,
# vs. the all-time total.
POST_BUILD_TREND_WINDOW_DAYS = 90

ASSET_CLASSES = ["External Entity", "Process", "Data Store", "Data Flow", "Model/Agent"]
STRIDE_LETTERS = ["S", "T", "R", "I", "D", "E"]

_read = read_report


def _empty_stride_counts() -> dict[tuple[str, str], int]:
    return {(asset_class, letter): 0 for asset_class in ASSET_CLASSES for letter in STRIDE_LETTERS}


def _stride_matrix_from_counts(counts: dict[tuple[str, str], int]) -> list[dict]:
    return [
        {
            "asset_class": asset_class,
            "cells": {letter: counts[(asset_class, letter)] for letter in STRIDE_LETTERS},
            "total": sum(counts[(asset_class, letter)] for letter in STRIDE_LETTERS),
        }
        for asset_class in ASSET_CLASSES
    ]


@dataclass
class ThreatModelingDashboard:
    coverage_reviewed: int = 0
    coverage_in_scope: int = 0
    coverage_pct: float = 0.0
    open_threats_past_due: int = 0
    mitigated_untested: int = 0
    median_threats_per_model: float | None = None
    stride_aggregate: list[dict] = field(default_factory=list)
    stride_by_project: list[dict] = field(default_factory=list)
    disposition: dict[str, int] = field(default_factory=dict)
    disposition_total: int = 0
    accepted_threats: list[dict] = field(default_factory=list)
    needs_rework: list[dict] = field(default_factory=list)
    recurring_patterns: list[tuple[str, int]] = field(default_factory=list)
    model_depth_mix: dict[str, int] = field(default_factory=dict)
    post_build_count_total: int = 0
    post_build_count_recent: int = 0
    post_build_recent: list = field(default_factory=list)
    falsified_assumptions: list[str] = field(default_factory=list)


def build(repo: RunRepository) -> ThreatModelingDashboard:
    dash = ThreatModelingDashboard()

    reviewed, in_scope = repo.architecture_coverage(SKILL_ID)
    dash.coverage_reviewed, dash.coverage_in_scope = reviewed, in_scope
    dash.coverage_pct = round(reviewed / in_scope * 100, 1) if in_scope else 0.0

    projects = repo.activity_summary_by_project(SKILL_ID)
    now = datetime.now(timezone.utc)

    mitigated_tested = 0
    mitigated_untested = 0
    open_not_past_due = 0
    past_due = 0
    accepted_total = 0
    transferred_total = 0
    accepted_threats: list[dict] = []
    depth_counter: Counter[str] = Counter()
    threats_per_model: list[float] = []
    falsified: list[str] = []
    stride_by_project: list[dict] = []
    aggregate_stride_counts = _empty_stride_counts()

    for project in projects:
        text = _read(project.get("latest_success_report_path"))
        if not text:
            continue

        rows = extract_threat_register_rows(text)
        threats_per_model.append(len(rows))

        is_past_due_age = False
        started = project.get("latest_started_at")
        if started:
            try:
                started_dt = datetime.fromisoformat(started)
            except ValueError:
                started_dt = None
            if started_dt is not None:
                if started_dt.tzinfo is None:
                    started_dt = started_dt.replace(tzinfo=timezone.utc)
                is_past_due_age = (now - started_dt).days > PAST_DUE_SLA_DAYS

        depth = extract_model_depth(text)
        if depth:
            depth_counter[depth] += 1

        falsified.extend(extract_falsified_assumptions(text))

        # Both a per-project matrix (a blank cell is a real gap on that
        # specific system) and a running portfolio total (the same cell,
        # summed across every project -- a fast glance at overall volume,
        # at the cost of not saying which project it came from).
        project_stride_counts = _empty_stride_counts()

        for row in rows:
            asset_class = row["asset_class"]
            if asset_class in ASSET_CLASSES:
                for letter in row["stride"].upper():
                    if letter in STRIDE_LETTERS:
                        project_stride_counts[(asset_class, letter)] += 1
                        aggregate_stride_counts[(asset_class, letter)] += 1

            disposition = row["disposition"].strip().lower()
            test_reference = row["test_reference"].strip().lower()

            if disposition == "mitigated":
                if test_reference in ("", "none", "n/a"):
                    mitigated_untested += 1
                else:
                    mitigated_tested += 1
            elif disposition == "gap":
                if is_past_due_age:
                    past_due += 1
                else:
                    open_not_past_due += 1
            elif disposition == "accepted":
                accepted_total += 1
                accepted_threats.append(
                    {
                        "project_id": project["project_id"],
                        "project": project["project_display_name"],
                        "threat_ref": row["id"],
                        "threat": row["threat"],
                    }
                )
            elif disposition == "transferred":
                transferred_total += 1

        stride_by_project.append(
            {
                "project_id": project["project_id"],
                "project_display_name": project["project_display_name"],
                "matrix": _stride_matrix_from_counts(project_stride_counts),
                "threat_count": len(rows),
            }
        )

    dash.open_threats_past_due = past_due
    dash.mitigated_untested = mitigated_untested
    dash.median_threats_per_model = percentile(threats_per_model, 50) if threats_per_model else None

    dash.disposition = {
        "mitigated_tested": mitigated_tested,
        "mitigated_untested": mitigated_untested,
        "accepted": accepted_total,
        "transferred": transferred_total,
        "open": open_not_past_due,
        "past_due": past_due,
    }
    dash.disposition_total = sum(dash.disposition.values())
    dash.stride_aggregate = _stride_matrix_from_counts(aggregate_stride_counts)
    dash.stride_by_project = stride_by_project

    # One table, not two: the report's own "Accepted" disposition carries
    # no named human owner, and `secfoo accept` is how that owner actually
    # gets recorded -- match the two by (project, threat ID) so each row
    # shows either a real owner or a plain "not recorded" gap to close,
    # instead of two disjoint lists a reader has to cross-reference by eye.
    recorded = repo.list_threat_acceptances(status="active", limit=200)
    recorded_by_key = {(r.project_id, r.threat_ref): r for r in recorded}
    matched_keys: set[tuple[int, str]] = set()

    merged_accepted: list[dict] = []
    for entry in accepted_threats:
        key = (entry["project_id"], entry["threat_ref"])
        record = recorded_by_key.get(key)
        if record:
            matched_keys.add(key)
        merged_accepted.append(
            {
                "project": entry["project"],
                "threat_ref": entry["threat_ref"],
                "threat": entry["threat"],
                "accepted_by": record.accepted_by if record else None,
            }
        )
    # A recorded acceptance whose threat no longer shows up as "Accepted" in
    # the latest report (older run, or the model's next pass changed its
    # mind) is still a real human decision -- keep it visible rather than
    # silently dropping it once the report text moves on.
    for record in recorded:
        key = (record.project_id, record.threat_ref)
        if key in matched_keys:
            continue
        merged_accepted.append(
            {
                "project": record.project_display_name,
                "threat_ref": record.threat_ref,
                "threat": record.title,
                "accepted_by": record.accepted_by,
            }
        )
    dash.accepted_threats = merged_accepted

    dash.model_depth_mix = {
        "full": depth_counter.get("Full", 0),
        "feature_level": depth_counter.get("Feature-level", 0),
        "lightweight": depth_counter.get("Lightweight", 0),
    }
    dash.falsified_assumptions = falsified

    # Recurring archetypes are aggregated across ALL successful runs, not
    # just the latest per project -- a pattern recurring over a project's
    # own history is exactly as platform-relevant as one recurring across
    # different projects.
    archetype_counter: Counter[str] = Counter()
    for run in repo.list_runs(skill_id=SKILL_ID, status="success", limit=500):
        text = _read(run.report_path)
        if not text:
            continue
        for row in extract_threat_register_rows(text):
            if row["archetype"]:
                archetype_counter[row["archetype"]] += 1
    dash.recurring_patterns = archetype_counter.most_common(8)

    dash.post_build_count_total = repo.post_build_findings_count()
    dash.post_build_count_recent = repo.post_build_findings_count(since_days=POST_BUILD_TREND_WINDOW_DAYS)
    dash.post_build_recent = repo.list_post_build_findings(limit=5)

    needs_rework = repo.unreviewed_and_stale_projects(SKILL_ID, stale_days=STALE_DAYS)
    append_boundary_changed_projects(repo, SKILL_ID, projects, needs_rework)

    # No criticality field exists (no separate system registry -- same
    # product decision as the Security Architecture dashboard), so total
    # findings is the best available proxy for "sort by business
    # criticality": a project with more open severity is more likely to
    # matter more, even though it isn't a true criticality ranking.
    findings_by_project = {
        p["project_id"]: p["critical_count"] + p["high_count"] + p["medium_count"] + p["low_count"]
        for p in projects
    }
    needs_rework.sort(key=lambda r: -findings_by_project.get(r["project_id"], 0))
    dash.needs_rework = needs_rework

    return dash
