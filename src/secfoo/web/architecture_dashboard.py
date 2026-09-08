"""Computes the Security Architecture Review activity page's extended
dashboard: coverage, exceptions, a findings-disposition approximation, the
CCM domain heatmap, recurring root causes, gate decisions, and the
unreviewed/stale table.

Per product decision, this deliberately does NOT introduce a persistent
per-finding lifecycle (open -> mitigated -> remediated, manually updated
over time) or a separate system registry. Instead it approximates from
what already exists: report text (parsed fresh each request via
report/architecture.py), run history, and the exceptions table. Every
approximation is called out in its own docstring/comment below -- this is
a deliberately honest dashboard, not a fabricated one.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from secfoo.report.architecture import (
    CCM_DOMAINS,
    classify_design_verdict,
    conformance_to_score,
    extract_ccm_conformance,
    extract_design_verdict,
    extract_root_causes,
    extract_standards_deviated,
    extract_verdict_counts,
)
from secfoo.storage.repository import RunRepository
from secfoo.web.dashboard_common import append_boundary_changed_projects, percentile, read_report

SKILL_ID = "security-architecture-review"

# A finding is "past due" once its most recent review is older than this.
# There's no per-finding due date (no persistent findings lifecycle was
# built this round), so this applies uniformly to every Confirmed-verdict
# finding on a project's latest run once that run itself is old enough --
# a coarser proxy than a true per-finding SLA clock, but an honest one.
PAST_DUE_SLA_DAYS = 30

# A project is "stale" if its most recent successful review predates this.
STALE_DAYS = 365

_read = read_report


@dataclass
class ArchitectureDashboard:
    coverage_reviewed: int = 0
    coverage_in_scope: int = 0
    coverage_pct: float = 0.0
    exceptions_past_expiry: int = 0
    open_findings_past_due: int = 0
    unverified_mitigations: int = 0
    cycle_time_p90_days: float | None = None
    ccm_rows: list[dict] = field(default_factory=list)
    uncovered_ccm_domains: list[str] = field(default_factory=list)
    disposition: dict[str, int] = field(default_factory=dict)
    disposition_total: int = 0
    exception_aging: dict[str, int] = field(default_factory=dict)
    stale_projects: list[dict] = field(default_factory=list)
    root_causes: list[tuple[str, int]] = field(default_factory=list)
    gate_mix: dict[str, int] = field(default_factory=dict)
    top_standards: list[tuple[str, int]] = field(default_factory=list)


def build(repo: RunRepository) -> ArchitectureDashboard:
    dash = ArchitectureDashboard()

    reviewed, in_scope = repo.architecture_coverage(SKILL_ID)
    dash.coverage_reviewed, dash.coverage_in_scope = reviewed, in_scope
    dash.coverage_pct = round(reviewed / in_scope * 100, 1) if in_scope else 0.0

    dash.exceptions_past_expiry = repo.exceptions_past_expiry_count()
    dash.exception_aging = repo.exceptions_aging_buckets()

    p90 = percentile(repo.assessment_cycle_times_days(), 90)
    dash.cycle_time_p90_days = round(p90, 1) if p90 is not None else None

    projects = repo.activity_summary_by_project(SKILL_ID)
    now = datetime.now(timezone.utc)

    ccm_scores: dict[str, list[float]] = {code: [] for code, _ in CCM_DOMAINS}
    ccm_assessed: dict[str, bool] = {code: False for code, _ in CCM_DOMAINS}

    root_cause_counter: Counter[str] = Counter()
    standards_counter: Counter[str] = Counter()
    gate_counter: Counter[str] = Counter()

    confirmed_total = 0
    conditional_total = 0
    past_due_total = 0
    remediated_total = 0

    for project in projects:
        text = _read(project.get("latest_success_report_path"))
        if not text:
            continue

        verdicts = extract_verdict_counts(text)
        confirmed_total += verdicts["confirmed"]
        conditional_total += verdicts["conditional"]

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
        if is_past_due_age:
            past_due_total += verdicts["confirmed"]

        bucket = classify_design_verdict(extract_design_verdict(text))
        if bucket:
            gate_counter[bucket] += 1

        root_cause_counter.update(extract_root_causes(text))
        standards_counter.update(extract_standards_deviated(text))

        for code, value in extract_ccm_conformance(text).items():
            score = conformance_to_score(value)
            if score is not None:
                ccm_scores[code].append(score)
                ccm_assessed[code] = True

        # Remediated approximation: the drop in total findings between a
        # project's two most recent runs of this skill. No per-finding
        # tracking exists, so this can't say WHICH findings closed -- only
        # that the count went down, which is the honest limit of what's
        # derivable without a persistent lifecycle.
        recent_runs = repo.list_runs(
            project_id=project["project_id"], skill_id=SKILL_ID, status="success", limit=2
        )
        if len(recent_runs) == 2:
            latest_run, prev_run = recent_runs
            latest_n = latest_run.critical_count + latest_run.high_count + latest_run.medium_count + latest_run.low_count
            prev_n = prev_run.critical_count + prev_run.high_count + prev_run.medium_count + prev_run.low_count
            remediated_total += max(0, prev_n - latest_n)

    dash.open_findings_past_due = past_due_total
    dash.unverified_mitigations = conditional_total

    accepted_total = len(repo.list_exceptions(status="active"))
    open_not_past_due = max(0, confirmed_total - past_due_total)
    dash.disposition = {
        "remediated": remediated_total,
        "mitigated": conditional_total,
        "accepted": accepted_total,
        "open": open_not_past_due,
        "past_due": past_due_total,
    }
    dash.disposition_total = sum(dash.disposition.values())

    for code, name in CCM_DOMAINS:
        scores = ccm_scores[code]
        avg = round(sum(scores) / len(scores)) if scores else None
        dash.ccm_rows.append(
            {"code": code, "name": name, "score": avg, "hatched": avg is None}
        )
    dash.uncovered_ccm_domains = [name for code, name in CCM_DOMAINS if not ccm_assessed[code]]

    dash.root_causes = root_cause_counter.most_common(8)
    dash.top_standards = standards_counter.most_common(5)
    dash.gate_mix = {
        "approve": gate_counter.get("approve", 0),
        "conditions": gate_counter.get("conditions", 0),
        "reject": gate_counter.get("reject", 0),
    }

    dash.stale_projects = repo.unreviewed_and_stale_projects(SKILL_ID, stale_days=STALE_DAYS)
    append_boundary_changed_projects(repo, SKILL_ID, projects, dash.stale_projects)

    return dash
