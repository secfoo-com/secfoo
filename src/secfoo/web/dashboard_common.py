"""Shared helpers between the Security Architecture and Threat Modeling
program dashboards -- both need to read a run's report file and detect
when a project's trust boundaries changed between its two most recent
reviews.
"""

from __future__ import annotations

from pathlib import Path

from secfoo.report.architecture import count_trust_boundaries
from secfoo.storage.repository import RunRepository


def percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(pct / 100 * (len(ordered) - 1))))
    return ordered[index]


def read_report(path: str | None) -> str:
    if not path:
        return ""
    file = Path(path)
    if not file.is_file():
        return ""
    return file.read_text()


def append_boundary_changed_projects(
    repo: RunRepository, skill_id: str, projects: list[dict], stale_projects: list[dict]
) -> None:
    """Flags a project whose two most recent runs of `skill_id` show a
    different trust-boundary count as needing rework, even though it was
    reviewed recently enough to not already be flagged stale by age. A
    changed boundary count is the one structural-change signal actually
    derivable from report text -- it stands in for the broader "boundary
    moved / new integration / design changed" triggers a real program
    would also track by hand. Mutates `stale_projects` in place.
    """
    already_flagged = {p["project_id"] for p in stale_projects}
    for project in projects:
        if project["project_id"] in already_flagged:
            continue
        recent_runs = repo.list_runs(
            project_id=project["project_id"], skill_id=skill_id, status="success", limit=2
        )
        if len(recent_runs) < 2:
            continue
        latest_text = read_report(recent_runs[0].report_path)
        prev_text = read_report(recent_runs[1].report_path)
        if not latest_text or not prev_text:
            continue
        if count_trust_boundaries(latest_text) != count_trust_boundaries(prev_text):
            stale_projects.append(
                {
                    "project_id": project["project_id"],
                    "project_display_name": project["project_display_name"],
                    "project_kind": project["project_kind"],
                    "state": "boundary_changed",
                    "last_reviewed_at": project.get("latest_started_at"),
                    "days_since_review": None,
                }
            )
