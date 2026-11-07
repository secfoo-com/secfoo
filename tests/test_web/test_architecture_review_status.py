"""Security Architecture page: the "Unreviewed & stale" panel shows only the
five most recently active projects, and every project's review status is
the last column of the "By project" table."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from secfoo.storage.repository import RunRepository
from secfoo.web.app import create_app

SKILL = "security-architecture-review"
REPORT = "# Security Architecture Review Report\n\n**Design verdict:** Sound\n"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    return TestClient(create_app())


def _project(repo: RunRepository, name: str, last_run_at: str) -> int:
    project_id = repo.upsert_project(f"https://github.com/{name}", name, "github")
    repo.create_assessment(project_id=project_id, assessment_type="internal", status="in_progress")
    repo._conn.execute("UPDATE projects SET last_run_at = ? WHERE id = ?", (last_run_at, project_id))
    repo._conn.commit()
    return project_id


def _run(repo: RunRepository, tmp_path, project_id: int, *, status: str, started_at: str) -> None:
    run_uuid = repo.create_run(project_id=project_id, skill_id=SKILL, skill_name="Security Architecture Review",
                               agent_id="claude", confluence_urls=[])
    path = tmp_path / f"{run_uuid}.md"
    path.write_text(REPORT)
    repo.complete_run(run_uuid, status=status, exit_code=0 if status == "success" else 1, duration_seconds=1.0,
                      report_path=str(path) if status == "success" else None, prompt_path=None, stderr_excerpt=None)
    repo._conn.execute("UPDATE runs SET started_at = ? WHERE run_uuid = ?", (started_at, run_uuid))
    repo._conn.commit()


def _section(html: str, start: str, end: str) -> str:
    i = html.index(start)
    return html[i:html.index(end, i)]


def test_stale_panel_shows_the_five_most_recently_active(client):
    repo = RunRepository()
    for day in range(1, 8):  # seven never-reviewed projects, last active on days 1..7
        _project(repo, f"acme/svc-{day}", f"2026-11-0{day}T09:00:00+00:00")
    repo.close()

    html = client.get(f"/activities/{SKILL}").text
    panel = _section(html, "Unreviewed &amp; stale", "</table>")
    assert re.findall(r"acme/svc-(\d)", panel) == ["7", "6", "5", "4", "3"]
    assert "Latest 5 of 7" in panel
    assert 'href="#by-project"' in panel


def test_by_project_ends_with_each_projects_review_status(client, tmp_path):
    repo = RunRepository()
    current = _project(repo, "acme/current", "2026-11-07T09:00:00+00:00")
    _run(repo, tmp_path, current, status="success", started_at="2026-11-07T09:00:00+00:00")
    stale = _project(repo, "acme/stale", "2024-01-01T09:00:00+00:00")
    _run(repo, tmp_path, stale, status="success", started_at="2024-01-01T09:00:00+00:00")
    broken = _project(repo, "acme/broken", "2026-11-06T09:00:00+00:00")
    _run(repo, tmp_path, broken, status="failed", started_at="2026-11-06T09:00:00+00:00")
    repo.close()

    html = client.get(f"/activities/{SKILL}").text
    table = _section(html, 'id="by-project"', "</table>")
    header = re.findall(r"<th>([^<]*)</th>", table)
    assert header[-1] == "Review status"

    def status_of(name: str) -> str:
        row = re.search(rf"<tr[^>]*>(?:(?!</tr>).)*{re.escape(name)}(?:(?!</tr>).)*</tr>", table, re.S).group(0)
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
        return re.sub(r"<[^>]+>", "", cells[-1]).strip()

    assert status_of("acme/current") == "Current"
    assert re.fullmatch(r"Stale \(\d+d\)", status_of("acme/stale"))
    assert status_of("acme/broken") == "No successful review"


def test_other_activities_have_no_review_status_column(client, tmp_path):
    repo = RunRepository()
    project_id = _project(repo, "acme/app", "2026-11-07T09:00:00+00:00")
    run_uuid = repo.create_run(project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude",
                               confluence_urls=[])
    repo.complete_run(run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=None,
                      prompt_path=None, stderr_excerpt=None)
    repo.close()
    html = client.get("/activities/sast").text
    assert "Review status" not in html
