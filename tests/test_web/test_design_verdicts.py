"""The Security Architecture page's Design verdicts panel and the verdict
shown on the architecture diagram card.

Agents write the verdict as a full sentence, so the page shows a short
label in the badge and the rest as wrapping text -- never the whole
sentence inside a (no-wrap) badge -- and the panel lists only the newest
reviews.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from secfoo.report.architecture import split_design_verdict
from secfoo.storage.repository import RunRepository
from secfoo.web.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    return TestClient(create_app())


def _report(verdict: str) -> str:
    return (
        "# Security Architecture Review Report\n\n## 3. Data Flow Diagram\n\n```mermaid\nflowchart LR\n"
        "  a([User]) -->|\"B1: HTTPS\"| b[\"API\"]\n```\n\n"
        f"## 11. Design Verdict & Remediation Roadmap\n\n**Design verdict:** {verdict}\n"
    )


def _seed(tmp_path, project: str, verdict: str, finished_at: str) -> str:
    repo = RunRepository()
    project_id = repo.upsert_project(f"https://github.com/{project}", project, "github")
    run_uuid = repo.create_run(project_id=project_id, skill_id="security-architecture-review",
                               skill_name="Security Architecture Review", agent_id="claude", confluence_urls=[])
    path = tmp_path / f"{run_uuid}.md"
    path.write_text(_report(verdict))
    repo.complete_run(run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(path),
                      prompt_path=None, stderr_excerpt=None)
    repo._conn.execute("UPDATE runs SET finished_at = ? WHERE run_uuid = ?", (finished_at, run_uuid))
    repo._conn.commit()
    repo.close()
    return run_uuid


@pytest.mark.parametrize(
    "verdict, label, reason",
    [
        ("Sound", "Sound", ""),
        ("Sound.", "Sound", ""),
        ("Sound with conditions: rotate the signing key first", "Sound with conditions",
         "Rotate the signing key first"),
        ("Not sound for any deployment handling real users or data. It fits its training purpose.",
         "Not sound", "For any deployment handling real users or data. It fits its training purpose."),
        ("Not sound — but only in the trivial sense that no design is present", "Not sound",
         "But only in the trivial sense that no design is present"),
        ("Not applicable — there is no design to render a verdict on", "Not applicable",
         "There is no design to render a verdict on"),
        ("Inconclusive pending the vendor's docs", "Unclear", "Inconclusive pending the vendor's docs"),
        (None, "Unclear", ""),
    ],
)
def test_split_design_verdict(verdict, label, reason):
    assert split_design_verdict(verdict) == (label, reason)


def _badges(html: str) -> list[str]:
    return [b.strip() for b in re.findall(r'<span class="badge[^"]*">([^<]*)</span>', html)]


def test_panel_lists_the_five_newest_reviews_newest_first(client, tmp_path):
    for day in range(1, 8):  # seven projects, reviewed on days 1..7
        _seed(tmp_path, f"acme/app-{day}", "Not sound for production use. Details follow.", f"2026-11-0{day}T10:00:00")
    html = client.get("/activities/security-architecture-review").text
    panel = html[html.index("Design verdicts"):html.index("</table>", html.index("Design verdicts"))]

    shown = re.findall(r"acme/app-(\d)", panel)
    assert shown == ["7", "6", "5", "4", "3"]
    assert "Latest 5 of 7 projects" in panel
    # The badge carries only the short label; the sentence is the "Why".
    assert "Not sound" in _badges(panel)
    assert all(len(b) <= len("Sound with conditions") for b in _badges(panel))
    assert "For production use. Details follow" in panel


def test_panel_row_links_to_the_review_the_verdict_came_from(client, tmp_path):
    good = _seed(tmp_path, "acme/app", "Sound", "2026-11-01T10:00:00")
    repo = RunRepository()
    project_id = repo.upsert_project("https://github.com/acme/app", "acme/app", "github")
    failed = repo.create_run(project_id=project_id, skill_id="security-architecture-review",
                             skill_name="Security Architecture Review", agent_id="claude", confluence_urls=[])
    repo.complete_run(failed, status="failed", exit_code=1, duration_seconds=1.0, report_path=None,
                      prompt_path=None, stderr_excerpt="boom")
    repo.close()

    html = client.get("/activities/security-architecture-review").text
    # Only the verdicts panel: the "By project" table rightly links the latest run.
    panel = html[html.index("Design verdicts"):html.index("</table>", html.index("Design verdicts"))]
    assert f'data-href="/runs/{good}"' in panel
    assert f'data-href="/runs/{failed}"' not in panel


def test_diagram_card_shows_label_badge_and_wrapping_reason(client, tmp_path):
    long_verdict = "Not sound for any deployment handling real users or data. It fits its declared purpose."
    _seed(tmp_path, "acme/app", long_verdict, "2026-11-01T10:00:00")
    html = client.get("/activities/security-architecture-review").text
    card = html[html.index("Architecture diagram"):]
    assert long_verdict not in _badges(card)
    assert "Not sound" in _badges(card)
    assert '<div class="verdict-summary' in card
    assert "For any deployment handling real users or data. It fits its declared purpose" in card

