from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from secfoo.storage.repository import RunRepository
from secfoo.web.app import create_app
from secfoo.web.templating import SIDEBAR_ACTIVITY_IDS


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", db_path)
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    return TestClient(create_app())


def _seed_run(*, skill_id: str, project_name: str = "acme/app", high: int = 0, medium: int = 0):
    repo = RunRepository()
    project_id = repo.upsert_project(f"https://github.com/{project_name}", project_name, "github")
    run_uuid = repo.create_run(
        project_id=project_id,
        skill_id=skill_id,
        skill_name=skill_id,
        agent_id="claude",
        confluence_urls=[],
    )
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=None,
        prompt_path=None, stderr_excerpt=None, high_count=high, medium_count=medium,
    )
    repo.close()
    return project_id, run_uuid


@pytest.mark.parametrize("skill_id", SIDEBAR_ACTIVITY_IDS)
def test_every_sidebar_activity_has_a_working_page(client, skill_id):
    resp = client.get(f"/activities/{skill_id}")
    assert resp.status_code == 200


def test_activity_page_unknown_skill_404s(client):
    resp = client.get("/activities/not-a-real-activity")
    assert resp.status_code == 404


def test_activity_page_empty_state(client):
    resp = client.get("/activities/sast")
    assert resp.status_code == 200
    assert "No project has been scanned with this activity yet" in resp.text


def test_activity_page_shows_per_project_rollup(client):
    _seed_run(skill_id="sast", project_name="acme/app", high=2, medium=1)
    _seed_run(skill_id="sast", project_name="acme/other", high=1)
    # A different activity's run must not leak into this page.
    _seed_run(skill_id="secret-scanning", project_name="acme/third", high=9)

    resp = client.get("/activities/sast")
    assert resp.status_code == 200
    assert "acme/app" in resp.text
    assert "acme/other" in resp.text
    assert "acme/third" not in resp.text


def test_activity_page_severity_totals_are_activity_scoped(client):
    _seed_run(skill_id="sast", high=3, medium=2)
    _seed_run(skill_id="sca-reachability", project_name="acme/dep", high=7)

    repo = RunRepository()
    assert repo.activity_severity_totals("sast").high == 3
    assert repo.activity_severity_totals("sca-reachability").high == 7
    repo.close()


def test_sidebar_lists_the_analysis_activities_on_every_page(client):
    for path in ["/", "/assessments", "/third-party", "/responsible-ai"]:
        resp = client.get(path)
        assert resp.status_code == 200
        for skill_id in SIDEBAR_ACTIVITY_IDS:
            assert f'href="/activities/{skill_id}"' in resp.text, f"{skill_id} missing from sidebar on {path}"


def test_sidebar_marks_exactly_the_active_activity(client):
    """Exactly one sidebar link may carry aria-current, and it must be the
    activity being viewed -- not Dashboard, and not a sibling activity
    whose id happens to be a prefix/substring of it.
    """
    import re

    resp = client.get("/activities/sast")
    links = re.findall(r'<a class="sidebar__link"[^>]*>[^<]*</a>', resp.text, re.S)
    active = [re.sub(r"\s+", " ", link) for link in links if "aria-current" in link]
    assert len(active) == 1, f"expected exactly one active link, got {active}"
    assert 'href="/activities/sast"' in active[0]
    assert ">SAST</a>" in active[0]


def test_project_page_shows_activity_coverage_including_gaps(client):
    project_id, _ = _seed_run(skill_id="sast", high=1)
    resp = client.get(f"/projects/{project_id}")
    assert resp.status_code == 200
    assert "Activity coverage" in resp.text
    # An activity never run against this project is shown as a gap.
    assert "Not run" in resp.text


def test_dashboard_skill_coverage_links_to_activity_pages(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert 'href="/activities/sast"' in resp.text


def test_dashboard_skill_board_uses_the_curated_order(client):
    """Workflow order, not alphabetical: design -> threats -> code -> deps
    -> secrets -> vendors -> AI/deployment.
    """
    import re

    resp = client.get("/")
    labels = re.findall(r'<span class="ds-caption">([^<]+)</span>\s*\n\s*<span class="ds-caption">\d+/\d+', resp.text)
    assert labels == [
        "Security Architecture",
        "Threat Modeling",
        "SAST",
        "SCA",
        "Secret Scanning",
        "Third-Party Risk",
        "Prompt Review",
        "Deployment Readiness",
        "Responsible AI",
    ]


def test_ordered_skills_appends_unlisted_skills_rather_than_dropping_them():
    """A new definitions/*.md must still appear even before anyone adds it
    to DISPLAY_SKILL_ORDER.
    """
    from secfoo.skills.loader import load_all_skills
    from secfoo.web.templating import ordered_skills

    assert {s.id for s in ordered_skills()} == set(load_all_skills())


def test_project_activity_table_uses_the_same_order(client):
    project_id, _ = _seed_run(skill_id="sast")
    resp = client.get(f"/projects/{project_id}")
    order = [
        resp.text.index(f">{label}</td>")
        for label in ["Security Architecture", "Threat Modeling", "SAST", "SCA", "Responsible AI"]
    ]
    assert order == sorted(order)


ARCHITECTURE_REPORT = """\
# Security Architecture Review Report

## 3. Data Flow Diagram

```mermaid
flowchart LR
  user([End user]) -->|"B1: HTTPS"| api["API service"]
  api -->|"B2: parameterized SQL"| db[("Primary DB")]
```

## 4. Trust Boundaries

| ID | Boundary | What crosses it | Enforced by | Gap |
|----|----------|------------------|--------------|-----|
| B1 | Internet -> API | HTTPS request | TLS + session middleware | - |
| B2 | API -> DB | SQL query | Parameterization | - |

## 11. Design Verdict & Remediation Roadmap

**Design verdict:** Not sound

The primary blocking issue is the hardcoded signing key.
"""


def _seed_run_with_report(tmp_path, *, skill_id, project_name, report_text):
    repo = RunRepository()
    project_id = repo.upsert_project(f"https://github.com/{project_name}", project_name, "github")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id=skill_id, skill_name=skill_id,
        agent_id="claude", confluence_urls=[],
    )
    report_path = tmp_path / f"{run_uuid}.md"
    report_path.write_text(report_text)
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(report_path),
        prompt_path=None, stderr_excerpt=None, high_count=1,
    )
    repo.close()
    return project_id, run_uuid


def test_architecture_activity_page_shows_diagram_and_verdict(client, tmp_path):
    _seed_run_with_report(
        tmp_path, skill_id="security-architecture-review", project_name="acme/app",
        report_text=ARCHITECTURE_REPORT,
    )
    resp = client.get("/activities/security-architecture-review")
    assert resp.status_code == 200
    assert "Architecture diagram" in resp.text
    assert 'class="mermaid"' in resp.text
    assert "flowchart LR" in resp.text
    assert "Not sound" in resp.text
    # The generic stat-card-grid (with its standalone "Trust boundaries
    # identified" tile) is hidden on this page -- the program dashboard
    # above already covers coverage more specifically, and the per-project
    # boundary count still shows in the "By project" table's own column.
    assert "Trust boundaries identified" not in resp.text
    assert "Projects covered" not in resp.text


SECOND_ARCHITECTURE_REPORT = """\
# Security Architecture Review Report

## 3. Data Flow Diagram

```mermaid
flowchart LR
  svc([Service]) -->|"B1: gRPC"| db2[("Other DB")]
```

## 4. Trust Boundaries

| ID | Boundary | What crosses it | Enforced by | Gap |
|----|----------|------------------|--------------|-----|
| B1 | Service -> DB | gRPC call | mTLS | - |

## 11. Design Verdict & Remediation Roadmap

**Design verdict:** Sound
"""


def test_architecture_activity_page_shows_one_diagram_at_a_time_with_a_project_selector(client, tmp_path):
    """A gallery rendering every project's diagram doesn't scale -- with
    more than one project that has a diagram, a <select> must appear and
    only ONE diagram (the selected project's) renders at a time.
    """
    _seed_run_with_report(
        tmp_path, skill_id="security-architecture-review", project_name="acme/app-a",
        report_text=ARCHITECTURE_REPORT,
    )
    _seed_run_with_report(
        tmp_path, skill_id="security-architecture-review", project_name="acme/app-b",
        report_text=SECOND_ARCHITECTURE_REPORT,
    )

    resp = client.get("/activities/security-architecture-review")
    assert resp.status_code == 200
    text = resp.text
    assert '<select class="select" name="diagram_project"' in text
    assert "acme/app-a" in text and "acme/app-b" in text  # both listed as <option>s
    # Only the default-selected project's diagram actually renders.
    assert text.count('class="mermaid"') == 1


def test_architecture_activity_page_diagram_selector_switches_on_query_param(client, tmp_path):
    _, run_a = _seed_run_with_report(
        tmp_path, skill_id="security-architecture-review", project_name="acme/app-a",
        report_text=ARCHITECTURE_REPORT,
    )
    project_b, run_b = _seed_run_with_report(
        tmp_path, skill_id="security-architecture-review", project_name="acme/app-b",
        report_text=SECOND_ARCHITECTURE_REPORT,
    )

    resp = client.get(f"/activities/security-architecture-review?diagram_project={project_b}")
    assert resp.status_code == 200
    text = resp.text
    assert text.count('class="mermaid"') == 1
    assert "Other DB" in text
    assert "Primary DB" not in text


def test_architecture_activity_page_single_project_has_no_selector(client, tmp_path):
    """With only one project to choose from, the <select> would be pure
    clutter -- it shouldn't render at all.
    """
    _seed_run_with_report(
        tmp_path, skill_id="security-architecture-review", project_name="acme/app",
        report_text=ARCHITECTURE_REPORT,
    )
    resp = client.get("/activities/security-architecture-review")
    assert resp.status_code == 200
    assert '<select class="select" name="diagram_project"' not in resp.text


def test_architecture_activity_page_diagram_stays_html_escaped(client, tmp_path):
    """Diagram source is agent-generated from a possibly-untrusted target.
    Jinja's default autoescaping must keep raw HTML from landing verbatim
    in the page, matching the same threat model as report/markdown.py.
    """
    malicious = '# Security Architecture Review Report\n\n## 3. Data Flow Diagram\n\n```mermaid\nflowchart LR\n  a["<script>alert(1)</script>"] --> b\n```\n\n**Design verdict:** Sound\n'
    _seed_run_with_report(
        tmp_path, skill_id="security-architecture-review", project_name="acme/evil",
        report_text=malicious,
    )
    resp = client.get("/activities/security-architecture-review")
    assert resp.status_code == 200
    assert "<script>alert(1)</script>" not in resp.text
    assert "&lt;script&gt;" in resp.text


def test_sast_activity_page_has_no_diagrams_section(client, tmp_path):
    """SAST reports never carry a diagram -- the section must not appear
    at all, not render empty.
    """
    _seed_run(skill_id="sast", high=1)
    resp = client.get("/activities/sast")
    assert resp.status_code == 200
    assert "Architecture diagram" not in resp.text
    assert "Trust boundaries identified" not in resp.text


def test_activity_page_without_mermaid_bundle_shows_raw_source(client, tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.web.app.MERMAID_BUNDLE", tmp_path / "does-not-exist.js")
    _seed_run_with_report(
        tmp_path, skill_id="security-architecture-review", project_name="acme/app",
        report_text=ARCHITECTURE_REPORT,
    )
    resp = client.get("/activities/security-architecture-review")
    assert resp.status_code == 200
    assert "flowchart LR" in resp.text
    assert 'class="mermaid"' not in resp.text
    assert "secfoo vendor mermaid" in resp.text


def test_activity_page_ignores_reports_from_failed_runs(client, tmp_path):
    """A failed run has no usable report -- must not surface a stale or
    partial diagram, and must not hide an earlier successful one.
    """
    repo = RunRepository()
    project_id = repo.upsert_project("https://github.com/acme/flaky", "acme/flaky", "github")
    ok_uuid = repo.create_run(
        project_id=project_id, skill_id="security-architecture-review", skill_name="Security Architecture Review",
        agent_id="claude", confluence_urls=[],
    )
    ok_report = tmp_path / "ok.md"
    ok_report.write_text(ARCHITECTURE_REPORT)
    repo.complete_run(
        ok_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(ok_report),
        prompt_path=None, stderr_excerpt=None,
    )
    failed_uuid = repo.create_run(
        project_id=project_id, skill_id="security-architecture-review", skill_name="Security Architecture Review",
        agent_id="claude", confluence_urls=[],
    )
    repo.complete_run(
        failed_uuid, status="failed", exit_code=1, duration_seconds=1.0, report_path=None,
        prompt_path=None, stderr_excerpt="boom",
    )
    repo.close()

    resp = client.get("/activities/security-architecture-review")
    assert resp.status_code == 200
    assert "flowchart LR" in resp.text
