from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from secfoo.storage.repository import RunRepository
from secfoo.web.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", db_path)
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    return TestClient(create_app())


ARCHITECTURE_REPORT = """\
# Security Architecture Review Report

## 3. Data Flow Diagram

```mermaid
flowchart LR
  user([End user]) -->|"B1: HTTPS"| api["API"]
```

## 8. CCM Domain Conformance

| Domain | Code | Conformance | Evidence |
|---|---|---|---|
| Audit & Assurance | A&A | Partial | some logs |
| Application & Interface Security | AIS | Conformant | validated |
| Human Resources Security | HRS | Not Assessed (process-assured) | external |

## 9. Findings Register

| ID | Finding | Severity | Category | Standard | Verdict |
|----|---------|----------|----------|----------|---------|
| A1 | Hardcoded key | High | Secrets Management | ISO 27001 A.10 | Confirmed |
| A2 | Missing rate limit | Medium | Authorization | N/A | Conditional |

## 12. Design Verdict & Remediation Roadmap

**Design verdict:** Sound with conditions
"""


def _seed(tmp_path, *, project_name="acme/app", report_text=ARCHITECTURE_REPORT, skill_id="security-architecture-review"):
    repo = RunRepository()
    project_id = repo.upsert_project(f"https://github.com/{project_name}", project_name, "github")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id=skill_id, skill_name=skill_id,
        agent_id="claude", confluence_urls=[], assessment_id=assessment_id,
    )
    report_path = tmp_path / f"{run_uuid}.md"
    report_path.write_text(report_text)
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(report_path),
        prompt_path=None, stderr_excerpt=None, high_count=1, medium_count=1,
    )
    repo.close()
    return project_id, assessment_id, run_uuid


def test_dashboard_appears_only_on_the_architecture_review_page(client, tmp_path):
    _seed(tmp_path, skill_id="prompt-review", report_text="# Prompt Review Report\n\n**Overall risk rating:** High\n")
    resp = client.get("/activities/prompt-review")
    assert resp.status_code == 200
    assert "Program dashboard" not in resp.text


def test_dashboard_renders_empty_state(client):
    resp = client.get("/activities/security-architecture-review")
    assert resp.status_code == 200
    assert "Program dashboard" in resp.text
    assert "0%" in resp.text


def test_dashboard_hides_generic_stat_card_grid(client, tmp_path):
    """The generic 'Projects covered / Runs / Total findings / Critical +
    High / Trust boundaries identified' block duplicates this program
    dashboard's own tiles -- hidden on this page per product feedback,
    same as it already is on the Threat Modeling activity page.
    """
    _seed(tmp_path)
    resp = client.get("/activities/security-architecture-review")
    assert resp.status_code == 200
    assert "Projects covered" not in resp.text
    assert "Trust boundaries identified" not in resp.text


def test_dashboard_hides_generic_findings_by_severity_card(client, tmp_path):
    """The generic 'Findings by severity' bar duplicates the program
    dashboard's own Risk disposition breakdown -- hidden on this page per
    product feedback. Other activities without a specialized dashboard
    (e.g. Prompt Review) must still show it.
    """
    _seed(tmp_path)
    resp = client.get("/activities/security-architecture-review")
    assert resp.status_code == 200
    assert "Findings by severity" not in resp.text

    resp = client.get("/activities/prompt-review")
    assert resp.status_code == 200
    assert "Findings by severity" in resp.text


def test_dashboard_renders_with_real_data(client, tmp_path):
    _seed(tmp_path)
    resp = client.get("/activities/security-architecture-review")
    assert resp.status_code == 200
    text = resp.text
    for marker in [
        "Program dashboard",
        "CCM domain conformance",
        "Risk disposition",
        "Exception aging",
        "Unreviewed",
        "Top recurring root causes",
        "Gate decision mix",
        "Most-deviated standards",
        "Uncovered CCM domains",
        'class="donut"',
        'class="stacked-bar"',
        'class="conformance-bar"',
    ]:
        assert marker in text, f"missing: {marker}"


def test_dashboard_coverage_reflects_in_scope_vs_reviewed(client, tmp_path):
    # In scope (has an assessment) but never reviewed with this skill.
    repo = RunRepository()
    unreviewed_project = repo.upsert_project("https://github.com/acme/other", "acme/other", "github")
    repo.create_assessment(project_id=unreviewed_project, assessment_type="internal", status="ready")
    repo.close()

    _seed(tmp_path)  # one reviewed project

    resp = client.get("/activities/security-architecture-review")
    assert resp.status_code == 200
    assert "1 / 2 in-scope systems" in resp.text
    assert "50.0%" in resp.text


def test_dashboard_shows_standard_from_findings_register(client, tmp_path):
    _seed(tmp_path)
    resp = client.get("/activities/security-architecture-review")
    assert "ISO 27001 A.10" in resp.text


def test_dashboard_shows_exceptions_past_expiry(client, tmp_path):
    project_id, _, _ = _seed(tmp_path)
    repo = RunRepository()
    repo.create_exception(
        project_id=project_id, title="Expired waiver", justification="j", granted_by="g", expires_at="2020-01-01",
    )
    repo.close()

    resp = client.get("/activities/security-architecture-review")
    assert resp.status_code == 200
    assert "Exceptions past expiry" in resp.text
    # The stat-card value of 1 must appear with the error-colored styling.
    assert "color:var(--color-error)" in resp.text


def test_dashboard_flags_never_reviewed_project(client, tmp_path):
    repo = RunRepository()
    project_id = repo.upsert_project("https://github.com/acme/untouched", "acme/untouched", "github")
    repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
    repo.close()

    resp = client.get("/activities/security-architecture-review")
    assert resp.status_code == 200
    assert "Never reviewed" in resp.text
    assert "acme/untouched" in resp.text


def test_dashboard_gate_mix_reflects_design_verdict(client, tmp_path):
    _seed(tmp_path)  # "Sound with conditions"
    resp = client.get("/activities/security-architecture-review")
    assert "With conditions (1)" in resp.text
    assert "Approve (0)" in resp.text
    assert "Reject (0)" in resp.text


def test_dashboard_diagram_section_still_present_alongside_new_dashboard(client, tmp_path):
    """The new program dashboard is additive -- the existing diagram
    viewer from the earlier feature must still render on the same page.
    """
    _seed(tmp_path)
    resp = client.get("/activities/security-architecture-review")
    assert "Architecture diagram" in resp.text
    assert 'class="mermaid"' in resp.text
