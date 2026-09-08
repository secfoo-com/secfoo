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


THREAT_MODEL_REPORT = """\
# Threat Model Report

## 1. Executive Summary

**Overall risk rating:** Medium
**Model depth:** Feature-level

## 3. Trust Boundaries & Data Flow

```mermaid
flowchart LR
  user([End user]) -->|"B1: HTTPS"| api["API"]
```

| ID | Boundary | What crosses it |
|----|----------|------------------|
| B1 | Internet -> API | HTTPS request |

## 4. Assumptions

| ID | Assumption | Validity | Note |
|----|------------|----------|------|
| X1 | Upstream gateway authenticates all requests | Falsified | found a bypass route |
| X2 | Platform isolates tenants | Holds | verified |

## 8. Threat Register

| ID | Threat | Archetype | Asset Class | Boundary | STRIDE | Severity | Disposition | Test Reference |
|----|--------|-----------|-------------|----------|--------|----------|--------------|-----------------|
| T1 | Unauthenticated call to internal svc | Unauthenticated internal service call | Process | B1 | E | High | Gap | none |
| T2 | Model prompt injection via tool output | Unbounded tool invocation | Model/Agent | B1 | T | Medium | Mitigated | test_prompt_inj_01 |
| T3 | Missing rate limit | Unbounded tool invocation | Data Flow | B1 | S | Low | Mitigated | none |
| T4 | Risk accepted for legacy endpoint | Legacy endpoint exposure | Process | B1 | R | Medium | Accepted | none |
"""


def _seed(tmp_path, *, project_name="acme/app", report_text=THREAT_MODEL_REPORT, skill_id="threat-modeling"):
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
        prompt_path=None, stderr_excerpt=None, high_count=1, medium_count=2, low_count=1,
    )
    repo.close()
    return project_id, assessment_id, run_uuid


def test_dashboard_appears_only_on_the_threat_modeling_page(client, tmp_path):
    _seed(tmp_path, skill_id="prompt-review", report_text="# Prompt Review Report\n\n**Overall risk rating:** High\n")
    resp = client.get("/activities/prompt-review")
    assert resp.status_code == 200
    assert "Program dashboard" not in resp.text


def test_dashboard_renders_empty_state(client):
    resp = client.get("/activities/threat-modeling")
    assert resp.status_code == 200
    assert "Program dashboard" in resp.text
    assert "0%" in resp.text


def test_dashboard_renders_with_real_data(client, tmp_path):
    _seed(tmp_path)
    resp = client.get("/activities/threat-modeling")
    assert resp.status_code == 200
    text = resp.text
    for marker in [
        "Program dashboard",
        "STRIDE",
        "Threat disposition",
        "Accepted threats",
        "Models needing rework",
        "Recurring threat patterns",
        "Model depth mix",
        "Threats found post-build",
        "Falsified assumptions",
        'class="stacked-bar"',
    ]:
        assert marker in text, f"missing: {marker}"


def test_dashboard_coverage_reflects_in_scope_vs_reviewed(client, tmp_path):
    repo = RunRepository()
    unreviewed_project = repo.upsert_project("https://github.com/acme/other", "acme/other", "github")
    repo.create_assessment(project_id=unreviewed_project, assessment_type="internal", status="ready")
    repo.close()

    _seed(tmp_path)  # one reviewed project

    resp = client.get("/activities/threat-modeling")
    assert resp.status_code == 200
    assert "1 / 2 in-scope systems" in resp.text
    assert "50.0%" in resp.text


def test_dashboard_shows_recurring_archetype(client, tmp_path):
    _seed(tmp_path)
    resp = client.get("/activities/threat-modeling")
    assert "Unbounded tool invocation" in resp.text


def test_dashboard_shows_mitigated_untested_count(client, tmp_path):
    # T3 is Mitigated with Test Reference "none" -- mitigated but untested.
    _seed(tmp_path)
    resp = client.get("/activities/threat-modeling")
    assert "Threats mitigated but untested" in resp.text


def test_dashboard_shows_accepted_threat(client, tmp_path):
    _seed(tmp_path)
    resp = client.get("/activities/threat-modeling")
    assert "Risk accepted for legacy endpoint" in resp.text
    # No matching secfoo accept record exists yet -- the owner column must
    # say so plainly rather than leaving a blank cell.
    assert "Not recorded" in resp.text


def test_dashboard_shows_falsified_assumption(client, tmp_path):
    _seed(tmp_path)
    resp = client.get("/activities/threat-modeling")
    assert "Upstream gateway authenticates all requests" in resp.text


def test_dashboard_shows_model_depth(client, tmp_path):
    _seed(tmp_path)
    resp = client.get("/activities/threat-modeling")
    assert "Feature-level" in resp.text


def test_dashboard_flags_never_modeled_project(client, tmp_path):
    repo = RunRepository()
    project_id = repo.upsert_project("https://github.com/acme/untouched", "acme/untouched", "github")
    repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
    repo.close()

    resp = client.get("/activities/threat-modeling")
    assert resp.status_code == 200
    assert "Never modeled" in resp.text
    assert "acme/untouched" in resp.text


def test_dashboard_does_not_show_generic_diagrams_gallery(client, tmp_path):
    """Threat Modeling reports carry their own Trust Boundaries & Data Flow
    mermaid diagram (section 3), which would otherwise trip the generic
    per-activity 'Architecture diagrams by project' gallery -- that gallery
    is redundant here since the STRIDE matrix/needs-rework table already
    cover this ground, so it's explicitly suppressed on this page.
    """
    _seed(tmp_path)  # THREAT_MODEL_REPORT above does contain a ```mermaid block
    resp = client.get("/activities/threat-modeling")
    assert resp.status_code == 200
    assert "Architecture diagrams by project" not in resp.text
    assert 'class="mermaid"' not in resp.text


def test_dashboard_shows_post_build_finding(client, tmp_path):
    project_id, _, _ = _seed(tmp_path)
    repo = RunRepository()
    repo.create_post_build_finding(
        project_id=project_id, title="SSRF via webhook URL", discovered_at="2026-08-01", discovered_by="Pen test Q3",
    )
    repo.close()

    resp = client.get("/activities/threat-modeling")
    assert resp.status_code == 200
    assert "SSRF via webhook URL" in resp.text


def test_dashboard_does_not_show_boundary_change_tile(client, tmp_path):
    """The Row-1 'Models stale after a boundary change' KPI tile was
    removed per product feedback -- the underlying signal still lives in
    the Models needing rework table below, just not as a standalone tile.
    """
    _seed(tmp_path)
    resp = client.get("/activities/threat-modeling")
    assert resp.status_code == 200
    assert "Models stale after a boundary change" not in resp.text


def test_dashboard_does_not_show_generic_stat_card_grid(client, tmp_path):
    """The generic 'Projects covered / Runs / Total findings / Critical +
    High' block duplicates the specialized dashboard's own tiles -- hidden
    on this page per product feedback.
    """
    _seed(tmp_path)
    resp = client.get("/activities/threat-modeling")
    assert resp.status_code == 200
    assert "Projects covered" not in resp.text
    assert "Critical + High" not in resp.text


OTHER_PROJECT_REPORT = """\
# Threat Model Report

## 1. Executive Summary

**Overall risk rating:** Low
**Model depth:** Lightweight

## 3. Trust Boundaries & Data Flow

```mermaid
flowchart LR
  svc([Service]) -->|"B1: gRPC"| db[("DB")]
```

| ID | Boundary | What crosses it |
|----|----------|------------------|
| B1 | Service -> DB | gRPC call |

## 8. Threat Register

| ID | Threat | Archetype | Asset Class | Boundary | STRIDE | Severity | Disposition | Test Reference |
|----|--------|-----------|-------------|----------|--------|----------|--------------|-----------------|
| T1 | Unsigned artifact pulled at deploy | Unsigned pipeline artifact | Data Store | B1 | T | High | Gap | none |
"""


def test_stride_matrix_shows_both_a_portfolio_total_and_one_table_per_project(client, tmp_path):
    """Two projects with disjoint STRIDE/asset-class profiles must each
    still get their own matrix underneath the portfolio total -- the total
    alone can't say which project actually has a given gap.
    """
    _seed(tmp_path, project_name="acme/app-a")
    _seed(tmp_path, project_name="acme/app-b", report_text=OTHER_PROJECT_REPORT)

    resp = client.get("/activities/threat-modeling")
    assert resp.status_code == 200
    text = resp.text
    assert "STRIDE" in text
    assert "Portfolio total" in text
    assert "By project" in text
    assert "acme/app-a" in text
    assert "acme/app-b" in text
    # Portfolio total table + one table per project (2) = 3.
    assert text.count('<table class="table">') >= 3


def test_stride_portfolio_total_sums_both_projects(client, tmp_path):
    """acme/app-a's T1 (Process/E) and acme/app-b's T1 (Data Store/T) are
    disjoint cells, so the portfolio total's Data Store/T cell must be 1
    (from app-b alone) -- verifies the aggregate is a real sum, not a
    relabeled per-project table.
    """
    _seed(tmp_path, project_name="acme/app-a")
    _seed(tmp_path, project_name="acme/app-b", report_text=OTHER_PROJECT_REPORT)

    from secfoo.storage.repository import RunRepository as _Repo
    from secfoo.web import threat_modeling_dashboard as tm

    repo = _Repo()
    dash = tm.build(repo)
    repo.close()

    aggregate = {row["asset_class"]: row["cells"] for row in dash.stride_aggregate}
    assert aggregate["Data Store"]["T"] == 1
    assert aggregate["Process"]["E"] == 1


def test_dashboard_reconciles_accepted_threat_with_recorded_owner(client, tmp_path):
    project_id, _, _ = _seed(tmp_path)
    repo = RunRepository()
    repo.create_threat_acceptance(
        project_id=project_id, threat_ref="T4", title="Legacy endpoint risk (internal title)",
        justification="Decommissioned next quarter", accepted_by="Jane Doe",
    )
    repo.close()

    resp = client.get("/activities/threat-modeling")
    assert resp.status_code == 200
    # Matched by (project, threat ID) -- shows the report's own threat text
    # plus the real owner, not two disjoint entries.
    assert "Risk accepted for legacy endpoint" in resp.text
    assert "Jane Doe" in resp.text
    assert "Not recorded" not in resp.text


def test_dashboard_shows_a_recorded_acceptance_with_no_matching_report_row(client, tmp_path):
    """A recorded acceptance for a threat ID the latest report no longer
    shows as Accepted (older run, or the model changed its mind) must still
    be visible -- it's a real human decision, not something to silently
    drop once report text moves on.
    """
    project_id, _, _ = _seed(tmp_path)
    repo = RunRepository()
    repo.create_threat_acceptance(
        project_id=project_id, threat_ref="T99", title="Old acceptance, no longer in report",
        justification="j", accepted_by="Jane Doe",
    )
    repo.close()

    resp = client.get("/activities/threat-modeling")
    assert resp.status_code == 200
    assert "Old acceptance, no longer in report" in resp.text
    assert "Jane Doe" in resp.text


def test_dashboard_shows_accept_cli_hint(client, tmp_path):
    _seed(tmp_path)
    resp = client.get("/activities/threat-modeling")
    assert resp.status_code == 200
    assert "secfoo accept create" in resp.text
