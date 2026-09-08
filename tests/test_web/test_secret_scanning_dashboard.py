from __future__ import annotations

from secfoo.storage.repository import RunRepository
from secfoo.web import secret_scanning_dashboard


def _repo(tmp_path):
    return RunRepository(db_path=tmp_path / "db.sqlite")


def _report(rows: str) -> str:
    return f"""\
# Secret Scanning Report

## 1. Executive Summary
Test summary. **Overall risk rating:** High

## 3. Findings Register
| ID | Secret type | Location | Source | Validity | Severity |
|----|-------------|----------|--------|----------|----------|
{rows}
## 4. Detailed Findings

### [HIGH] S1: placeholder
- **Type:** x, **Source:** config, **Validity:** Looks live
- **Location:** `x`
- **Evidence:** AKIA1234...
- **Exposure:** full account access
- **Remediation:** rotate immediately
"""


def _seed(tmp_path, repo, *, project_name, report_text):
    project_id = repo.upsert_project(f"https://github.com/{project_name}", project_name, "github")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="secret-scanning", skill_name="Secret Scanning",
        agent_id="claude", confluence_urls=[],
    )
    report_path = tmp_path / f"{run_uuid}.md"
    report_path.write_text(report_text)
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(report_path),
        prompt_path=None, stderr_excerpt=None, high_count=1,
    )
    return project_id


def test_build_empty_state(tmp_path):
    repo = _repo(tmp_path)
    dash = secret_scanning_dashboard.build(repo)
    assert dash.total == 0
    assert dash.findings == []
    assert dash.severity_counts == {"high": 0, "medium": 0, "low": 0}
    repo.close()


def test_build_extracts_a_real_finding(tmp_path):
    repo = _repo(tmp_path)
    report = _report(rows="| S1 | AWS access key | `deploy/ci.yml:14` | config | Looks live | High |\n")
    _seed(tmp_path, repo, project_name="acme/app", report_text=report)

    dash = secret_scanning_dashboard.build(repo)
    assert dash.total == 1
    finding = dash.findings[0]
    assert finding.secret_type == "AWS access key"
    assert finding.location == "deploy/ci.yml:14"
    assert finding.source == "config"
    assert finding.validity == "Looks live"
    assert finding.severity == "High"
    assert finding.evidence == "AKIA1234..."
    assert finding.remediation == "rotate immediately"
    assert finding.project_display_name == "acme/app"
    repo.close()


def test_build_looks_live_and_source_counts(tmp_path):
    repo = _repo(tmp_path)
    report = _report(
        rows=(
            "| S1 | AWS key | `a.yml:1` | config | Looks live | High |\n"
            "| S2 | Slack webhook | Onboarding (Confluence) | docs | Unclear | Medium |\n"
            "| S3 | Old DB password | `git log -- old.py` | history | Placeholder | Low |\n"
        )
    )
    _seed(tmp_path, repo, project_name="acme/app", report_text=report)

    dash = secret_scanning_dashboard.build(repo)
    assert dash.total == 3
    assert dash.looks_live_count == 1
    assert dash.docs_count == 1
    assert dash.history_count == 1
    assert dash.source_counts == {"code": 0, "config": 1, "history": 1, "docs": 1}
    repo.close()


def test_build_sorts_by_severity_descending(tmp_path):
    repo = _repo(tmp_path)
    report = _report(
        rows=(
            "| S1 | Low secret | `a` | code | Placeholder | Low |\n"
            "| S2 | High secret | `b` | code | Looks live | High |\n"
            "| S3 | Medium secret | `c` | code | Unclear | Medium |\n"
        )
    )
    _seed(tmp_path, repo, project_name="acme/app", report_text=report)

    dash = secret_scanning_dashboard.build(repo)
    assert [f.severity for f in dash.findings] == ["High", "Medium", "Low"]
    repo.close()


def test_build_aggregates_across_multiple_projects(tmp_path):
    repo = _repo(tmp_path)
    report_a = _report(rows="| S1 | Key A | `a` | code | Looks live | High |\n")
    report_b = _report(rows="| S1 | Key B | `b` | config | Unclear | Medium |\n")
    _seed(tmp_path, repo, project_name="acme/app-a", report_text=report_a)
    _seed(tmp_path, repo, project_name="acme/app-b", report_text=report_b)

    dash = secret_scanning_dashboard.build(repo)
    assert dash.total == 2
    assert {f.project_display_name for f in dash.findings} == {"acme/app-a", "acme/app-b"}
    repo.close()


def test_build_findings_by_key_matches_the_list(tmp_path):
    repo = _repo(tmp_path)
    report = _report(rows="| S1 | AWS key | `a.yml:1` | config | Looks live | High |\n")
    _seed(tmp_path, repo, project_name="acme/app", report_text=report)

    dash = secret_scanning_dashboard.build(repo)
    assert len(dash.findings) == 1
    finding = dash.findings[0]
    assert dash.findings_by_key[finding.key] is finding


def test_build_same_location_different_projects_gets_distinct_keys(tmp_path):
    repo = _repo(tmp_path)
    report = _report(rows="| S1 | AWS key | `a.yml:1` | config | Looks live | High |\n")
    _seed(tmp_path, repo, project_name="acme/app-a", report_text=report)
    _seed(tmp_path, repo, project_name="acme/app-b", report_text=report)

    dash = secret_scanning_dashboard.build(repo)
    assert dash.total == 2
    keys = {f.key for f in dash.findings}
    assert len(keys) == 2
    repo.close()


def test_build_strips_markdown_backticks_from_location(tmp_path):
    repo = _repo(tmp_path)
    report = _report(rows="| S1 | AWS key | `a.yml:1` | config | Looks live | High |\n")
    _seed(tmp_path, repo, project_name="acme/app", report_text=report)

    dash = secret_scanning_dashboard.build(repo)
    assert dash.findings[0].location == "a.yml:1"
    repo.close()


def test_build_same_type_and_location_different_ids_get_distinct_keys(tmp_path):
    repo = _repo(tmp_path)
    report = _report(
        rows=(
            "| S1 | AWS key | `a.yml:1` | config | Looks live | High |\n"
            "| S2 | AWS key | `a.yml:1` | config | Unclear | Medium |\n"
        )
    )
    _seed(tmp_path, repo, project_name="acme/app", report_text=report)

    dash = secret_scanning_dashboard.build(repo)
    assert dash.total == 2
    keys = {f.key for f in dash.findings}
    assert len(keys) == 2
    repo.close()
