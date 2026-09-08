from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from secfoo.storage.repository import RunRepository
from secfoo.web.app import create_app

REPORT = """\
# Secret Scanning Report

## 1. Executive Summary
Test summary. **Overall risk rating:** High

## 3. Findings Register
| ID | Secret type | Location | Source | Validity | Severity |
|----|-------------|----------|--------|----------|----------|
| S1 | AWS access key | `deploy/ci.yml:14` | config | Looks live | High |

## 4. Detailed Findings

### [HIGH] S1: AWS access key in deploy/ci.yml
- **Type:** AWS access key, **Source:** config, **Validity:** Looks live
- **Location:** `deploy/ci.yml:14`
- **Evidence:** AKIAJ4F2...
- **Exposure:** Full production AWS account access.
- **Remediation:** Rotate the key immediately, then move it to a secret manager.
"""


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", db_path)
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    return TestClient(create_app())


def _seed(tmp_path, *, project_name="acme/app", report_text=REPORT):
    repo = RunRepository()
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
    repo.close()
    return project_id, run_uuid


def test_secret_scanning_dashboard_renders_empty_state(client):
    resp = client.get("/activities/secret-scanning")
    assert resp.status_code == 200
    assert "Program dashboard" in resp.text
    assert "Secrets found" in resp.text


def test_secret_scanning_dashboard_renders_with_real_data(client, tmp_path):
    _seed(tmp_path)
    resp = client.get("/activities/secret-scanning")
    assert resp.status_code == 200
    text = resp.text
    for marker in [
        "Program dashboard",
        "Top findings",
        "AWS access key",
        "deploy/ci.yml:14",
        "Looks live",
        'href="/activities/secret-scanning/findings"',
        'class="donut"',
    ]:
        assert marker in text, f"missing: {marker}"


def test_secret_scanning_dashboard_does_not_show_generic_stat_card_grid_or_severity_bar(client, tmp_path):
    _seed(tmp_path)
    resp = client.get("/activities/secret-scanning")
    assert resp.status_code == 200
    assert "Projects covered" not in resp.text
    assert "Findings by severity" not in resp.text


def test_secret_scanning_findings_list_renders_empty_state(client):
    resp = client.get("/activities/secret-scanning/findings")
    assert resp.status_code == 200
    assert "All findings" in resp.text


def test_secret_scanning_findings_list_shows_findings(client, tmp_path):
    _seed(tmp_path)
    resp = client.get("/activities/secret-scanning/findings")
    assert resp.status_code == 200
    assert "AWS access key" in resp.text
    assert "acme/app" in resp.text


def test_secret_scanning_findings_list_filters_by_project(client, tmp_path):
    other_report = REPORT.replace("AWS access key", "GitHub token").replace("S1 |", "S1 |").replace(
        "deploy/ci.yml:14", "scripts/deploy.sh:3"
    )
    project_a, _ = _seed(tmp_path, project_name="acme/app-a")
    _, _ = _seed(tmp_path, project_name="acme/app-b", report_text=other_report)

    resp_all = client.get("/activities/secret-scanning/findings")
    assert "AWS access key" in resp_all.text
    assert "GitHub token" in resp_all.text

    resp_a = client.get(f"/activities/secret-scanning/findings?project_id={project_a}")
    assert "AWS access key" in resp_a.text
    assert "GitHub token" not in resp_a.text


def test_secret_scanning_finding_detail_renders_for_a_real_finding(client, tmp_path):
    _seed(tmp_path)
    dashboard_resp = client.get("/activities/secret-scanning")
    match = re.search(r"/activities/secret-scanning/findings/([0-9a-f]+)", dashboard_resp.text)
    assert match, dashboard_resp.text
    key = match.group(1)

    resp = client.get(f"/activities/secret-scanning/findings/{key}")
    assert resp.status_code == 200
    assert "AWS access key" in resp.text
    assert "AKIAJ4F2..." in resp.text
    assert "Rotate the key immediately" in resp.text
    assert "acme/app" in resp.text
    assert 'href="/activities/secret-scanning/findings"' in resp.text


def test_secret_scanning_finding_detail_404s_for_unknown_key(client, tmp_path):
    resp = client.get("/activities/secret-scanning/findings/deadbeefdeadbeef")
    assert resp.status_code == 404
