from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from secfoo.storage.repository import RunRepository
from secfoo.web.app import create_app

SAMPLE_REPORT = """\
# Security Architecture Review Report

## Summary
All good.

## Findings

### [HIGH] Example finding
- **Severity:** High
- **Location:** app.py
- **Description:** desc
- **Recommendation:** fix it

## Coverage Notes
n/a
"""


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", db_path)
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    return TestClient(create_app())


def _seed_run(tmp_path, *, status: str = "success") -> tuple[int, str]:
    repo = RunRepository()
    project_id = repo.upsert_project("https://github.com/org/repo", "org/repo", "github")
    run_uuid = repo.create_run(
        project_id=project_id,
        skill_id="security-architecture-review",
        skill_name="Security Architecture Review",
        agent_id="claude",
        confluence_urls=[],
    )
    report_path = tmp_path / "report.md"
    report_path.write_text(SAMPLE_REPORT)
    repo.complete_run(
        run_uuid,
        status=status,
        exit_code=0,
        duration_seconds=3.4,
        report_path=str(report_path),
        prompt_path=None,
        stderr_excerpt=None,
    )
    repo.close()
    return project_id, run_uuid


def test_overview_empty_state(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "No assessments yet" in resp.text


def test_overview_lists_recent_assessment(client, tmp_path):
    project_id, run_uuid = _seed_run(tmp_path)
    repo = RunRepository()
    repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
    repo.close()

    resp = client.get("/")
    assert resp.status_code == 200
    assert "org/repo" in resp.text


def test_project_detail(client, tmp_path):
    project_id, _ = _seed_run(tmp_path)
    resp = client.get(f"/projects/{project_id}")
    assert resp.status_code == 200
    assert "Security Architecture Review" in resp.text


def test_project_detail_404(client):
    resp = client.get("/projects/999999")
    assert resp.status_code == 404


def test_run_detail_renders_severity_badge(client, tmp_path):
    _, run_uuid = _seed_run(tmp_path)
    resp = client.get(f"/runs/{run_uuid}")
    assert resp.status_code == 200
    assert "badge--error" in resp.text
    assert "Example finding" in resp.text


def test_run_detail_404(client):
    resp = client.get("/runs/does-not-exist")
    assert resp.status_code == 404


def test_report_download(client, tmp_path):
    _, run_uuid = _seed_run(tmp_path)
    resp = client.get(f"/runs/{run_uuid}/report.md")
    assert resp.status_code == 200
    assert "Security Architecture Review Report" in resp.text


def test_static_design_system_css_served(client):
    resp = client.get("/static/design-system/design-system.css")
    assert resp.status_code == 200


def test_run_detail_omits_mermaid_script_when_bundle_absent(client, tmp_path, monkeypatch):
    """Mermaid is an optional asset. Without it the page must not emit a
    <script src> pointing at a file that 404s -- diagrams degrade to
    readable Mermaid source instead.
    """
    monkeypatch.setattr("secfoo.web.app.MERMAID_BUNDLE", tmp_path / "nope.js")
    _, run_uuid = _seed_run(tmp_path)
    resp = client.get(f"/runs/{run_uuid}")
    assert resp.status_code == 200
    assert "vendor/mermaid.min.js" not in resp.text


def test_run_detail_loads_mermaid_when_bundle_present(client, tmp_path, monkeypatch):
    bundle = tmp_path / "mermaid.min.js"
    bundle.write_text("// stub")
    monkeypatch.setattr("secfoo.web.app.MERMAID_BUNDLE", bundle)
    _, run_uuid = _seed_run(tmp_path)
    resp = client.get(f"/runs/{run_uuid}")
    assert resp.status_code == 200
    assert "vendor/mermaid.min.js" in resp.text
    # The init/run call (including securityLevel: "strict" -- agent-generated
    # content is untrusted) lives in the external mermaid-init.js, not an
    # inline <script> block: the portal's CSP (default-src 'self', no
    # 'unsafe-inline') silently blocks inline script content, so it must be
    # a same-origin file for the diagram to actually render there.
    assert '<script src="/static/js/mermaid-init.js"></script>' in resp.text


def test_mermaid_init_js_sanitizes_agent_generated_content():
    from secfoo.web.app import STATIC_DIR

    content = (STATIC_DIR / "js" / "mermaid-init.js").read_text()
    assert 'securityLevel: "strict"' in content
