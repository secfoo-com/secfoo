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


def _seed_finding(*, project_name="acme/app", fingerprint="fp-1", **overrides):
    """The SAST dashboard reads from the persistent sast_findings table,
    not report text -- unlike every other activity dashboard, seeding a
    plain report/run here does nothing. Seed the table directly, the way
    runner.py's post-run hook would after a real `secfoo run --skill sast`.
    """
    repo = RunRepository()
    project_id = repo.upsert_project(f"https://github.com/{project_name}", project_name, "github")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[]
    )
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=None,
        prompt_path=None, stderr_excerpt=None, high_count=1,
    )
    run_id = repo.get_run(run_uuid).id
    fields = {
        "current_ref": "F1",
        "title": "SQL Injection via raw query",
        "severity": "High",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "verdict": "Confirmed",
        "location_file": "app/db.py",
        "location_line": "42",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cvss_score": 9.1,
        "description": "Untrusted input reaches a raw SQL query.",
        "recommendation": "Use parameterized queries.",
    }
    fields.update(overrides)
    repo.upsert_sast_finding(project_id=project_id, fingerprint=fingerprint, run_id=run_id, **fields)
    repo.close()
    return project_id, fingerprint


def test_sast_dashboard_renders_empty_state(client):
    resp = client.get("/activities/sast")
    assert resp.status_code == 200
    assert "Program dashboard" in resp.text
    assert "Open findings" in resp.text


def test_sast_dashboard_renders_with_real_data(client):
    _seed_finding()
    resp = client.get("/activities/sast")
    assert resp.status_code == 200
    text = resp.text
    for marker in [
        "Program dashboard",
        "Top findings",
        "SQL Injection via raw query",
        "CWE-89",
        "app/db.py:42",
        "Verified",
        "External",
        'href="/activities/sast/findings"',
        'class="donut"',
    ]:
        assert marker in text, f"missing: {marker}"


def test_sast_dashboard_does_not_show_generic_stat_card_grid_or_severity_bar(client):
    _seed_finding()
    resp = client.get("/activities/sast")
    assert resp.status_code == 200
    assert "Projects covered" not in resp.text
    assert "Findings by severity" not in resp.text


def test_sast_findings_list_renders_empty_state(client):
    resp = client.get("/activities/sast/findings")
    assert resp.status_code == 200
    assert "All findings" in resp.text
    assert "Open (0)" in resp.text
    assert "Closed (0)" in resp.text


def test_sast_findings_list_shows_open_findings_by_default(client):
    _seed_finding()
    resp = client.get("/activities/sast/findings")
    assert resp.status_code == 200
    assert "SQL Injection via raw query" in resp.text


def test_sast_findings_list_closed_tab_shows_closed_findings(client):
    project_id, fingerprint = _seed_finding()
    repo = RunRepository()
    repo.close_stale_sast_findings(
        project_id=project_id, run_id=1, seen_fingerprints=[], closed_at="2026-08-22T00:00:00Z"
    )
    repo.close()

    open_resp = client.get("/activities/sast/findings?status=open")
    assert "SQL Injection via raw query" not in open_resp.text

    closed_resp = client.get("/activities/sast/findings?status=closed")
    assert "SQL Injection via raw query" in closed_resp.text


def test_sast_findings_list_search_filters_findings(client):
    _seed_finding(fingerprint="fp-sqli", title="SQL Injection", cwe="CWE-89")
    _seed_finding(fingerprint="fp-xss", title="Reflected XSS", cwe="CWE-79")

    resp = client.get("/activities/sast/findings?q=XSS")
    assert "Reflected XSS" in resp.text
    assert "SQL Injection" not in resp.text


def test_sast_findings_list_filters_by_project(client):
    project_a, fp_a = _seed_finding(project_name="acme/app-a", fingerprint="fp-a", title="Finding in app A")
    project_b, fp_b = _seed_finding(project_name="acme/app-b", fingerprint="fp-b", title="Finding in app B")

    resp = client.get(f"/activities/sast/findings?project_id={project_a}")
    assert "Finding in app A" in resp.text
    assert "Finding in app B" not in resp.text

    resp_all = client.get("/activities/sast/findings")
    assert "Finding in app A" in resp_all.text
    assert "Finding in app B" in resp_all.text


def test_sast_findings_list_project_dropdown_lists_scanned_projects(client):
    _seed_finding(project_name="acme/app-a")
    resp = client.get("/activities/sast/findings")
    assert "acme/app-a" in resp.text


def test_sast_finding_detail_renders_for_a_real_finding(client):
    _, fingerprint = _seed_finding()
    resp = client.get(f"/activities/sast/findings/{fingerprint}")
    assert resp.status_code == 200
    assert "SQL Injection via raw query" in resp.text
    assert "Untrusted input reaches a raw SQL query." in resp.text
    assert "Use parameterized queries." in resp.text
    assert "app/db.py:42" in resp.text
    assert "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" in resp.text


def test_sast_finding_detail_404s_for_unknown_fingerprint(client):
    resp = client.get("/activities/sast/findings/does-not-exist")
    assert resp.status_code == 404
