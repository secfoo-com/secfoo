"""Run page steps/receipt/blocked card, the live status endpoint, the
Agents page, Run Assessment starters, and SAST reviewer sign-off."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from secfoo.storage.repository import RunRepository
from secfoo.web import run_status
from secfoo.web.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", tmp_path / "db.sqlite")
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.web.run_status.run_dir", lambda uuid: tmp_path / "reports" / uuid)
    return TestClient(create_app())


def _run(status=None, agent_id="claude", stderr=None):
    repo = RunRepository()
    project_id = repo.upsert_project("p", "Payments API", "local")
    assessment_id = repo.create_assessment(project_id=project_id, assessment_type="internal", status="ready")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id=agent_id,
        confluence_urls=[], assessment_id=assessment_id,
    )
    if status:
        repo.complete_run(
            run_uuid, status=status, exit_code=1 if status == "failed" else None, duration_seconds=2.0,
            report_path=None, prompt_path=None, stderr_excerpt=stderr,
        )
    record = repo.get_run(run_uuid)
    repo.close()
    return record


def test_running_run_page_shows_live_steps(client):
    run = _run()
    resp = client.get(f"/runs/{run.run_uuid}")
    assert resp.status_code == 200
    assert f'data-live-run="/runs/{run.run_uuid}/status.json"' in resp.text
    assert "Run receipt" in resp.text
    assert 'data-state="live"' in resp.text


def test_status_json_reports_steps_and_activity(client):
    run = _run()
    data = client.get(f"/runs/{run.run_uuid}/status.json").json()
    assert data["active"] is True
    assert data["steps"][0]["label"] == "Run created"

    finished = _run(status="success")
    data = client.get(f"/runs/{finished.run_uuid}/status.json").json()
    assert data["active"] is False


def test_missing_api_key_run_shows_blocked_card_with_fix(client):
    run = _run(status="binary_not_found", agent_id="api")
    resp = client.get(f"/runs/{run.run_uuid}")
    assert "Blocked" in resp.text
    assert "No API key found for the api agent" in resp.text
    assert "ANTHROPIC_API_KEY" in resp.text
    assert "Try again" in resp.text


def test_failed_run_marks_agent_step_failed(client):
    run = _run(status="failed", stderr="rate limited")
    states = [s.state for s in run_status.run_steps(run)]
    assert states[2] == "failed"
    assert run_status.blocked_hint(run).title.startswith("Claude Code stopped with an error")


def test_successful_run_has_no_blocked_hint(client):
    assert run_status.blocked_hint(_run(status="success")) is None


def test_agents_page_lists_every_adapter(client):
    resp = client.get("/agents")
    assert resp.status_code == 200
    for label in ("Claude Code", "Cursor", "Codex CLI", "API agent (LiteLLM)"):
        assert label in resp.text


def test_run_form_offers_starter_templates(client):
    run = _run()
    resp = client.get(f"/assessments/{run.assessment_id}/runs/new")
    assert 'data-starter-skills="sast,secret-scanning"' in resp.text
    assert "/static/js/run-form.js" in resp.text


def _finding():
    repo = RunRepository()
    project_id = repo.upsert_project("p", "Payments API", "local")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[]
    )
    run_id = repo.get_run(run_uuid).id
    repo.upsert_sast_finding(
        project_id=project_id, fingerprint="fp1", current_ref="F1", title="SQL Injection", severity="High",
        cwe="CWE-89", owasp=None, verdict="Confirmed", location_file="db.py", location_line="4",
        cvss_vector=None, cvss_score=8.0, run_id=run_id,
    )
    finding = repo.list_sast_findings()[0]
    repo.close()
    return finding


def test_review_signoff_round_trip(client):
    finding = _finding()
    resp = client.post(
        "/activities/sast/findings/fp1/review",
        data={"finding_id": finding.id, "review_status": "false_positive", "reviewer": "sam", "note": "test data"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    page = client.get("/activities/sast/findings/fp1").text
    assert "False positive" in page and "sam" in page

    client.post("/activities/sast/findings/fp1/review", data={"finding_id": finding.id, "review_status": "clear"})
    assert "Awaiting review" in client.get("/activities/sast/findings/fp1").text


def test_accepting_risk_requires_a_reason(client):
    finding = _finding()
    resp = client.post(
        "/activities/sast/findings/fp1/review",
        data={"finding_id": finding.id, "review_status": "accepted_risk"},
    )
    assert resp.status_code == 400


def test_review_survives_the_finding_being_seen_again(client):
    finding = _finding()
    repo = RunRepository()
    repo.review_sast_finding(finding.id, review_status="confirmed", reviewed_by="sam")
    repo.upsert_sast_finding(
        project_id=finding.project_id, fingerprint="fp1", current_ref="F2", title="SQL Injection", severity="High",
        cwe="CWE-89", owasp=None, verdict="Confirmed", location_file="db.py", location_line="4",
        cvss_vector=None, cvss_score=8.0, run_id=finding.first_seen_run_id,
    )
    assert repo.list_sast_findings()[0].review_status == "confirmed"
    repo.close()


def test_assessment_page_shows_review_pipeline_states(client):
    run = _run(status="binary_not_found", agent_id="api")
    resp = client.get(f"/assessments/{run.assessment_id}")
    assert "Review pipeline" in resp.text
    assert 'data-state="blocked"' in resp.text
    assert 'data-state="todo"' in resp.text
    assert "Agent not found" in resp.text


def test_dashboard_getting_started_checklist_tracks_real_state(client):
    resp = client.get("/")
    assert "Four steps to your first signed-off review" in resp.text
    _run(status="success")
    resp = client.get("/")
    assert resp.text.count('data-done="true"') >= 2


def test_relative_time_filter():
    from datetime import datetime, timedelta, timezone

    from secfoo.web.templating import format_ago

    now = datetime.now(timezone.utc)
    assert format_ago((now - timedelta(minutes=5)).isoformat()) == "5m ago"
    assert format_ago((now - timedelta(hours=3)).isoformat()) == "3h ago"
    assert format_ago(None) == "-"
