from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secfoo.storage.repository import RunRepository
from secfoo.web.app import create_app


@pytest.fixture
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", db_path)
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.config.ATTACHMENTS_DIR", tmp_path / "attachments")
    return TestClient(create_app())


def _create_assessment(*, assessment_type: str = "internal", status: str = "ready", **fields) -> tuple[int, int]:
    repo = RunRepository()
    project_id = repo.upsert_project("https://github.com/org/vendor-app", "org/vendor-app", "github")
    assessment_id = repo.create_assessment(
        project_id=project_id, assessment_type=assessment_type, status=status, **fields
    )
    repo.close()
    return project_id, assessment_id


def test_assessments_list_empty_state(client):
    resp = client.get("/assessments")
    assert resp.status_code == 200
    assert "No assessments match" in resp.text


def test_assessments_list_shows_created_assessment(client):
    _create_assessment(application_id="APP-1", sar_number="SAR-1")
    resp = client.get("/assessments")
    assert resp.status_code == 200
    assert "org/vendor-app" in resp.text
    assert "APP-1" in resp.text
    assert "SAR-1" in resp.text


def test_assessments_list_row_is_clickable_anywhere_not_just_the_first_cell(client):
    """The row's navigation must be on the <tr>, matching every other
    list page in the app (activities, projects, third-party, etc.) --
    this one used to put `class="run-row" onclick=...` on just the first
    <td>, so clicking the Type/Status/Findings/Reviewed columns did
    nothing, and the shared `tr.run-row { cursor: pointer }` CSS rule
    never even matched to show it was clickable there in the first place.
    """
    _project_id, assessment_id = _create_assessment(application_id="APP-1")
    resp = client.get("/assessments")
    assert f'<tr class="run-row" data-href="/assessments/{assessment_id}">' in resp.text


def test_assessments_list_filters_by_type(client):
    _create_assessment(assessment_type="internal")
    _create_assessment(assessment_type="third_party")
    resp = client.get("/assessments", params={"type": "third_party"})
    assert resp.status_code == 200
    assert 'aria-selected="true"' in resp.text


def test_assessments_create_via_form(client, tmp_path):
    project_dir = tmp_path / "local-app"
    project_dir.mkdir()
    resp = client.post(
        "/assessments",
        data={
            "project_name": "My Local App",
            "project": str(project_dir),
            "assessment_type": "internal",
            "status": "ready",
            "application_id": "APP-9",
        },
        follow_redirects=False,
    )
    # Create -> Run is a guided flow: land on the Run Assessment page next,
    # not the detail page.
    assert resp.status_code == 303
    assert resp.headers["location"] == "/assessments/1/runs/new"

    resp = client.get("/assessments/1")
    assert resp.status_code == 200
    assert "My Local App" in resp.text
    assert "APP-9" in resp.text


def test_assessments_create_project_name_overrides_auto_derived_display_name(client, tmp_path):
    project_dir = tmp_path / "auto-derived-name"
    project_dir.mkdir()
    client.post(
        "/assessments",
        data={
            "project_name": "Custom Friendly Name",
            "project": str(project_dir),
            "assessment_type": "internal",
        },
        follow_redirects=False,
    )
    resp = client.get("/assessments")
    assert "Custom Friendly Name" in resp.text
    assert "auto-derived-name" not in resp.text


def test_assessments_create_accepts_public_github_url(client):
    resp = client.post(
        "/assessments",
        data={
            "project_name": "Hello World (fork)",
            "project": "https://github.com/octocat/Hello-World",
            "assessment_type": "third_party",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/assessments/1/runs/new"

    resp = client.get("/assessments/1")
    assert resp.status_code == 200
    assert "Hello World (fork)" in resp.text
    assert "Third-Party" in resp.text


def test_assessment_detail_404(client):
    resp = client.get("/assessments/999")
    assert resp.status_code == 404


def test_assessment_detail_shows_findings_and_runs(client, tmp_path):
    project_id, assessment_id = _create_assessment()
    repo = RunRepository()
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="security-architecture-review", skill_name="Security Architecture Review",
        agent_id="claude", confluence_urls=[], assessment_id=assessment_id,
    )
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=None, prompt_path=None,
        stderr_excerpt=None, high_count=2,
    )
    repo.close()

    resp = client.get(f"/assessments/{assessment_id}")
    assert resp.status_code == 200
    assert "Security Architecture Review" in resp.text
    assert "severity-bar__fill--high" in resp.text


def test_assessment_upload_ai_bom_and_counts(client, tmp_path):
    _, assessment_id = _create_assessment()
    files = {"file": ("ai-bom.json", '{"models": [{"name": "gemini"}], "tools": []}', "application/json")}
    resp = client.post(f"/assessments/{assessment_id}/attachments", files=files, follow_redirects=False)
    assert resp.status_code == 303

    resp = client.get(f"/assessments/{assessment_id}")
    assert resp.status_code == 200
    assert "ai-bom.json" in resp.text
    assert "1 model(s)" in resp.text


def test_assessment_upload_sanitizes_path_traversal_filename(client, tmp_path):
    """A malicious Content-Disposition filename must never escape the
    assessment's own attachment directory. Regression test for a real path
    traversal / arbitrary file write finding a threat-assessment run
    against this exact route confirmed. The route sanitizes to a safe
    basename (matching the CLI upload command's existing behavior) rather
    than rejecting outright, so a traversal attempt still succeeds -- just
    landing safely inside the assessment's own directory instead of where
    the attacker aimed it.
    """
    _, assessment_id = _create_assessment()
    files = {"file": ("../../escaped.txt", "pwned", "text/plain")}
    resp = client.post(f"/assessments/{assessment_id}/attachments", files=files, follow_redirects=False)
    assert resp.status_code == 303

    safe_path = tmp_path / "attachments" / str(assessment_id) / "escaped.txt"
    assert safe_path.exists()
    assert safe_path.read_text() == "pwned"
    # Must not have escaped to the parent attachments dir or above it.
    assert not (tmp_path / "attachments" / "escaped.txt").exists()
    assert not (tmp_path / "escaped.txt").exists()


def test_assessment_upload_sanitizes_absolute_path_filename(client, tmp_path):
    _, assessment_id = _create_assessment()
    absolute_target = tmp_path / "escaped-absolute.txt"

    files = {"file": (str(absolute_target), "pwned", "text/plain")}
    resp = client.post(f"/assessments/{assessment_id}/attachments", files=files, follow_redirects=False)
    assert resp.status_code == 303
    # Must NOT land at the attacker-specified absolute path.
    assert not absolute_target.exists()

    safe_path = tmp_path / "attachments" / str(assessment_id) / "escaped-absolute.txt"
    assert safe_path.exists()


def test_assessment_upload_rejects_dotdot_only_filename(client):
    _, assessment_id = _create_assessment()
    files = {"file": ("..", "pwned", "text/plain")}
    resp = client.post(f"/assessments/{assessment_id}/attachments", files=files)
    assert resp.status_code == 400


def _real_docx_bytes(text: str) -> bytes:
    import io

    import docx

    document = docx.Document()
    document.add_paragraph(text)
    buf = io.BytesIO()
    document.save(buf)
    return buf.getvalue()


def test_assessment_upload_vendor_doc_extracts_text_but_does_not_trigger_for_internal(client, monkeypatch):
    """A PDF/DOCX/PPTX upload is treated as a vendor document (and its
    text extracted) regardless of assessment type -- but the auto-trigger
    into a Third-Party Risk Assessment run only fires for third_party
    assessments; an internal assessment's vendor doc is just reference
    material, same as any other attachment.
    """
    calls = []
    monkeypatch.setattr(
        "secfoo.web.routes.assessments.execute_runs", lambda **kw: calls.append(kw) or []
    )
    _, assessment_id = _create_assessment(assessment_type="internal")

    files = {
        "file": (
            "vendor.docx", _real_docx_bytes("Vendor SOC 2 excerpt"),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
    }
    resp = client.post(f"/assessments/{assessment_id}/attachments", files=files, follow_redirects=False)
    assert resp.status_code == 303

    resp = client.get(f"/assessments/{assessment_id}")
    assert "vendor.docx" in resp.text
    assert calls == []


def test_assessment_upload_vendor_doc_auto_triggers_for_third_party(client, monkeypatch, tmp_path):
    monkeypatch.setattr("secfoo.web.routes.assessments.threading.Thread", _SyncThread)
    calls = []
    target_dir_snapshot = {}

    def fake_execute_runs(**kw):
        calls.append(kw)
        # The temp target directory is cleaned up in a `finally` right
        # after this returns -- inspect its contents now, while it exists.
        target_dir = Path(kw["target"])
        target_dir_snapshot["is_dir"] = target_dir.is_dir()
        target_dir_snapshot["files"] = {p.name: p.read_text() for p in target_dir.glob("*.txt")}
        return []

    monkeypatch.setattr("secfoo.web.routes.assessments.execute_runs", fake_execute_runs)
    project_id, assessment_id = _create_assessment(assessment_type="third_party")

    files = {
        "file": (
            "soc2-report.docx", _real_docx_bytes("SOC 2 Type II report body text"),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
    }
    resp = client.post(f"/assessments/{assessment_id}/attachments", files=files, follow_redirects=False)
    assert resp.status_code == 303

    assert len(calls) == 1
    call = calls[0]
    assert call["skill_ids"] == ["third-party-risk-assessment"]
    assert call["assessment_id"] == assessment_id
    assert call["project_id"] == project_id
    # The target was a synthetic temp directory, not the vendor's real
    # project identifier -- containing the extracted document text.
    assert target_dir_snapshot["is_dir"] is True
    assert len(target_dir_snapshot["files"]) == 1
    assert "SOC 2 Type II report body text" in next(iter(target_dir_snapshot["files"].values()))


def test_assessment_upload_vendor_doc_third_party_does_not_trigger_when_extraction_yields_no_text(
    client, monkeypatch
):
    monkeypatch.setattr("secfoo.web.routes.assessments.threading.Thread", _SyncThread)
    calls = []
    monkeypatch.setattr(
        "secfoo.web.routes.assessments.execute_runs", lambda **kw: calls.append(kw) or []
    )
    _, assessment_id = _create_assessment(assessment_type="third_party")

    # A .pdf that isn't actually a valid PDF -- extraction degrades to "",
    # so the background function should return early without ever calling
    # execute_runs, rather than running an assessment against nothing.
    files = {"file": ("corrupt.pdf", b"%PDF-1.4\nnot a real pdf", "application/pdf")}
    resp = client.post(f"/assessments/{assessment_id}/attachments", files=files, follow_redirects=False)
    assert resp.status_code == 303
    assert calls == []


def test_assessment_upload_vendor_doc_rejects_oversized_file(client, monkeypatch):
    monkeypatch.setattr("secfoo.docext.MAX_UPLOAD_BYTES", 10)
    _, assessment_id = _create_assessment(assessment_type="third_party")

    files = {"file": ("big.pdf", b"%PDF-1.4\n" + b"x" * 100, "application/pdf")}
    resp = client.post(f"/assessments/{assessment_id}/attachments", files=files)
    assert resp.status_code == 413

    resp = client.get(f"/assessments/{assessment_id}")
    assert "big.pdf" not in resp.text


def test_assessment_delete_via_post(client):
    _, assessment_id = _create_assessment()
    resp = client.post(f"/assessments/{assessment_id}/delete")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}

    resp = client.get(f"/assessments/{assessment_id}")
    assert resp.status_code == 404


def test_assessment_delete_unknown_404(client):
    resp = client.post("/assessments/999/delete")
    assert resp.status_code == 404


class _SyncThread:
    """Stand-in for threading.Thread that runs its target synchronously in
    the calling thread, so tests can assert on execute_runs' call args
    deterministically without racing a real background thread.
    """

    def __init__(self, target=None, kwargs=None, daemon=None):
        self._target = target
        self._kwargs = kwargs or {}

    def start(self):
        self._target(**self._kwargs)


def test_assessment_detail_links_to_run_assessment_page(client):
    _, assessment_id = _create_assessment()
    resp = client.get(f"/assessments/{assessment_id}")
    assert resp.status_code == 200
    assert "Run Assessment" in resp.text
    assert f'href="/assessments/{assessment_id}/runs/new"' in resp.text


def test_assessment_run_form_page_renders(client):
    _, assessment_id = _create_assessment()
    resp = client.get(f"/assessments/{assessment_id}/runs/new")
    assert resp.status_code == 200
    assert 'name="skill"' in resp.text
    assert 'name="agent"' in resp.text
    assert f'action="/assessments/{assessment_id}/runs"' in resp.text


def test_assessment_run_form_page_404_for_unknown_assessment(client):
    resp = client.get("/assessments/999/runs/new")
    assert resp.status_code == 404


def test_assessment_new_form_page_renders(client):
    resp = client.get("/assessments/new")
    assert resp.status_code == 200
    assert 'name="project_name"' in resp.text
    assert 'name="project"' in resp.text
    assert 'action="/assessments"' in resp.text


def test_create_then_run_flow_end_to_end(client, tmp_path):
    """Full guided flow: New Assessment page -> submit -> redirected to the
    Run Assessment page -> submit -> redirected to the detail page.
    """
    project_dir = tmp_path / "flow-app"
    project_dir.mkdir()

    resp = client.get("/assessments/new")
    assert resp.status_code == 200

    resp = client.post(
        "/assessments",
        data={"project_name": "Flow App", "project": str(project_dir), "assessment_type": "internal"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    run_form_url = resp.headers["location"]

    resp = client.get(run_form_url)
    assert resp.status_code == 200
    assert "Flow App" in resp.text


def test_trigger_run_calls_execute_runs_with_expected_args(monkeypatch, client):
    project_id, assessment_id = _create_assessment()
    monkeypatch.setattr("secfoo.web.routes.assessments.threading.Thread", _SyncThread)

    captured = {}

    def fake_execute_runs(**kwargs):
        captured.update(kwargs)
        return []

    monkeypatch.setattr("secfoo.web.routes.assessments.execute_runs", fake_execute_runs)

    resp = client.post(
        f"/assessments/{assessment_id}/runs",
        data={
            "skill": ["security-architecture-review", "prompt-review"],
            "agent": "claude",
            "depth": "quick",
            "confluence": "https://a.example/x\nhttps://a.example/y\n",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == f"/assessments/{assessment_id}"

    assert captured["skill_ids"] == ["security-architecture-review", "prompt-review"]
    assert captured["agent_id"] == "claude"
    assert captured["depth"] == "quick"
    assert captured["assessment_id"] == assessment_id
    assert captured["confluence_urls"] == ["https://a.example/x", "https://a.example/y"]
    assert captured["target"] == "https://github.com/org/vendor-app"


def test_trigger_run_unknown_skill_returns_400(client):
    _, assessment_id = _create_assessment()
    resp = client.post(
        f"/assessments/{assessment_id}/runs",
        data={"skill": ["not-a-real-skill"], "agent": "claude", "depth": "quick"},
    )
    assert resp.status_code == 400


def test_trigger_run_unknown_agent_returns_400(client):
    _, assessment_id = _create_assessment()
    resp = client.post(
        f"/assessments/{assessment_id}/runs",
        data={"skill": ["security-architecture-review"], "agent": "not-a-real-agent", "depth": "quick"},
    )
    assert resp.status_code == 400


def test_trigger_run_unknown_depth_returns_400(client):
    _, assessment_id = _create_assessment()
    resp = client.post(
        f"/assessments/{assessment_id}/runs",
        data={"skill": ["security-architecture-review"], "agent": "claude", "depth": "extreme"},
    )
    assert resp.status_code == 400


def test_trigger_run_unknown_assessment_returns_404(client):
    resp = client.post(
        "/assessments/999/runs",
        data={"skill": ["security-architecture-review"], "agent": "claude", "depth": "quick"},
    )
    assert resp.status_code == 404


def test_assessment_detail_shows_running_banner_and_auto_refresh(client, tmp_path):
    project_id, assessment_id = _create_assessment()
    repo = RunRepository()
    repo.create_run(
        project_id=project_id, skill_id="security-architecture-review", skill_name="Security Architecture Review",
        agent_id="claude", confluence_urls=[], assessment_id=assessment_id,
    )
    repo.close()

    resp = client.get(f"/assessments/{assessment_id}")
    assert resp.status_code == 200
    assert "refreshes automatically" in resp.text
    assert '<meta http-equiv="refresh" content="5">' in resp.text


def test_third_party_page_lists_only_third_party(client):
    _create_assessment(assessment_type="internal")
    _create_assessment(assessment_type="third_party")
    resp = client.get("/third-party")
    assert resp.status_code == 200
    assert "1 third-party assessment" in resp.text


def test_third_party_page_empty_state(client):
    resp = client.get("/third-party")
    assert resp.status_code == 200
    assert "No third-party assessments yet" in resp.text
    assert "Vendor CCM v4 conformance" in resp.text


def test_third_party_page_shows_ccm_heatmap_for_a_real_vendor_assessment(client):
    from secfoo.web import third_party_dashboard

    project_id, assessment_id = _create_assessment(assessment_type="third_party")
    repo = RunRepository()
    run_uuid = repo.create_run(
        project_id=project_id, skill_id=third_party_dashboard.SKILL_ID, skill_name="Third-Party Risk Assessment",
        agent_id="claude", confluence_urls=[], assessment_id=assessment_id,
    )
    report_path = Path(repo.db_path).parent / "third-party-report.md"
    report_path.write_text(
        "# Third-Party Risk Assessment Report\n\n## 3. CCM Domain Conformance\n"
        "| Domain | Code | Conformance | Evidence |\n|---|---|---|---|\n"
        "| Audit & Assurance | A&A | Conformant | soc2.pdf |\n"
    )
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(report_path),
        prompt_path=None, stderr_excerpt=None,
    )
    repo.close()

    resp = client.get("/third-party")
    assert resp.status_code == 200
    # Jinja autoescapes "&" to "&amp;" in the rendered HTML.
    assert "A&amp;A" in resp.text
    assert "100%" in resp.text


def test_responsible_ai_page_empty_state(client):
    resp = client.get("/responsible-ai")
    assert resp.status_code == 200
    assert "No assessments have a Responsible AI risk rating yet" in resp.text


def test_responsible_ai_page_shows_derived_risk(client, tmp_path):
    project_id, assessment_id = _create_assessment()
    repo = RunRepository()
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="responsible-ai-compliance", skill_name="Responsible AI Compliance",
        agent_id="claude", confluence_urls=[], assessment_id=assessment_id,
    )
    report_path = tmp_path / "report.md"
    report_path.write_text("# Report\n\n## Summary\n**Overall risk rating:** High.\n")
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=str(report_path),
        prompt_path=None, stderr_excerpt=None,
    )
    repo.close()

    resp = client.get("/responsible-ai")
    assert resp.status_code == 200
    assert "high-risk" in resp.text
    assert "provisional" in resp.text
