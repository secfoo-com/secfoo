from __future__ import annotations

from typer.testing import CliRunner

from secfoo.cli import app

runner = CliRunner()


def _configure_store(monkeypatch, tmp_path):
    db_path = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", db_path)
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    monkeypatch.setattr("secfoo.config.ATTACHMENTS_DIR", tmp_path / "attachments")


def test_assessment_create_and_list(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    project_dir = tmp_path / "myproject"
    project_dir.mkdir()

    result = runner.invoke(
        app,
        ["assessment", "create", "--project", str(project_dir), "--type", "internal", "--app-id", "APP-1"],
    )
    assert result.exit_code == 0
    assert "Created assessment 1" in result.stdout

    result = runner.invoke(app, ["assessment", "list"])
    assert result.exit_code == 0
    assert "APP-1" in result.stdout
    assert "myproject" in result.stdout


def test_assessment_create_with_custom_name_overrides_auto_derived(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    project_dir = tmp_path / "myproject"
    project_dir.mkdir()

    result = runner.invoke(
        app,
        ["assessment", "create", "--project", str(project_dir), "--type", "internal", "--name", "Friendly Name"],
    )
    assert result.exit_code == 0

    result = runner.invoke(app, ["assessment", "list"])
    # Rich wraps/truncates long cell text, so check fragments rather than
    # the literal joined string.
    assert "Friendly" in result.stdout
    assert "Name" in result.stdout
    assert "myproject" not in result.stdout


def test_assessment_create_accepts_public_github_url(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(
        app,
        [
            "assessment", "create",
            "--project", "https://github.com/octocat/Hello-World",
            "--type", "third-party",
        ],
    )
    assert result.exit_code == 0
    assert "Created assessment 1" in result.stdout

    result = runner.invoke(app, ["assessment", "list"])
    # Rich truncates long cell text with an ellipsis in the CLI's compact
    # table width, so check a safe prefix rather than the literal string.
    assert "octocat/H" in result.stdout
    assert "third_par" in result.stdout


def test_assessment_list_empty(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(app, ["assessment", "list"])
    assert result.exit_code == 0
    assert "No assessments found" in result.stdout


def test_assessment_show_unknown_exits_nonzero(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(app, ["assessment", "show", "999"])
    assert result.exit_code == 1


def test_assessment_update_requires_a_field(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    project_dir = tmp_path / "myproject"
    project_dir.mkdir()
    runner.invoke(app, ["assessment", "create", "--project", str(project_dir), "--type", "internal"])

    result = runner.invoke(app, ["assessment", "update", "1"])
    assert result.exit_code == 1
    assert "Nothing to update" in result.output


def test_assessment_update_status(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    project_dir = tmp_path / "myproject"
    project_dir.mkdir()
    runner.invoke(app, ["assessment", "create", "--project", str(project_dir), "--type", "internal"])

    result = runner.invoke(app, ["assessment", "update", "1", "--status", "completed"])
    assert result.exit_code == 0

    result = runner.invoke(app, ["assessment", "show", "1"])
    assert "Status: completed" in result.stdout


def test_assessment_upload_ai_bom_parses_and_reports_counts(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    project_dir = tmp_path / "myproject"
    project_dir.mkdir()
    runner.invoke(app, ["assessment", "create", "--project", str(project_dir), "--type", "internal"])

    bom_file = tmp_path / "ai-bom.json"
    bom_file.write_text('{"models": [{"name": "gemini"}], "tools": [{"name": "langchain"}]}')

    result = runner.invoke(app, ["assessment", "upload", "1", str(bom_file)])
    assert result.exit_code == 0
    assert "Parsed 1 model(s), 1 tool(s)" in result.stdout

    result = runner.invoke(app, ["assessment", "show", "1"])
    assert "ai-bom.json" in result.stdout
    assert "ai_bom" in result.stdout


def test_assessment_upload_malformed_ai_bom_still_uploads_with_warning(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    project_dir = tmp_path / "myproject"
    project_dir.mkdir()
    runner.invoke(app, ["assessment", "create", "--project", str(project_dir), "--type", "internal"])

    bom_file = tmp_path / "ai-bom.json"
    bom_file.write_text("{not valid json")

    result = runner.invoke(app, ["assessment", "upload", "1", str(bom_file)])
    assert result.exit_code == 0
    assert "AI-BOM parsing failed" in result.output


def test_assessment_upload_missing_file_exits_nonzero(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    project_dir = tmp_path / "myproject"
    project_dir.mkdir()
    runner.invoke(app, ["assessment", "create", "--project", str(project_dir), "--type", "internal"])

    result = runner.invoke(app, ["assessment", "upload", "1", str(tmp_path / "nope.json")])
    assert result.exit_code == 1


def test_assessment_delete(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    project_dir = tmp_path / "myproject"
    project_dir.mkdir()
    runner.invoke(app, ["assessment", "create", "--project", str(project_dir), "--type", "internal"])

    result = runner.invoke(app, ["assessment", "delete", "1"])
    assert result.exit_code == 0

    result = runner.invoke(app, ["assessment", "show", "1"])
    assert result.exit_code == 1


def test_assessment_delete_unknown_exits_nonzero(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(app, ["assessment", "delete", "999"])
    assert result.exit_code == 1


def test_run_command_threads_assessment_id_through(monkeypatch, tmp_path):
    captured = {}

    def fake_execute_runs(**kwargs):
        captured["assessment_id"] = kwargs["assessment_id"]
        from secfoo.runner import RunOutcome

        return [
            RunOutcome(
                run_uuid="u1",
                skill_id="security-architecture-review",
                skill_name="Security Architecture Review",
                agent_id="claude",
                status="success",
                exit_code=0,
                duration_seconds=1.0,
                report_path="/tmp/r.md",
            )
        ]

    monkeypatch.setattr("secfoo.cli.execute_runs", fake_execute_runs)
    result = runner.invoke(app, ["run", "--skill", "security-architecture-review", "--agent", "claude", "--assessment", "7"])
    assert result.exit_code == 0
    assert captured["assessment_id"] == 7
