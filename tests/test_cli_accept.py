from __future__ import annotations

from typer.testing import CliRunner

from secfoo.cli import app

runner = CliRunner()


def _configure_store(monkeypatch, tmp_path):
    db_path = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", db_path)
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)


def _create(monkeypatch, tmp_path, **overrides):
    _configure_store(monkeypatch, tmp_path)
    project_dir = tmp_path / "myproject"
    project_dir.mkdir(exist_ok=True)
    args = [
        "accept", "create",
        "--project", str(project_dir),
        "--threat-id", overrides.get("threat_id", "T4"),
        "--title", overrides.get("title", "Legacy endpoint risk"),
        "--justification", overrides.get("justification", "Decommissioned next quarter"),
        "--accepted-by", overrides.get("accepted_by", "Jane Doe"),
    ]
    if "expires_at" in overrides:
        args += ["--expires-at", overrides["expires_at"]]
    if "run" in overrides:
        args += ["--run", overrides["run"]]
    return runner.invoke(app, args)


def test_accept_create_and_list(monkeypatch, tmp_path):
    result = _create(monkeypatch, tmp_path)
    assert result.exit_code == 0
    assert "Recorded acceptance 1" in result.stdout

    result = runner.invoke(app, ["accept", "list"])
    assert result.exit_code == 0
    assert "Legacy endpoint risk" in result.stdout
    assert "Jane Doe" in result.stdout
    assert "T4" in result.stdout


def test_accept_list_empty(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(app, ["accept", "list"])
    assert result.exit_code == 0
    assert "No threat acceptances recorded" in result.stdout


def test_accept_show(monkeypatch, tmp_path):
    _create(monkeypatch, tmp_path)
    result = runner.invoke(app, ["accept", "show", "1"])
    assert result.exit_code == 0
    assert "T4" in result.stdout
    assert "Status: active" in result.stdout


def test_accept_show_unknown_exits_nonzero(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(app, ["accept", "show", "999"])
    assert result.exit_code == 1


def test_accept_create_with_unknown_run_exits_nonzero(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    project_dir = tmp_path / "myproject"
    project_dir.mkdir(exist_ok=True)
    result = runner.invoke(
        app,
        [
            "accept", "create",
            "--project", str(project_dir),
            "--threat-id", "T1",
            "--title", "x",
            "--justification", "y",
            "--accepted-by", "z",
            "--run", "not-a-real-run-uuid",
        ],
    )
    assert result.exit_code == 1
    assert "No run found" in result.output


def test_accept_update_status(monkeypatch, tmp_path):
    _create(monkeypatch, tmp_path)
    result = runner.invoke(app, ["accept", "update", "1", "--status", "revoked"])
    assert result.exit_code == 0

    result = runner.invoke(app, ["accept", "show", "1"])
    assert "Status: revoked" in result.stdout


def test_accept_update_requires_a_field(monkeypatch, tmp_path):
    _create(monkeypatch, tmp_path)
    result = runner.invoke(app, ["accept", "update", "1"])
    assert result.exit_code == 1
    assert "Nothing to update" in result.output


def test_accept_delete(monkeypatch, tmp_path):
    _create(monkeypatch, tmp_path)
    result = runner.invoke(app, ["accept", "delete", "1"])
    assert result.exit_code == 0

    result = runner.invoke(app, ["accept", "show", "1"])
    assert result.exit_code == 1


def test_accept_delete_unknown_exits_nonzero(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(app, ["accept", "delete", "999"])
    assert result.exit_code == 1


def test_accept_list_filters_by_status(monkeypatch, tmp_path):
    _create(monkeypatch, tmp_path, threat_id="T1", title="one")
    _create(monkeypatch, tmp_path, threat_id="T2", title="two")
    runner.invoke(app, ["accept", "update", "2", "--status", "revoked"])

    result = runner.invoke(app, ["accept", "list", "--status", "active"])
    assert "one" in result.stdout
    assert "two" not in result.stdout
