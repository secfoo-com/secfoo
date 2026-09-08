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
        "exception", "create",
        "--project", str(project_dir),
        "--title", overrides.get("title", "Legacy auth exemption"),
        "--justification", overrides.get("justification", "migration in progress"),
        "--granted-by", overrides.get("granted_by", "Jane Doe"),
        "--expires-at", overrides.get("expires_at", "2099-01-01"),
    ]
    if "control" in overrides:
        args += ["--control", overrides["control"]]
    return runner.invoke(app, args)


def test_exception_create_and_list(monkeypatch, tmp_path):
    result = _create(monkeypatch, tmp_path, control="IAM")
    assert result.exit_code == 0
    assert "Created exception 1" in result.stdout

    result = runner.invoke(app, ["exception", "list"])
    assert result.exit_code == 0
    assert "Legacy auth exemption" in result.stdout
    assert "IAM" in result.stdout


def test_exception_list_empty(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(app, ["exception", "list"])
    assert result.exit_code == 0
    assert "No exceptions found" in result.stdout


def test_exception_show(monkeypatch, tmp_path):
    _create(monkeypatch, tmp_path)
    result = runner.invoke(app, ["exception", "show", "1"])
    assert result.exit_code == 0
    assert "Legacy auth exemption" in result.stdout
    assert "Status: active" in result.stdout


def test_exception_show_unknown_exits_nonzero(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(app, ["exception", "show", "999"])
    assert result.exit_code == 1


def test_exception_update_status(monkeypatch, tmp_path):
    _create(monkeypatch, tmp_path)
    result = runner.invoke(app, ["exception", "update", "1", "--status", "revoked"])
    assert result.exit_code == 0

    result = runner.invoke(app, ["exception", "show", "1"])
    assert "Status: revoked" in result.stdout


def test_exception_update_requires_a_field(monkeypatch, tmp_path):
    _create(monkeypatch, tmp_path)
    result = runner.invoke(app, ["exception", "update", "1"])
    assert result.exit_code == 1
    assert "Nothing to update" in result.output


def test_exception_delete(monkeypatch, tmp_path):
    _create(monkeypatch, tmp_path)
    result = runner.invoke(app, ["exception", "delete", "1"])
    assert result.exit_code == 0

    result = runner.invoke(app, ["exception", "show", "1"])
    assert result.exit_code == 1


def test_exception_delete_unknown_exits_nonzero(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(app, ["exception", "delete", "999"])
    assert result.exit_code == 1


def test_exception_list_filters_by_status(monkeypatch, tmp_path):
    _create(monkeypatch, tmp_path, title="one")
    _create(monkeypatch, tmp_path, title="two")
    runner.invoke(app, ["exception", "update", "2", "--status", "revoked"])

    result = runner.invoke(app, ["exception", "list", "--status", "active"])
    assert "one" in result.stdout
    assert "two" not in result.stdout
