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
        "miss", "create",
        "--project", str(project_dir),
        "--title", overrides.get("title", "SSRF via webhook URL"),
        "--discovered-at", overrides.get("discovered_at", "2026-08-01"),
    ]
    if "description" in overrides:
        args += ["--description", overrides["description"]]
    if "discovered_by" in overrides:
        args += ["--discovered-by", overrides["discovered_by"]]
    if "run" in overrides:
        args += ["--run", overrides["run"]]
    return runner.invoke(app, args)


def test_miss_create_and_list(monkeypatch, tmp_path):
    result = _create(monkeypatch, tmp_path, discovered_by="Pen test Q3")
    assert result.exit_code == 0
    assert "Recorded post-build finding 1" in result.stdout

    result = runner.invoke(app, ["miss", "list"])
    assert result.exit_code == 0
    assert "SSRF via webhook URL" in result.stdout
    assert "Pen test Q3" in result.stdout


def test_miss_list_empty(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(app, ["miss", "list"])
    assert result.exit_code == 0
    assert "No post-build findings recorded" in result.stdout


def test_miss_show(monkeypatch, tmp_path):
    _create(monkeypatch, tmp_path, description="found in pen test")
    result = runner.invoke(app, ["miss", "show", "1"])
    assert result.exit_code == 0
    assert "SSRF via webhook URL" in result.stdout
    assert "found in pen test" in result.stdout


def test_miss_show_unknown_exits_nonzero(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(app, ["miss", "show", "999"])
    assert result.exit_code == 1


def test_miss_create_with_unknown_run_exits_nonzero(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    project_dir = tmp_path / "myproject"
    project_dir.mkdir(exist_ok=True)
    result = runner.invoke(
        app,
        [
            "miss", "create",
            "--project", str(project_dir),
            "--title", "x",
            "--discovered-at", "2026-08-01",
            "--run", "not-a-real-run-uuid",
        ],
    )
    assert result.exit_code == 1
    assert "No run found" in result.output


def test_miss_delete(monkeypatch, tmp_path):
    _create(monkeypatch, tmp_path)
    result = runner.invoke(app, ["miss", "delete", "1"])
    assert result.exit_code == 0

    result = runner.invoke(app, ["miss", "show", "1"])
    assert result.exit_code == 1


def test_miss_delete_unknown_exits_nonzero(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(app, ["miss", "delete", "999"])
    assert result.exit_code == 1
