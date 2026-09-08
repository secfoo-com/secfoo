from __future__ import annotations

import json
import urllib.error

from typer.testing import CliRunner

from secfoo.cli import app

runner = CliRunner()


class _FakeResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _configure_store(monkeypatch, tmp_path):
    db_path = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", db_path)
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)

    # cloud.toml's default path is bound in two places at import time --
    # secfoo.cli (used by the not-connected checks) and secfoo.cloud (used
    # by load/save_cloud_config's own default) -- both need patching for a
    # fully isolated test, same trap documented in repository.py's
    # contextvar fix.
    cloud_config_path = tmp_path / "cloud.toml"
    monkeypatch.setattr("secfoo.cli.CLOUD_CONFIG_PATH", cloud_config_path)
    monkeypatch.setattr("secfoo.cloud.CLOUD_CONFIG_PATH", cloud_config_path)


def _mock_urlopen(monkeypatch, *, response: dict | None = None, raises: Exception | None = None):
    def _fake_urlopen(request, timeout=None):
        if raises is not None:
            raise raises
        return _FakeResponse(response or {})

    monkeypatch.setattr("secfoo.cloud.urllib.request.urlopen", _fake_urlopen)


def test_cloud_login_success(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    _mock_urlopen(monkeypatch, response={"tenant_slug": "acme", "tenant_display_name": "Acme Corp", "scope": "ingest"})

    result = runner.invoke(app, ["cloud", "login", "--api-key", "sfc_ingest_abc"])
    assert result.exit_code == 0
    assert "Acme Corp" in result.stdout
    assert (tmp_path / "cloud.toml").exists()


def test_cloud_login_rejects_view_scoped_key(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    _mock_urlopen(monkeypatch, response={"tenant_slug": "acme", "tenant_display_name": "Acme Corp", "scope": "view"})

    result = runner.invoke(app, ["cloud", "login", "--api-key", "sfc_view_abc"])
    assert result.exit_code == 1
    assert "scoped for 'view'" in result.output
    assert not (tmp_path / "cloud.toml").exists()


def test_cloud_login_fails_on_invalid_key(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    _mock_urlopen(monkeypatch, raises=urllib.error.HTTPError("url", 401, "Unauthorized", {}, None))

    result = runner.invoke(app, ["cloud", "login", "--api-key", "bad-key"])
    assert result.exit_code == 1
    assert "Login failed" in result.output
    assert not (tmp_path / "cloud.toml").exists()


def test_cloud_status_when_not_connected(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(app, ["cloud", "status"])
    assert result.exit_code == 0
    assert "Not connected" in result.stdout


def test_cloud_status_when_connected(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    _mock_urlopen(monkeypatch, response={"tenant_slug": "acme", "tenant_display_name": "Acme Corp", "scope": "ingest"})
    runner.invoke(app, ["cloud", "login", "--api-key", "sfc_ingest_abc"])

    result = runner.invoke(app, ["cloud", "status"])
    assert result.exit_code == 0
    assert "Acme Corp" in result.stdout
    assert "Unsynced local runs: 0" in result.stdout


def test_cloud_status_reports_unreachable_portal_without_crashing(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    _mock_urlopen(monkeypatch, response={"tenant_slug": "acme", "tenant_display_name": "Acme Corp", "scope": "ingest"})
    runner.invoke(app, ["cloud", "login", "--api-key", "sfc_ingest_abc"])

    _mock_urlopen(monkeypatch, raises=urllib.error.URLError("Connection refused"))
    result = runner.invoke(app, ["cloud", "status"])
    assert result.exit_code == 0
    assert "couldn't reach it" in result.output


def test_cloud_logout_when_not_connected(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(app, ["cloud", "logout"])
    assert result.exit_code == 0
    assert "Not connected" in result.stdout


def test_cloud_logout_removes_config(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    _mock_urlopen(monkeypatch, response={"tenant_slug": "acme", "tenant_display_name": "Acme Corp", "scope": "ingest"})
    runner.invoke(app, ["cloud", "login", "--api-key", "sfc_ingest_abc"])
    assert (tmp_path / "cloud.toml").exists()

    result = runner.invoke(app, ["cloud", "logout"])
    assert result.exit_code == 0
    assert not (tmp_path / "cloud.toml").exists()


def test_cloud_sync_when_not_connected(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    result = runner.invoke(app, ["cloud", "sync"])
    assert result.exit_code == 1
    assert "Not connected" in result.output


def test_cloud_sync_with_nothing_to_sync(monkeypatch, tmp_path):
    _configure_store(monkeypatch, tmp_path)
    _mock_urlopen(monkeypatch, response={"tenant_slug": "acme", "tenant_display_name": "Acme Corp", "scope": "ingest"})
    runner.invoke(app, ["cloud", "login", "--api-key", "sfc_ingest_abc"])

    result = runner.invoke(app, ["cloud", "sync"])
    assert result.exit_code == 0
    assert "Nothing to sync" in result.stdout


def test_cloud_sync_pushes_unsynced_runs(monkeypatch, tmp_path):
    from secfoo.storage.repository import RunRepository

    _configure_store(monkeypatch, tmp_path)
    _mock_urlopen(monkeypatch, response={"tenant_slug": "acme", "tenant_display_name": "Acme Corp", "scope": "ingest"})
    runner.invoke(app, ["cloud", "login", "--api-key", "sfc_ingest_abc"])

    repo = RunRepository(db_path=tmp_path / "db.sqlite")
    project_id = repo.upsert_project("https://github.com/acme/app", "acme/app", "github")
    run_uuid = repo.create_run(
        project_id=project_id, skill_id="sast", skill_name="SAST", agent_id="claude", confluence_urls=[],
    )
    repo.complete_run(
        run_uuid, status="success", exit_code=0, duration_seconds=1.0, report_path=None,
        prompt_path=None, stderr_excerpt=None,
    )
    repo.close()

    _mock_urlopen(monkeypatch, response={"server_run_id": run_uuid, "status": "recorded"})
    result = runner.invoke(app, ["cloud", "sync"])
    assert result.exit_code == 0
    assert "Synced 1/1" in result.stdout

    repo2 = RunRepository(db_path=tmp_path / "db.sqlite")
    assert repo2.get_run(run_uuid).cloud_synced_at is not None
    repo2.close()
