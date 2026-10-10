from __future__ import annotations

import json
import os

from typer.testing import CliRunner

from secfoo import memory
from secfoo.cli import app
from secfoo.runner import RunOutcome
from secfoo.storage.repository import RunRepository

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


def _service(monkeypatch, *, whoami=None):
    calls = []

    def _fake(request, timeout=None):
        calls.append(request.full_url)
        if request.full_url.endswith("/verify"):
            return _FakeResponse({"api_key": "sfm_free_abc"})
        if request.full_url.endswith("/whoami"):
            return _FakeResponse(whoami or {"plan": "free", "daily_quota": 200, "used_today": 0})
        return _FakeResponse({"status": "code_sent"})

    monkeypatch.setattr("secfoo.memory.urllib.request.urlopen", _fake)
    return calls


def test_interactive_signup_sends_code_then_saves_key(monkeypatch):
    calls = _service(monkeypatch)
    monkeypatch.setattr("secfoo.cli._is_interactive", lambda: True)

    result = runner.invoke(app, ["memory", "signup", "--email", "dev@example.com", "--url", "https://m.test"],
                           input="424242\n")

    assert result.exit_code == 0, result.output
    assert calls == ["https://m.test/v1/signup", "https://m.test/v1/signup/verify"]
    assert memory.load_memory_config() == memory.MemoryConfig(api_key="sfm_free_abc", url="https://m.test")


def test_non_interactive_signup_is_two_steps(monkeypatch):
    calls = _service(monkeypatch)
    monkeypatch.setattr("secfoo.cli._is_interactive", lambda: False)

    first = runner.invoke(app, ["memory", "signup", "--email", "dev@example.com"])
    assert first.exit_code == 0
    assert "--code <code>" in first.output
    assert memory.load_memory_config() is None

    second = runner.invoke(app, ["memory", "signup", "--email", "dev@example.com", "--code", "424242"])
    assert second.exit_code == 0, second.output
    assert calls[-1].endswith("/v1/signup/verify")
    assert memory.load_memory_config().api_key == "sfm_free_abc"


def test_signup_without_email_off_a_terminal_fails_cleanly(monkeypatch):
    monkeypatch.setattr("secfoo.cli._is_interactive", lambda: False)
    result = runner.invoke(app, ["memory", "signup"])
    assert result.exit_code == 1


def test_login_validates_before_saving(monkeypatch):
    _service(monkeypatch, whoami={"plan": "team", "daily_quota": 5000, "used_today": 12})
    result = runner.invoke(app, ["memory", "login", "--api-key", " sfm_team_x "])
    assert result.exit_code == 0, result.output
    assert "plan team" in result.output
    assert memory.load_memory_config().api_key == "sfm_team_x"


def test_login_with_a_rejected_key_saves_nothing(monkeypatch):
    import urllib.error
    from io import BytesIO

    def _fake(request, timeout=None):
        raise urllib.error.HTTPError(request.full_url, 401, "no", {}, BytesIO(b'{"detail": "invalid key"}'))

    monkeypatch.setattr("secfoo.memory.urllib.request.urlopen", _fake)
    result = runner.invoke(app, ["memory", "login", "--api-key", "bad"])
    assert result.exit_code == 1
    assert memory.load_memory_config() is None


def test_status_and_logout(monkeypatch, tmp_path):
    monkeypatch.setattr("secfoo.settings.CONFIG_PATH", tmp_path / "config.toml")
    _service(monkeypatch)
    assert "Not set up" in runner.invoke(app, ["memory", "status"]).output

    memory.save_memory_config(memory.MemoryConfig(api_key="k"))
    status = runner.invoke(app, ["memory", "status"])
    assert "on" in status.output
    assert "plan free" in status.output

    monkeypatch.setenv("SECFOO_MEMORY", "off")
    assert "Disabled by SECFOO_MEMORY" in runner.invoke(app, ["memory", "status"]).output

    assert runner.invoke(app, ["memory", "logout"]).exit_code == 0
    assert memory.load_memory_config() is None
    assert "No secfoo-memory key saved" in runner.invoke(app, ["memory", "logout"]).output


def test_run_no_memory_disables_memory_for_the_process(monkeypatch):
    seen = {}

    def _fake_execute_runs(**kwargs):
        seen["env"] = os.environ.get("SECFOO_MEMORY")
        return [RunOutcome(run_uuid="u", skill_id="sast", skill_name="SAST", agent_id="claude", status="success",
                           exit_code=0, duration_seconds=1.0, report_path="/tmp/r.md")]

    monkeypatch.setattr("secfoo.cli.execute_runs", _fake_execute_runs)
    monkeypatch.setattr("secfoo.cli._is_interactive", lambda: False)
    result = runner.invoke(app, ["run", "--skill", "sast", "--no-memory"])
    assert result.exit_code == 0, result.output
    assert seen["env"] == "off"


def test_findings_export_emits_jsonl_and_can_drop_locations(monkeypatch, tmp_path):
    db_path = tmp_path / "db.sqlite"
    monkeypatch.setattr("secfoo.storage.repository.DB_PATH", db_path)
    monkeypatch.setattr("secfoo.storage.repository.ensure_store_dirs", lambda: None)
    repo = RunRepository(db_path=db_path)
    project_id = repo.upsert_project(identifier="/p", display_name="proj", kind="local")
    run_id = repo.get_run(repo.create_run(project_id=project_id, skill_id="sast", skill_name="SAST",
                                          agent_id="claude", confluence_urls=[])).id
    repo.upsert_sast_finding(
        project_id=project_id, fingerprint="a", current_ref="F1", title="SQLi", severity="High", cwe="CWE-89",
        owasp=None, verdict="Confirmed", location_file="app/db.py", location_line="4", cvss_vector=None,
        cvss_score=None, run_id=run_id, language="python", construct="raw sql from request parameter",
    )
    repo.upsert_secret_finding(
        project_id=project_id, fingerprint="s", run_id=run_id, current_ref="S1", secret_type="API token",
        location_file="ci.yml", severity="High",
    )
    repo.close()

    result = runner.invoke(app, ["findings", "export", "--skill", "sast"])
    assert result.exit_code == 0, result.output
    records = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(records) == 1
    record = records[0]
    assert record["skill_id"] == "sast"
    assert record["project"] == "proj"
    assert record["construct"] == "raw sql from request parameter"
    assert record["location_file"] == "app/db.py"
    assert "id" not in record and "project_id" not in record and "first_seen_run_id" not in record

    out = tmp_path / "f.jsonl"
    result = runner.invoke(app, ["findings", "export", "--no-locations", "--output", str(out)])
    assert result.exit_code == 0
    records = [json.loads(line) for line in out.read_text().splitlines()]
    assert {r["skill_id"] for r in records} == {"sast", "secret-scanning"}
    assert all("location_file" not in r and "code_region_hash" not in r for r in records)

    assert runner.invoke(app, ["findings", "export", "--status", "closed"]).stdout == ""
