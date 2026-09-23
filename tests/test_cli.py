from __future__ import annotations

import pytest
from typer.testing import CliRunner

from secfoo import mcp as mcp_module
from secfoo.cli import app
from secfoo.runner import RunOutcome
from secfoo.settings import Defaults, MCPServerConfig, SecfooConfig
from secfoo.skills.loader import load_all_skills
from secfoo.storage.models import CostRow, ProjectRecord

runner = CliRunner()


def _outcome(status: str) -> RunOutcome:
    return RunOutcome(
        run_uuid="u1",
        skill_id="security-architecture-review",
        skill_name="Security Architecture Review",
        agent_id="claude",
        status=status,
        exit_code=0 if status == "success" else 1,
        duration_seconds=1.2,
        report_path="/tmp/r.md",
    )


def test_run_command_success_exits_zero(monkeypatch):
    monkeypatch.setattr("secfoo.cli.execute_runs", lambda **kwargs: [_outcome("success")])
    result = runner.invoke(app, ["run", "--skill", "security-architecture-review", "--agent", "claude"])
    assert result.exit_code == 0
    assert "success" in result.stdout


def test_run_command_nonzero_exit_on_failed_outcome(monkeypatch):
    monkeypatch.setattr("secfoo.cli.execute_runs", lambda **kwargs: [_outcome("failed")])
    result = runner.invoke(app, ["run", "--skill", "security-architecture-review"])
    assert result.exit_code == 1


def test_run_command_rejects_unknown_skill():
    result = runner.invoke(app, ["run", "--skill", "not-a-real-skill"])
    assert result.exit_code != 0


def test_run_command_does_not_prompt_when_not_a_terminal(monkeypatch):
    """CliRunner's stdin isn't a real terminal -- the same as CI/scripted
    use -- so the project-name/application-id prompts must stay silent and
    just pass None through, exactly like before this feature existed.
    """
    captured: dict = {}

    def fake_execute_runs(**kwargs):
        captured.update(kwargs)
        return [_outcome("success")]

    monkeypatch.setattr("secfoo.cli.execute_runs", fake_execute_runs)
    result = runner.invoke(app, ["run", "--skill", "security-architecture-review", "--agent", "claude"])

    assert result.exit_code == 0
    assert captured["project_display_name"] is None
    assert captured["assessment_application_id"] is None


def test_run_command_prompts_for_project_name_and_app_id_on_a_terminal(monkeypatch):
    captured: dict = {}

    def fake_execute_runs(**kwargs):
        captured.update(kwargs)
        return [_outcome("success")]

    monkeypatch.setattr("secfoo.cli.execute_runs", fake_execute_runs)
    monkeypatch.setattr("secfoo.cli._is_interactive", lambda: True)
    prompts = iter(["Checkout Service", "APP-42"])
    monkeypatch.setattr("secfoo.cli.Prompt.ask", lambda *a, **k: next(prompts))

    result = runner.invoke(app, ["run", "--skill", "security-architecture-review", "--agent", "claude"])

    assert result.exit_code == 0
    assert captured["project_display_name"] == "Checkout Service"
    assert captured["assessment_application_id"] == "APP-42"


def test_run_command_skips_prompt_when_flags_already_given(monkeypatch):
    captured: dict = {}

    def fake_execute_runs(**kwargs):
        captured.update(kwargs)
        return [_outcome("success")]

    monkeypatch.setattr("secfoo.cli.execute_runs", fake_execute_runs)
    monkeypatch.setattr("secfoo.cli._is_interactive", lambda: True)

    def fail_prompt(*a, **k):
        raise AssertionError("should not prompt when --project-name/--app-id are already given")

    monkeypatch.setattr("secfoo.cli.Prompt.ask", fail_prompt)

    result = runner.invoke(
        app,
        [
            "run",
            "--skill",
            "security-architecture-review",
            "--agent",
            "claude",
            "--project-name",
            "Checkout Service",
            "--app-id",
            "APP-42",
        ],
    )

    assert result.exit_code == 0
    assert captured["project_display_name"] == "Checkout Service"
    assert captured["assessment_application_id"] == "APP-42"


def test_run_command_does_not_prompt_when_assessment_given(monkeypatch):
    captured: dict = {}

    def fake_execute_runs(**kwargs):
        captured.update(kwargs)
        return [_outcome("success")]

    monkeypatch.setattr("secfoo.cli.execute_runs", fake_execute_runs)
    monkeypatch.setattr("secfoo.cli._is_interactive", lambda: True)

    def fail_prompt(*a, **k):
        raise AssertionError("should not prompt when attaching to an existing --assessment")

    monkeypatch.setattr("secfoo.cli.Prompt.ask", fail_prompt)

    result = runner.invoke(
        app,
        ["run", "--skill", "security-architecture-review", "--agent", "claude", "--assessment", "1"],
    )

    assert result.exit_code == 0
    assert captured["project_display_name"] is None
    assert captured["assessment_application_id"] is None


def test_run_command_does_not_warn_when_responsible_ai_run_standalone(monkeypatch):
    """responsible-ai-compliance results only ever surface on the
    Responsible AI dashboard when attached to an assessment -- but
    execute_runs() now auto-creates one whenever --assessment is omitted
    (see runner.py), so a standalone run no longer needs, and must no
    longer print, the old "re-run with --assessment" warning.
    """
    monkeypatch.setattr("secfoo.cli.execute_runs", lambda **kwargs: [_outcome("success")])
    result = runner.invoke(app, ["run", "--skill", "responsible-ai-compliance", "--agent", "claude"])
    assert result.exit_code == 0
    assert "Responsible AI dashboard" not in " ".join(result.stdout.split())


def test_run_command_does_not_warn_when_responsible_ai_run_with_assessment(monkeypatch):
    monkeypatch.setattr("secfoo.cli.execute_runs", lambda **kwargs: [_outcome("success")])
    result = runner.invoke(
        app, ["run", "--skill", "responsible-ai-compliance", "--agent", "claude", "--assessment", "1"]
    )
    assert result.exit_code == 0
    assert "Responsible AI dashboard" not in " ".join(result.stdout.split())


def test_run_command_does_not_warn_for_other_skills(monkeypatch):
    monkeypatch.setattr("secfoo.cli.execute_runs", lambda **kwargs: [_outcome("success")])
    result = runner.invoke(app, ["run", "--skill", "sast", "--agent", "claude"])
    assert result.exit_code == 0
    assert "Responsible AI dashboard" not in " ".join(result.stdout.split())


def test_skill_id_enum_is_derived_from_the_skill_definition_files():
    """Guards against the CLI and the web UI offering different skill sets:
    SkillId is built from definitions/*.md rather than hand-listed, so a
    new skill file registers everywhere at once.
    """
    from secfoo.cli import SkillId
    from secfoo.skills.loader import load_all_skills

    assert {member.value for member in SkillId} == set(load_all_skills())


@pytest.mark.parametrize("skill_id", sorted(load_all_skills()))
def test_run_command_accepts_every_defined_skill(skill_id, monkeypatch):
    monkeypatch.setattr("secfoo.cli.execute_runs", lambda **kwargs: [_outcome("success")])
    result = runner.invoke(app, ["run", "--skill", skill_id, "--agent", "claude"])
    assert result.exit_code == 0, f"CLI rejected defined skill {skill_id!r}"


def test_run_command_shows_per_skill_progress(monkeypatch):
    def fake_execute_runs(**kwargs):
        kwargs["on_skill_start"]("Security Architecture Review")
        kwargs["on_skill_complete"]("Security Architecture Review", "success")
        return [_outcome("success")]

    monkeypatch.setattr("secfoo.cli.execute_runs", fake_execute_runs)
    result = runner.invoke(app, ["run", "--skill", "security-architecture-review"])
    assert result.exit_code == 0
    assert "Security Architecture Review" in result.stdout


def test_agents_command_lists_all_adapters():
    result = runner.invoke(app, ["agents"])
    assert result.exit_code == 0
    for agent_id in ["claude", "agent", "agy", "gemini", "secfoo", "codex"]:
        assert agent_id in result.stdout


class _FakeRepoEmpty:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def list_projects(self):
        return []

    def list_runs(self, **kwargs):
        return []

    def get_run(self, run_uuid):
        return None

    def total_cost_usd(self, *, project_id=None):
        return 0.0


class _FakeRepoWithCost:
    def __init__(self, *, total, projects=()):
        self._total = total
        self._projects = list(projects)
        self.requested_project_id = "not-called"

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def list_projects(self):
        return self._projects

    def total_cost_usd(self, *, project_id=None):
        self.requested_project_id = project_id
        return self._total

    def cost_summary(self, *, group_by, project_id=None, since=None):
        self.requested_project_id = project_id
        return [CostRow(label="secfoo", runs=1, input_tokens=100, output_tokens=10, cost_usd=self._total, unpriced_runs=0)]


def test_cost_command_prints_total_spend(monkeypatch):
    fake = _FakeRepoWithCost(total=1.2345)
    monkeypatch.setattr("secfoo.cli.RunRepository", lambda *a, **kw: fake)
    result = runner.invoke(app, ["cost"])
    assert result.exit_code == 0
    assert "$1.23" in result.stdout
    assert fake.requested_project_id is None


def test_cost_command_filters_by_matching_project(monkeypatch):
    project = ProjectRecord(
        id=7, identifier="https://github.com/acme/app", display_name="Acme App",
        kind="github", first_seen_at="t1", last_run_at="t2",
    )
    fake = _FakeRepoWithCost(total=0.5, projects=[project])
    monkeypatch.setattr("secfoo.cli.RunRepository", lambda *a, **kw: fake)
    result = runner.invoke(app, ["cost", "--project", "acme"])
    assert result.exit_code == 0
    assert "$0.50" in result.stdout
    assert fake.requested_project_id == 7


def test_cost_command_warns_when_project_has_no_match(monkeypatch):
    fake = _FakeRepoWithCost(total=0.0, projects=[])
    monkeypatch.setattr("secfoo.cli.RunRepository", lambda *a, **kw: fake)
    result = runner.invoke(app, ["cost", "--project", "nonexistent"])
    assert result.exit_code == 0
    assert "No project matches" in result.stdout
    assert fake.requested_project_id == "not-called"


def test_list_command_no_runs(monkeypatch):
    monkeypatch.setattr("secfoo.cli.RunRepository", lambda *a, **kw: _FakeRepoEmpty())
    result = runner.invoke(app, ["list"])
    assert result.exit_code == 0
    assert "No runs found" in result.stdout


def test_show_command_unknown_run_exits_nonzero(monkeypatch):
    monkeypatch.setattr("secfoo.cli.RunRepository", lambda *a, **kw: _FakeRepoEmpty())
    result = runner.invoke(app, ["show", "does-not-exist"])
    assert result.exit_code == 1


def test_run_command_uses_config_toml_default_agent_when_not_specified(monkeypatch):
    monkeypatch.setattr(
        "secfoo.cli.load_config", lambda: SecfooConfig(defaults=Defaults(agent="gemini"), mcp_servers=[])
    )
    captured = {}

    def fake_execute_runs(**kwargs):
        captured["agent_id"] = kwargs["agent_id"]
        return [_outcome("success")]

    monkeypatch.setattr("secfoo.cli.execute_runs", fake_execute_runs)
    result = runner.invoke(app, ["run", "--skill", "security-architecture-review"])
    assert result.exit_code == 0
    assert captured["agent_id"] == "gemini"


def test_run_command_explicit_flag_overrides_config_toml_default(monkeypatch):
    monkeypatch.setattr(
        "secfoo.cli.load_config", lambda: SecfooConfig(defaults=Defaults(agent="gemini"), mcp_servers=[])
    )
    captured = {}

    def fake_execute_runs(**kwargs):
        captured["agent_id"] = kwargs["agent_id"]
        return [_outcome("success")]

    monkeypatch.setattr("secfoo.cli.execute_runs", fake_execute_runs)
    result = runner.invoke(app, ["run", "--skill", "security-architecture-review", "--agent", "claude"])
    assert result.exit_code == 0
    assert captured["agent_id"] == "claude"


def test_mcp_list_no_servers(monkeypatch):
    monkeypatch.setattr(
        "secfoo.cli.load_config", lambda: SecfooConfig(defaults=Defaults(), mcp_servers=[])
    )
    result = runner.invoke(app, ["mcp", "list"])
    assert result.exit_code == 0
    assert "No MCP servers configured" in result.stdout


def test_mcp_list_with_servers(monkeypatch):
    servers = [MCPServerConfig(name="Atlassian-Rovo-MCP", command="npx", args=["-y", "mcp-remote@latest"])]
    monkeypatch.setattr(
        "secfoo.cli.load_config", lambda: SecfooConfig(defaults=Defaults(), mcp_servers=servers)
    )
    result = runner.invoke(app, ["mcp", "list"])
    assert result.exit_code == 0
    assert "Atlassian-Rovo-MCP" in result.stdout


def test_mcp_sync_claude_shortcuts_without_calling_sync(monkeypatch):
    servers = [MCPServerConfig(name="s", command="npx")]
    monkeypatch.setattr(
        "secfoo.cli.load_config", lambda: SecfooConfig(defaults=Defaults(), mcp_servers=servers)
    )

    def fail_if_called(agent_id, servers):
        raise AssertionError("mcp.sync should not be called for claude")

    monkeypatch.setattr(mcp_module, "sync", fail_if_called)
    result = runner.invoke(app, ["mcp", "sync", "--agent", "claude"])
    assert result.exit_code == 0
    assert "doesn't need syncing" in result.stdout


def test_mcp_sync_dispatches_to_mcp_module(monkeypatch):
    servers = [MCPServerConfig(name="s", command="npx")]
    monkeypatch.setattr(
        "secfoo.cli.load_config", lambda: SecfooConfig(defaults=Defaults(), mcp_servers=servers)
    )
    monkeypatch.setattr(
        mcp_module, "sync", lambda agent_id, servers: [mcp_module.SyncResult("s", True, "added")]
    )
    result = runner.invoke(app, ["mcp", "sync", "--agent", "gemini"])
    assert result.exit_code == 0
    assert "s: added" in result.stdout


def test_mcp_sync_reports_failure_as_nonzero_exit(monkeypatch):
    servers = [MCPServerConfig(name="s", command="npx")]
    monkeypatch.setattr(
        "secfoo.cli.load_config", lambda: SecfooConfig(defaults=Defaults(), mcp_servers=servers)
    )
    monkeypatch.setattr(
        mcp_module, "sync", lambda agent_id, servers: [mcp_module.SyncResult("s", False, "boom")]
    )
    result = runner.invoke(app, ["mcp", "sync", "--agent", "gemini"])
    assert result.exit_code == 1


def test_config_init_writes_file(tmp_path, monkeypatch):
    config_path = tmp_path / "config.toml"
    monkeypatch.setattr("secfoo.cli.CONFIG_PATH", config_path)
    result = runner.invoke(app, ["config", "init"])
    assert result.exit_code == 0
    assert config_path.exists()
    assert "mcp_servers" in config_path.read_text()


def test_config_init_refuses_to_overwrite_without_force(tmp_path, monkeypatch):
    config_path = tmp_path / "config.toml"
    config_path.write_text("# existing\n")
    monkeypatch.setattr("secfoo.cli.CONFIG_PATH", config_path)
    result = runner.invoke(app, ["config", "init"])
    assert result.exit_code == 1
    assert config_path.read_text() == "# existing\n"


def test_config_init_force_overwrites(tmp_path, monkeypatch):
    config_path = tmp_path / "config.toml"
    config_path.write_text("# existing\n")
    monkeypatch.setattr("secfoo.cli.CONFIG_PATH", config_path)
    result = runner.invoke(app, ["config", "init", "--force"])
    assert result.exit_code == 0
    assert "mcp_servers" in config_path.read_text()


def test_mcp_sync_unsupported_agent_exits_nonzero(monkeypatch):
    servers = [MCPServerConfig(name="s", command="npx")]
    monkeypatch.setattr(
        "secfoo.cli.load_config", lambda: SecfooConfig(defaults=Defaults(), mcp_servers=servers)
    )
    result = runner.invoke(app, ["mcp", "sync", "--agent", "agy"])
    assert result.exit_code == 1


def test_mcp_sync_codex_is_reported_unsupported(monkeypatch):
    servers = [MCPServerConfig(name="s", command="npx")]
    monkeypatch.setattr(
        "secfoo.cli.load_config", lambda: SecfooConfig(defaults=Defaults(), mcp_servers=servers)
    )
    result = runner.invoke(app, ["mcp", "sync", "--agent", "codex"])
    assert result.exit_code == 1
    assert "codex" in result.output
