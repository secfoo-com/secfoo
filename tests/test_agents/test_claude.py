from __future__ import annotations

import json

from secfoo.agents.claude import ClaudeAdapter
from secfoo.settings import MCPServerConfig


def test_build_command_argv(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.agents.claude.load_config", lambda: _empty_config())
    adapter = ClaudeAdapter()
    cmd = adapter.build_command("hello", workdir=tmp_path)
    assert cmd[0] == "claude"
    assert "-p" in cmd
    assert "hello" in cmd
    assert "--allowedTools" in cmd
    assert "--permission-mode" in cmd
    assert "default" in cmd


def test_build_command_no_mcp_config_flag_when_no_servers_configured(tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.agents.claude.load_config", lambda: _empty_config())
    adapter = ClaudeAdapter()
    cmd = adapter.build_command("hello", workdir=tmp_path)
    assert "--mcp-config" not in cmd


def test_build_command_adds_mcp_config_and_server_level_tool_grant(tmp_path, monkeypatch):
    server = MCPServerConfig(name="Atlassian-Rovo-MCP", command="npx", args=["-y", "mcp-remote@latest"])
    monkeypatch.setattr("secfoo.agents.claude.load_config", lambda: _config_with([server]))
    generated_path = tmp_path / "claude-mcp-config.json"
    monkeypatch.setattr("secfoo.agents.claude.write_claude_mcp_config", lambda servers: generated_path)

    adapter = ClaudeAdapter()
    cmd = adapter.build_command("hello", workdir=tmp_path)

    assert "--mcp-config" in cmd
    assert str(generated_path) in cmd
    allowed_tools_idx = cmd.index("--allowedTools") + 1
    assert "mcp__Atlassian-Rovo-MCP" in cmd[allowed_tools_idx]


def _empty_config():
    from secfoo.settings import Defaults, SecfooConfig

    return SecfooConfig(defaults=Defaults(), mcp_servers=[])


def _config_with(servers):
    from secfoo.settings import Defaults, SecfooConfig

    return SecfooConfig(defaults=Defaults(), mcp_servers=servers)


def test_extract_report_parses_json_result_field():
    adapter = ClaudeAdapter()
    stdout = json.dumps({"result": "# Report\ncontent"})
    assert adapter.extract_report(stdout) == "# Report\ncontent"


def test_extract_report_falls_back_to_raw_stdout_on_non_json():
    adapter = ClaudeAdapter()
    assert adapter.extract_report("not json") == "not json"


def test_run_success_extracts_report_from_json(fake_popen, tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.agents.claude.load_config", lambda: _empty_config())
    fake_popen(returncode=0, stdout=json.dumps({"result": "# Threat Report"}), stderr="")
    adapter = ClaudeAdapter()
    result = adapter.run("review this", workdir=tmp_path)
    assert result.status == "success"
    assert result.raw_report == "# Threat Report"
