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


def test_extract_cost_parses_total_cost_usd():
    adapter = ClaudeAdapter()
    stdout = json.dumps({"result": "ok", "total_cost_usd": 0.0412})
    assert adapter.extract_cost(stdout) == 0.0412


def test_extract_cost_returns_none_when_field_missing():
    adapter = ClaudeAdapter()
    assert adapter.extract_cost(json.dumps({"result": "ok"})) is None


def test_extract_cost_returns_none_on_non_json():
    adapter = ClaudeAdapter()
    assert adapter.extract_cost("not json") is None


def test_run_success_sets_cost_usd_from_json(fake_popen, tmp_path, monkeypatch):
    monkeypatch.setattr("secfoo.agents.claude.load_config", lambda: _empty_config())
    fake_popen(
        returncode=0,
        stdout=json.dumps({"result": "# Threat Report", "total_cost_usd": 0.0412}),
        stderr="",
    )
    adapter = ClaudeAdapter()
    result = adapter.run("review this", workdir=tmp_path)
    assert result.cost_usd == 0.0412
def test_extract_usage_reads_cost_and_sums_cached_input_tokens():
    stdout = json.dumps({
        "result": "report",
        "total_cost_usd": 0.4512,
        "usage": {
            "input_tokens": 100,
            "cache_creation_input_tokens": 2000,
            "cache_read_input_tokens": 30000,
            "output_tokens": 4000,
        },
    })
    usage = ClaudeAdapter().extract_usage(stdout)
    assert usage.input_tokens == 32100
    assert usage.output_tokens == 4000
    assert usage.cost_usd == 0.4512


def test_extract_usage_unknown_when_stdout_is_not_json():
    usage = ClaudeAdapter().extract_usage("plain text")
    assert usage.cost_usd is None
    assert usage.input_tokens is None


def test_run_records_usage_from_json_output(tmp_path, monkeypatch, fake_popen):
    monkeypatch.setattr("secfoo.agents.claude.load_config", lambda: _empty_config())
    stdout = json.dumps({"result": "report", "total_cost_usd": 1.5, "usage": {"input_tokens": 10, "output_tokens": 5}})
    fake_popen(returncode=0, stdout=stdout)
    result = ClaudeAdapter().run("prompt", workdir=tmp_path)
    assert result.cost_usd == 1.5
    assert result.input_tokens == 10
    assert result.output_tokens == 5
