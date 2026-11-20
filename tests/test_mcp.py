from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from secfoo import mcp
from secfoo.agents import ADAPTERS
from secfoo.agents.claude import ClaudeAdapter
from secfoo.settings import MCPServerConfig

STDIO_SERVER = MCPServerConfig(
    name="Atlassian-Rovo-MCP",
    command="npx",
    args=["-y", "mcp-remote@latest", "https://mcp.atlassian.com/v1/mcp/authv2"],
    env={"ATLASSIAN_API_KEY": "secret-123"},
)
REMOTE_SERVER = MCPServerConfig(
    name="example",
    url="https://example.com/mcp",
    transport="http",
    headers={"Authorization": "Bearer abc"},
)


# ---------- claude: ephemeral config ----------


def test_write_claude_mcp_config_returns_none_when_no_servers(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp, "STORE_DIR", tmp_path)
    monkeypatch.setattr(mcp, "CLAUDE_MCP_CONFIG_PATH", tmp_path / "claude-mcp-config.json")
    assert mcp.write_claude_mcp_config([]) is None


def test_write_claude_mcp_config_stdio_shape(tmp_path, monkeypatch):
    config_path = tmp_path / "claude-mcp-config.json"
    monkeypatch.setattr(mcp, "STORE_DIR", tmp_path)
    monkeypatch.setattr(mcp, "CLAUDE_MCP_CONFIG_PATH", config_path)

    result_path = mcp.write_claude_mcp_config([STDIO_SERVER])
    assert result_path == config_path
    payload = json.loads(config_path.read_text())
    assert payload == {
        "mcpServers": {
            "Atlassian-Rovo-MCP": {
                "command": "npx",
                "args": ["-y", "mcp-remote@latest", "https://mcp.atlassian.com/v1/mcp/authv2"],
                "env": {"ATLASSIAN_API_KEY": "secret-123"},
            }
        }
    }


def test_write_claude_mcp_config_remote_shape(tmp_path, monkeypatch):
    config_path = tmp_path / "claude-mcp-config.json"
    monkeypatch.setattr(mcp, "STORE_DIR", tmp_path)
    monkeypatch.setattr(mcp, "CLAUDE_MCP_CONFIG_PATH", config_path)

    mcp.write_claude_mcp_config([REMOTE_SERVER])
    payload = json.loads(config_path.read_text())
    assert payload["mcpServers"]["example"] == {
        "type": "http",
        "url": "https://example.com/mcp",
        "headers": {"Authorization": "Bearer abc"},
    }


def test_claude_build_command_per_run_mcp_scoping(tmp_path, monkeypatch):
    config_path = tmp_path / "claude-mcp-config.json"
    monkeypatch.setattr(mcp, "STORE_DIR", tmp_path)
    monkeypatch.setattr(mcp, "CLAUDE_MCP_CONFIG_PATH", config_path)
    monkeypatch.setattr(
        "secfoo.agents.claude.load_config",
        lambda: type("Cfg", (), {"mcp_servers": [STDIO_SERVER]})(),
    )
    monkeypatch.setattr("secfoo.memory.memory_server", lambda: None)

    cmd = ClaudeAdapter().build_command("run review", workdir=tmp_path)
    assert "--mcp-config" in cmd
    idx = cmd.index("--mcp-config")
    assert cmd[idx + 1] == str(config_path)
    assert "--strict-mcp-config" in cmd
    assert any("mcp__Atlassian-Rovo-MCP" in arg for arg in cmd)


# ---------- gemini: persistent via `gemini mcp add` ----------


def test_gemini_existing_names_parses_real_output_format(monkeypatch):
    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(
            cmd, 0, stdout="Configured MCP servers:\n\n✗ my-server: echo  (stdio) - Disconnected\n", stderr=""
        )

    monkeypatch.setattr(mcp.subprocess, "run", fake_run)
    assert mcp._gemini_existing_names() == {"my-server"}


def test_sync_gemini_skips_already_configured(monkeypatch):
    monkeypatch.setattr(mcp, "_gemini_existing_names", lambda: {"Atlassian-Rovo-MCP"})

    def fail_if_called(cmd, **kwargs):
        raise AssertionError("should not attempt to add an already-configured server")

    monkeypatch.setattr(mcp.subprocess, "run", fail_if_called)
    results = mcp.sync_gemini([STDIO_SERVER])
    assert results == [mcp.SyncResult("Atlassian-Rovo-MCP", True, "already configured, skipped")]


def test_sync_gemini_adds_new_server(monkeypatch):
    monkeypatch.setattr(mcp, "_gemini_existing_names", lambda: set())
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(mcp.subprocess, "run", fake_run)
    results = mcp.sync_gemini([STDIO_SERVER])
    assert results[0].ok is True
    assert results[0].message == "added"
    assert captured["cmd"][:4] == ["gemini", "mcp", "add", "--scope"]
    assert "Atlassian-Rovo-MCP" in captured["cmd"]


def test_sync_gemini_reports_failure(monkeypatch):
    monkeypatch.setattr(mcp, "_gemini_existing_names", lambda: set())

    def fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="boom")

    monkeypatch.setattr(mcp.subprocess, "run", fake_run)
    results = mcp.sync_gemini([STDIO_SERVER])
    assert results[0].ok is False
    assert "boom" in results[0].message


# ---------- agent (Cursor): persistent via ~/.cursor/mcp.json ----------


def test_sync_cursor_creates_new_config_file(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)
    monkeypatch.setattr(mcp.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", ""))

    results = mcp.sync_cursor([STDIO_SERVER])
    assert results[0].ok is True
    payload = json.loads(cursor_path.read_text())
    assert payload["mcpServers"]["Atlassian-Rovo-MCP"]["command"] == "npx"
    assert payload["mcpServers"]["Atlassian-Rovo-MCP"]["env"] == {"ATLASSIAN_API_KEY": "secret-123"}


def test_sync_cursor_preserves_existing_unrelated_entries(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    cursor_path.write_text(json.dumps({"unrelated": "setting", "mcpServers": {"other-server": {"command": "foo"}}}))
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)
    monkeypatch.setattr(mcp.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", ""))

    mcp.sync_cursor([STDIO_SERVER])
    payload = json.loads(cursor_path.read_text())
    assert payload.get("unrelated") == "setting"
    assert "other-server" in payload["mcpServers"]
    assert "Atlassian-Rovo-MCP" in payload["mcpServers"]


def test_sync_cursor_skips_already_configured(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    cursor_path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "Atlassian-Rovo-MCP": {
                        "command": "npx",
                        "args": ["-y", "mcp-remote@latest", "https://mcp.atlassian.com/v1/mcp/authv2"],
                        "env": {"ATLASSIAN_API_KEY": "secret-123"},
                    }
                }
            }
        )
    )
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)

    def fail_if_called(cmd, **kwargs):
        raise AssertionError("should not call `agent mcp enable` for an already-configured server")

    monkeypatch.setattr(mcp.subprocess, "run", fail_if_called)
    results = mcp.sync_cursor([STDIO_SERVER])
    assert results == [mcp.SyncResult("Atlassian-Rovo-MCP", True, "already configured, skipped")]


def test_sync_cursor_reports_enable_failure(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)
    monkeypatch.setattr(mcp.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "denied"))

    results = mcp.sync_cursor([STDIO_SERVER])
    assert results[0].ok is False
    assert "denied" in results[0].message


# ---------- codex: persistent via ~/.codex/config.toml ----------


def test_sync_codex_creates_new_config_file(tmp_path, monkeypatch):
    codex_path = tmp_path / "config.toml"
    monkeypatch.setattr(mcp, "CODEX_MCP_CONFIG_PATH", codex_path)

    results = mcp.sync_codex([STDIO_SERVER])
    assert results[0].ok is True
    assert "added to" in results[0].message
    data = tomllib.loads(codex_path.read_text(encoding="utf-8"))
    server = data["mcp_servers"]["Atlassian-Rovo-MCP"]
    assert server["command"] == "npx"
    assert server["args"] == ["-y", "mcp-remote@latest", "https://mcp.atlassian.com/v1/mcp/authv2"]
    assert server["env"] == {"ATLASSIAN_API_KEY": "secret-123"}


def test_sync_codex_preserves_existing_unrelated_entries_and_servers(tmp_path, monkeypatch):
    codex_path = tmp_path / "config.toml"
    initial_toml = (
        'model = "gpt-4o"\n\n'
        '[sandbox]\n'
        'mode = "read-only"\n\n'
        '[mcp_servers.preexisting]\n'
        'command = "node"\n'
        'args = ["index.js"]\n'
    )
    codex_path.write_text(initial_toml, encoding="utf-8")
    monkeypatch.setattr(mcp, "CODEX_MCP_CONFIG_PATH", codex_path)

    mcp.sync_codex([STDIO_SERVER])
    data = tomllib.loads(codex_path.read_text(encoding="utf-8"))
    assert data["model"] == "gpt-4o"
    assert data["sandbox"]["mode"] == "read-only"
    assert "preexisting" in data["mcp_servers"]
    assert "Atlassian-Rovo-MCP" in data["mcp_servers"]


def test_sync_codex_is_idempotent(tmp_path, monkeypatch):
    codex_path = tmp_path / "config.toml"
    monkeypatch.setattr(mcp, "CODEX_MCP_CONFIG_PATH", codex_path)

    res1 = mcp.sync_codex([STDIO_SERVER])
    assert res1[0].ok is True
    assert "added to" in res1[0].message

    res2 = mcp.sync_codex([STDIO_SERVER])
    assert res2[0].ok is True
    assert res2[0].message == "already configured, skipped"


def test_sync_codex_serializes_url_transport_headers_and_env(tmp_path, monkeypatch):
    codex_path = tmp_path / "config.toml"
    monkeypatch.setattr(mcp, "CODEX_MCP_CONFIG_PATH", codex_path)

    mcp.sync_codex([REMOTE_SERVER])
    data = tomllib.loads(codex_path.read_text(encoding="utf-8"))
    server = data["mcp_servers"]["example"]
    assert server["url"] == "https://example.com/mcp"
    assert server["transport"] == "http"
    assert server["headers"] == {"Authorization": "Bearer abc"}


def test_sync_codex_reports_invalid_toml(tmp_path, monkeypatch):
    codex_path = tmp_path / "config.toml"
    codex_path.write_text("invalid = [toml", encoding="utf-8")
    monkeypatch.setattr(mcp, "CODEX_MCP_CONFIG_PATH", codex_path)

    results = mcp.sync_codex([STDIO_SERVER])
    assert results[0].ok is False
    assert "not valid TOML" in results[0].message


# ---------- copilot: persistent via ~/.copilot/mcp-config.json ----------


def test_sync_copilot_creates_new_config_file(tmp_path, monkeypatch):
    copilot_path = tmp_path / "mcp-config.json"
    monkeypatch.setattr(mcp, "COPILOT_MCP_CONFIG_PATH", copilot_path)

    results = mcp.sync_copilot([STDIO_SERVER])
    assert results[0].ok is True
    data = json.loads(copilot_path.read_text(encoding="utf-8"))
    server = data["mcpServers"]["Atlassian-Rovo-MCP"]
    assert server["type"] == "local"
    assert server["command"] == "npx"
    assert server["tools"] == ["*"]
    assert server["env"] == {"ATLASSIAN_API_KEY": "secret-123"}


def test_sync_copilot_preserves_existing_unrelated_entries(tmp_path, monkeypatch):
    copilot_path = tmp_path / "mcp-config.json"
    copilot_path.write_text(
        json.dumps({"unrelated": "val", "mcpServers": {"other": {"command": "tool"}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(mcp, "COPILOT_MCP_CONFIG_PATH", copilot_path)

    mcp.sync_copilot([STDIO_SERVER])
    data = json.loads(copilot_path.read_text(encoding="utf-8"))
    assert data["unrelated"] == "val"
    assert "other" in data["mcpServers"]
    assert "Atlassian-Rovo-MCP" in data["mcpServers"]


def test_sync_copilot_is_idempotent(tmp_path, monkeypatch):
    copilot_path = tmp_path / "mcp-config.json"
    monkeypatch.setattr(mcp, "COPILOT_MCP_CONFIG_PATH", copilot_path)

    res1 = mcp.sync_copilot([STDIO_SERVER])
    assert res1[0].ok is True
    assert "added to" in res1[0].message

    res2 = mcp.sync_copilot([STDIO_SERVER])
    assert res2[0].ok is True
    assert res2[0].message == "already configured, skipped"


def test_sync_copilot_serializes_url_headers_and_env(tmp_path, monkeypatch):
    copilot_path = tmp_path / "mcp-config.json"
    monkeypatch.setattr(mcp, "COPILOT_MCP_CONFIG_PATH", copilot_path)

    mcp.sync_copilot([REMOTE_SERVER])
    data = json.loads(copilot_path.read_text(encoding="utf-8"))
    server = data["mcpServers"]["example"]
    assert server["type"] == "http"
    assert server["url"] == "https://example.com/mcp"
    assert server["headers"] == {"Authorization": "Bearer abc"}
    assert server["tools"] == ["*"]


# ---------- opencode: persistent via ~/.config/opencode/opencode.json ----------


def test_sync_opencode_creates_new_config_file(tmp_path, monkeypatch):
    opencode_path = tmp_path / "opencode.json"
    monkeypatch.setattr(mcp, "OPENCODE_MCP_CONFIG_PATH", opencode_path)

    results = mcp.sync_opencode([STDIO_SERVER])
    assert results[0].ok is True
    data = json.loads(opencode_path.read_text(encoding="utf-8"))
    server = data["mcp"]["Atlassian-Rovo-MCP"]
    assert server["type"] == "local"
    assert server["command"] == ["npx", "-y", "mcp-remote@latest", "https://mcp.atlassian.com/v1/mcp/authv2"]
    assert server["environment"] == {"ATLASSIAN_API_KEY": "secret-123"}
    assert server["enabled"] is True


def test_sync_opencode_preserves_existing_unrelated_entries(tmp_path, monkeypatch):
    opencode_path = tmp_path / "opencode.json"
    opencode_path.write_text(
        json.dumps({"$schema": "https://opencode.ai/config.json", "mcp": {"other": {"enabled": True}}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(mcp, "OPENCODE_MCP_CONFIG_PATH", opencode_path)

    mcp.sync_opencode([STDIO_SERVER])
    data = json.loads(opencode_path.read_text(encoding="utf-8"))
    assert "$schema" in data
    assert "other" in data["mcp"]
    assert "Atlassian-Rovo-MCP" in data["mcp"]


def test_sync_opencode_is_idempotent(tmp_path, monkeypatch):
    opencode_path = tmp_path / "opencode.json"
    monkeypatch.setattr(mcp, "OPENCODE_MCP_CONFIG_PATH", opencode_path)

    res1 = mcp.sync_opencode([STDIO_SERVER])
    assert res1[0].ok is True
    res2 = mcp.sync_opencode([STDIO_SERVER])
    assert res2[0].ok is True
    assert res2[0].message == "already configured, skipped"


def test_sync_opencode_serializes_url_headers_and_env(tmp_path, monkeypatch):
    opencode_path = tmp_path / "opencode.json"
    monkeypatch.setattr(mcp, "OPENCODE_MCP_CONFIG_PATH", opencode_path)

    mcp.sync_opencode([REMOTE_SERVER])
    data = json.loads(opencode_path.read_text(encoding="utf-8"))
    server = data["mcp"]["example"]
    assert server["type"] == "remote"
    assert server["url"] == "https://example.com/mcp"
    assert server["enabled"] is True
    assert server["headers"] == {"Authorization": "Bearer abc"}


# ---------- droid: persistent via ~/.factory/mcp.json ----------


def test_sync_droid_creates_new_config_file(tmp_path, monkeypatch):
    droid_path = tmp_path / "mcp.json"
    monkeypatch.setattr(mcp, "DROID_MCP_CONFIG_PATH", droid_path)

    results = mcp.sync_droid([STDIO_SERVER])
    assert results[0].ok is True
    data = json.loads(droid_path.read_text(encoding="utf-8"))
    server = data["mcpServers"]["Atlassian-Rovo-MCP"]
    assert server["command"] == "npx"
    assert server["env"] == {"ATLASSIAN_API_KEY": "secret-123"}


def test_sync_droid_preserves_existing_unrelated_entries(tmp_path, monkeypatch):
    droid_path = tmp_path / "mcp.json"
    droid_path.write_text(json.dumps({"version": 1, "mcpServers": {"other": {"command": "tool"}}}), encoding="utf-8")
    monkeypatch.setattr(mcp, "DROID_MCP_CONFIG_PATH", droid_path)

    mcp.sync_droid([STDIO_SERVER])
    data = json.loads(droid_path.read_text(encoding="utf-8"))
    assert data["version"] == 1
    assert "other" in data["mcpServers"]
    assert "Atlassian-Rovo-MCP" in data["mcpServers"]


def test_sync_droid_is_idempotent(tmp_path, monkeypatch):
    droid_path = tmp_path / "mcp.json"
    monkeypatch.setattr(mcp, "DROID_MCP_CONFIG_PATH", droid_path)

    res1 = mcp.sync_droid([STDIO_SERVER])
    assert res1[0].ok is True
    res2 = mcp.sync_droid([STDIO_SERVER])
    assert res2[0].ok is True
    assert res2[0].message == "already configured, skipped"


def test_sync_droid_serializes_url_headers_and_env(tmp_path, monkeypatch):
    droid_path = tmp_path / "mcp.json"
    monkeypatch.setattr(mcp, "DROID_MCP_CONFIG_PATH", droid_path)

    mcp.sync_droid([REMOTE_SERVER])
    data = json.loads(droid_path.read_text(encoding="utf-8"))
    server = data["mcpServers"]["example"]
    assert server["type"] == "http"
    assert server["url"] == "https://example.com/mcp"
    assert server["headers"] == {"Authorization": "Bearer abc"}


# ---------- devin: persistent via mcp_config.json ----------


def test_sync_devin_creates_new_config_file(tmp_path, monkeypatch):
    devin_path = tmp_path / "mcp_config.json"
    monkeypatch.setattr(mcp, "DEVIN_MCP_CONFIG_PATH", devin_path)

    results = mcp.sync_devin([STDIO_SERVER])
    assert results[0].ok is True
    data = json.loads(devin_path.read_text(encoding="utf-8"))
    server = data["mcpServers"]["Atlassian-Rovo-MCP"]
    assert server["command"] == "npx"
    assert server["env"] == {"ATLASSIAN_API_KEY": "secret-123"}


def test_sync_devin_preserves_existing_unrelated_entries(tmp_path, monkeypatch):
    devin_path = tmp_path / "mcp_config.json"
    devin_path.write_text(json.dumps({"global_key": "val", "mcpServers": {"other": {"command": "tool"}}}), encoding="utf-8")
    monkeypatch.setattr(mcp, "DEVIN_MCP_CONFIG_PATH", devin_path)

    mcp.sync_devin([STDIO_SERVER])
    data = json.loads(devin_path.read_text(encoding="utf-8"))
    assert data["global_key"] == "val"
    assert "other" in data["mcpServers"]
    assert "Atlassian-Rovo-MCP" in data["mcpServers"]


def test_sync_devin_is_idempotent(tmp_path, monkeypatch):
    devin_path = tmp_path / "mcp_config.json"
    monkeypatch.setattr(mcp, "DEVIN_MCP_CONFIG_PATH", devin_path)

    res1 = mcp.sync_devin([STDIO_SERVER])
    assert res1[0].ok is True
    res2 = mcp.sync_devin([STDIO_SERVER])
    assert res2[0].ok is True
    assert res2[0].message == "already configured, skipped"


def test_sync_devin_serializes_url_headers_and_env(tmp_path, monkeypatch):
    devin_path = tmp_path / "mcp_config.json"
    monkeypatch.setattr(mcp, "DEVIN_MCP_CONFIG_PATH", devin_path)

    mcp.sync_devin([REMOTE_SERVER])
    data = json.loads(devin_path.read_text(encoding="utf-8"))
    server = data["mcpServers"]["example"]
    assert server["type"] == "http"
    assert server["url"] == "https://example.com/mcp"
    assert server["headers"] == {"Authorization": "Bearer abc"}


# ---------- dispatch & error reporting ----------


def test_sync_dispatches_all_supported_agents(monkeypatch):
    called = []
    for agent_id in mcp.SYNC_SUPPORTED_AGENTS:
        monkeypatch.setattr(mcp, f"sync_{'cursor' if agent_id == 'agent' else agent_id}", lambda servers, aid=agent_id: called.append(aid))
    for agent_id in mcp.SYNC_SUPPORTED_AGENTS:
        mcp.sync(agent_id, [STDIO_SERVER])
    assert set(called) == mcp.SYNC_SUPPORTED_AGENTS


def test_sync_unsupported_agent_message_includes_matrix():
    with pytest.raises(ValueError) as excinfo:
        mcp.sync("agy", [])
    msg = str(excinfo.value)
    assert "isn't supported for 'agy'" in msg
    assert "docs/REFERENCE.md" in msg
    assert "claude" in msg
    assert "per-run" in msg
    assert "sync" in msg
    assert "none" in msg

    with pytest.raises(ValueError) as excinfo:
        mcp.sync("api", [])
    assert "isn't supported for 'api'" in str(excinfo.value)


# ---------- consistency: docs/REFERENCE.md vs canonical matrix ----------


def test_reference_md_mcp_matrix_consistency():
    ref_path = Path(__file__).resolve().parents[1] / "docs" / "REFERENCE.md"
    assert ref_path.exists(), "docs/REFERENCE.md must exist in repository root"
    content = ref_path.read_text(encoding="utf-8")
    parsed = mcp.parse_mcp_support_from_reference_md(content)

    # Must cover all 10 adapters defined in ADAPTERS
    assert set(parsed.keys()) == set(ADAPTERS.keys()), f"Missing adapters in docs/REFERENCE.md table: {set(ADAPTERS.keys()) - set(parsed.keys())}"

    # Must match canonical matrix
    for agent_id, support in mcp.CANONICAL_MCP_SUPPORT.items():
        assert agent_id in parsed
        assert parsed[agent_id].mechanism == support.mechanism
