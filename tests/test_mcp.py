from __future__ import annotations

import json
import logging
import os
import subprocess

import pytest
import tomlkit

from secfoo import mcp
from secfoo.settings import MCPServerConfig

STDIO_SERVER = MCPServerConfig(
    name="Atlassian-Rovo-MCP",
    command="npx",
    args=["-y", "mcp-remote@latest", "https://mcp.atlassian.com/v1/mcp/authv2"],
)
REMOTE_SERVER = MCPServerConfig(
    name="example",
    url="https://example.com/mcp",
    transport="http",
    headers={"Authorization": "Bearer abc"},
)


# ---------- storage primitives ----------


def test_write_private_file_creates_file_with_0600(tmp_path):
    target = tmp_path / "private.txt"
    mcp._write_private_file(target, "secret content")
    assert target.exists()
    assert target.read_text(encoding="utf-8") == "secret content"
    if os.name != "nt":
        mode = target.stat().st_mode & 0o777
        assert mode == 0o600


def test_write_private_file_logs_warning_on_chmod_failure(
    tmp_path, monkeypatch, caplog
):
    target = tmp_path / "private_fail.txt"

    def fail_chmod(path, mode):
        raise OSError("chmod failed")

    monkeypatch.setattr(os, "chmod", fail_chmod)
    with caplog.at_level(logging.WARNING):
        mcp._write_private_file(target, "test")
    assert target.exists()
    assert any("Failed to chmod 0600" in record.message for record in caplog.records)


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
    if os.name != "nt":
        assert config_path.stat().st_mode & 0o777 == 0o600
    payload = json.loads(config_path.read_text())
    assert payload == {
        "mcpServers": {
            "Atlassian-Rovo-MCP": {
                "command": "npx",
                "args": ["-y", "mcp-remote@latest", "https://mcp.atlassian.com/v1/mcp/authv2"],
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


def test_sync_gemini_raises_clean_error_when_cli_missing(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("gemini not found")

    monkeypatch.setattr(mcp.subprocess, "run", fake_run)
    with pytest.raises(mcp.MCPSyncError, match="Gemini CLI .* is not installed"):
        mcp.sync_gemini([STDIO_SERVER])


# ---------- agent (Cursor): persistent via ~/.cursor/mcp.json ----------


def test_sync_json_mcp_config_rejects_non_dict_json(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    cursor_path.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)

    with pytest.raises(mcp.MCPSyncError, match="does not contain a JSON object"):
        mcp.sync_cursor([STDIO_SERVER])


def test_sync_json_mcp_config_rejects_null_json(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    cursor_path.write_text("null", encoding="utf-8")
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)

    with pytest.raises(mcp.MCPSyncError, match="does not contain a JSON object"):
        mcp.sync_cursor([STDIO_SERVER])


def test_sync_json_mcp_config_handles_non_utf8_file(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    cursor_path.write_bytes(b"\xff\xfe\x00\x00")
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)

    results = mcp.sync_cursor([STDIO_SERVER])
    assert results[0].ok is False
    assert "is not valid UTF-8" in results[0].message


def test_sync_cursor_creates_new_config_file(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)
    monkeypatch.setattr(
        mcp.subprocess,
        "run",
        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", ""),
    )

    results = mcp.sync_cursor([STDIO_SERVER])
    assert results[0].ok is True
    payload = json.loads(cursor_path.read_text())
    assert payload["mcpServers"]["Atlassian-Rovo-MCP"]["command"] == "npx"


def test_sync_cursor_preserves_existing_unrelated_entries(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    cursor_path.write_text(json.dumps({"mcpServers": {"other-server": {"command": "foo"}}}))
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)
    monkeypatch.setattr(mcp.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", ""))

    mcp.sync_cursor([STDIO_SERVER])
    payload = json.loads(cursor_path.read_text())
    assert "other-server" in payload["mcpServers"]
    assert "Atlassian-Rovo-MCP" in payload["mcpServers"]


def test_sync_cursor_preserves_disabled_server(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    initial_content = {
        "mcpServers": {
            "Atlassian-Rovo-MCP": {
                "command": "original-command",
                "disabled": True,
            }
        }
    }
    cursor_path.write_text(json.dumps(initial_content), encoding="utf-8")
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)

    results = mcp.sync_cursor([STDIO_SERVER])
    assert results == [
        mcp.SyncResult("Atlassian-Rovo-MCP", True, "already configured, skipped")
    ]

    saved = json.loads(cursor_path.read_text(encoding="utf-8"))
    assert saved["mcpServers"]["Atlassian-Rovo-MCP"]["disabled"] is True
    assert saved["mcpServers"]["Atlassian-Rovo-MCP"]["command"] == "original-command"


def test_sync_cursor_skips_already_configured(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    cursor_path.write_text(json.dumps({"mcpServers": {"Atlassian-Rovo-MCP": {"command": "npx"}}}))
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


def test_sync_cursor_reports_binary_missing_on_enable(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)

    def fake_run(*args, **kwargs):
        raise FileNotFoundError("agent not found")

    monkeypatch.setattr(mcp.subprocess, "run", fake_run)
    results = mcp.sync_cursor([STDIO_SERVER])
    assert results[0].ok is False
    assert cursor_path.exists()
    assert "written, but agent binary not found on PATH to enable" in results[0].message


def test_sync_cursor_reports_command_error_on_enable(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)

    def fake_run(*args, **kwargs):
        raise OSError("permission denied executing agent")

    monkeypatch.setattr(mcp.subprocess, "run", fake_run)
    results = mcp.sync_cursor([STDIO_SERVER])
    assert results[0].ok is False
    assert cursor_path.exists()
    assert (
        "written, but agent mcp enable could not run: permission denied executing agent"
        in results[0].message
    )


def test_sync_cursor_reports_timeout_on_enable(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=["agent", "mcp", "enable", "Atlassian-Rovo-MCP"], timeout=30
        )

    monkeypatch.setattr(mcp.subprocess, "run", fake_run)
    results = mcp.sync_cursor([STDIO_SERVER])
    assert results[0].ok is False
    assert cursor_path.exists()
    assert (
        "written, but agent mcp enable could not run: Command '['agent', 'mcp', 'enable', 'Atlassian-Rovo-MCP']' timed out after 30 seconds"
        in results[0].message
    )


# ---------- codex: persistent via ~/.codex/config.toml ----------


def test_sync_codex_creates_fresh_file(tmp_path, monkeypatch):
    codex_path = tmp_path / ".codex" / "config.toml"
    monkeypatch.setattr(mcp, "CODEX_CONFIG_PATH", codex_path)

    results = mcp.sync_codex([STDIO_SERVER])
    assert results[0].ok is True
    assert codex_path.exists()
    if os.name != "nt":
        assert codex_path.stat().st_mode & 0o777 == 0o600
    doc = tomlkit.parse(codex_path.read_text(encoding="utf-8"))
    assert doc["mcp_servers"]["Atlassian-Rovo-MCP"]["command"] == "npx"


def test_sync_codex_preserves_formatting_comments_and_empty_tables(
    tmp_path, monkeypatch
):
    codex_path = tmp_path / ".codex" / "config.toml"
    initial = """# Global comment
created_at = 2026-11-20T20:00:00Z

[features]

[mcp_servers.user_server]
command = "my-tool"
"""
    codex_path.parent.mkdir(parents=True, exist_ok=True)
    codex_path.write_text(initial, encoding="utf-8")
    monkeypatch.setattr(mcp, "CODEX_CONFIG_PATH", codex_path)

    results = mcp.sync_codex([STDIO_SERVER])
    assert results[0].ok is True
    text = codex_path.read_text(encoding="utf-8")
    assert "# Global comment" in text
    assert "created_at = 2026-11-20T20:00:00Z" in text
    assert "[features]" in text
    assert "user_server" in text
    assert "Atlassian-Rovo-MCP" in text


def test_sync_codex_remote_server_mapping(tmp_path, monkeypatch):
    codex_path = tmp_path / ".codex" / "config.toml"
    monkeypatch.setattr(mcp, "CODEX_CONFIG_PATH", codex_path)

    remote = MCPServerConfig(
        name="remote-http",
        url="https://api.example.com/mcp",
        transport="http",
        headers={"Authorization": "Bearer token123"},
    )
    results = mcp.sync_codex([remote])
    assert results[0].ok is True
    doc = tomlkit.parse(codex_path.read_text(encoding="utf-8"))
    server_tbl = doc["mcp_servers"]["remote-http"]
    assert server_tbl["url"] == "https://api.example.com/mcp"
    assert server_tbl["http_headers"]["Authorization"] == "Bearer token123"
    assert "transport" not in server_tbl


def test_sync_codex_skips_sse_remote_server(tmp_path, monkeypatch):
    codex_path = tmp_path / ".codex" / "config.toml"
    monkeypatch.setattr(mcp, "CODEX_CONFIG_PATH", codex_path)

    sse_server = MCPServerConfig(
        name="remote-sse",
        url="https://api.example.com/sse",
        transport="sse",
    )
    results = mcp.sync_codex([sse_server])
    assert results[0].ok is False
    assert "SSE" in results[0].message
    assert not codex_path.exists()


def test_sync_codex_idempotent(tmp_path, monkeypatch):
    codex_path = tmp_path / ".codex" / "config.toml"
    monkeypatch.setattr(mcp, "CODEX_CONFIG_PATH", codex_path)

    mcp.sync_codex([STDIO_SERVER])
    results2 = mcp.sync_codex([STDIO_SERVER])
    assert results2 == [
        mcp.SyncResult("Atlassian-Rovo-MCP", True, "already configured, skipped")
    ]


def test_sync_codex_handles_invalid_toml(tmp_path, monkeypatch):
    codex_path = tmp_path / ".codex" / "config.toml"
    codex_path.parent.mkdir(parents=True, exist_ok=True)
    codex_path.write_text("invalid = [toml", encoding="utf-8")
    monkeypatch.setattr(mcp, "CODEX_CONFIG_PATH", codex_path)

    results = mcp.sync_codex([STDIO_SERVER])
    assert results[0].ok is False
    assert "is not valid TOML" in results[0].message


def test_sync_codex_rejects_non_table_mcp_servers(tmp_path, monkeypatch):
    codex_path = tmp_path / ".codex" / "config.toml"
    codex_path.parent.mkdir(parents=True, exist_ok=True)
    codex_path.write_text("mcp_servers = 5\n", encoding="utf-8")
    monkeypatch.setattr(mcp, "CODEX_CONFIG_PATH", codex_path)

    with pytest.raises(mcp.MCPSyncError, match="'mcp_servers' .* is not a TOML table"):
        mcp.sync_codex([STDIO_SERVER])


def test_sync_codex_handles_non_utf8_file(tmp_path, monkeypatch):
    codex_path = tmp_path / ".codex" / "config.toml"
    codex_path.parent.mkdir(parents=True, exist_ok=True)
    codex_path.write_bytes(b"\xff\xfe\x00\x00")
    monkeypatch.setattr(mcp, "CODEX_CONFIG_PATH", codex_path)

    results = mcp.sync_codex([STDIO_SERVER])
    assert results[0].ok is False
    assert "is not valid UTF-8" in results[0].message


def test_sync_codex_converts_inline_mcp_servers_table(tmp_path, monkeypatch):
    codex_path = tmp_path / ".codex" / "config.toml"
    codex_path.parent.mkdir(parents=True, exist_ok=True)
    codex_path.write_text("mcp_servers = {}\n", encoding="utf-8")
    monkeypatch.setattr(mcp, "CODEX_CONFIG_PATH", codex_path)

    results = mcp.sync_codex([STDIO_SERVER])
    assert results[0].ok is True
    doc = tomlkit.parse(codex_path.read_text(encoding="utf-8"))
    assert doc["mcp_servers"]["Atlassian-Rovo-MCP"]["command"] == "npx"


def test_sync_codex_preserves_crlf_line_endings(tmp_path, monkeypatch):
    codex_path = tmp_path / ".codex" / "config.toml"
    codex_path.parent.mkdir(parents=True, exist_ok=True)
    codex_path.write_bytes(b"# c\r\n[features]\r\n\r\n")
    monkeypatch.setattr(mcp, "CODEX_CONFIG_PATH", codex_path)

    results = mcp.sync_codex([STDIO_SERVER])
    assert results[0].ok is True
    assert codex_path.read_bytes().startswith(b"# c\r\n[features]\r\n")


def test_sync_codex_converts_non_empty_inline_table(tmp_path, monkeypatch):
    codex_path = tmp_path / ".codex" / "config.toml"
    codex_path.parent.mkdir(parents=True, exist_ok=True)
    codex_path.write_text('mcp_servers = { a = { command = "x" } }\n', encoding="utf-8")
    monkeypatch.setattr(mcp, "CODEX_CONFIG_PATH", codex_path)

    server_b = MCPServerConfig(name="b", command="y")
    results = mcp.sync_codex([server_b])
    assert results[0].ok is True
    doc = tomlkit.parse(codex_path.read_text(encoding="utf-8"))
    assert doc["mcp_servers"]["a"]["command"] == "x"
    assert doc["mcp_servers"]["b"]["command"] == "y"


# ---------- dispatch ----------


def test_sync_dispatches_by_agent_id(monkeypatch):
    monkeypatch.setattr(mcp, "sync_gemini", lambda servers: "gemini-result")
    monkeypatch.setattr(mcp, "sync_cursor", lambda servers: "cursor-result")
    monkeypatch.setattr(mcp, "sync_codex", lambda servers: "codex-result")
    monkeypatch.setattr(mcp, "sync_copilot", lambda servers: "copilot-result")
    monkeypatch.setattr(mcp, "sync_opencode", lambda servers: "opencode-result")
    monkeypatch.setattr(mcp, "sync_droid", lambda servers: "droid-result")
    monkeypatch.setattr(mcp, "sync_devin", lambda servers: "devin-result")
    assert mcp.sync("gemini", []) == "gemini-result"
    assert mcp.sync("agent", []) == "cursor-result"
    assert mcp.sync("codex", []) == "codex-result"
    assert mcp.sync("copilot", []) == "copilot-result"
    assert mcp.sync("opencode", []) == "opencode-result"
    assert mcp.sync("droid", []) == "droid-result"
    assert mcp.sync("devin", []) == "devin-result"


# ---------- copilot: persistent via ~/.copilot/mcp-config.json ----------


def test_sync_copilot_stdio_and_remote(tmp_path, monkeypatch):
    copilot_path = tmp_path / "mcp-config.json"
    monkeypatch.setattr(mcp, "COPILOT_MCP_CONFIG_PATH", copilot_path)

    sse_server = MCPServerConfig(
        name="sse-server",
        url="https://api.example.com/sse",
        transport="sse",
    )
    results = mcp.sync_copilot([STDIO_SERVER, REMOTE_SERVER, sse_server])
    assert len(results) == 3
    assert all(r.ok for r in results)

    doc = json.loads(copilot_path.read_text(encoding="utf-8"))
    assert doc["mcpServers"]["Atlassian-Rovo-MCP"] == {
        "type": "local",
        "command": "npx",
        "args": ["-y", "mcp-remote@latest", "https://mcp.atlassian.com/v1/mcp/authv2"],
        "tools": ["*"],
    }
    assert doc["mcpServers"]["example"] == {
        "type": "http",
        "url": "https://example.com/mcp",
        "tools": ["*"],
        "headers": {"Authorization": "Bearer abc"},
    }
    assert doc["mcpServers"]["sse-server"] == {
        "type": "sse",
        "url": "https://api.example.com/sse",
        "tools": ["*"],
    }
    if os.name != "nt":
        assert copilot_path.stat().st_mode & 0o777 == 0o600


def test_sync_copilot_preserves_and_idempotent(tmp_path, monkeypatch):
    copilot_path = tmp_path / "mcp-config.json"
    initial = {
        "otherKey": "custom",
        "mcpServers": {
            "existing": {"type": "local", "command": "echo", "tools": ["*"]},
            "Atlassian-Rovo-MCP": {
                "type": "local",
                "command": "custom-cmd",
                "tools": ["read"],
            },
        },
    }
    copilot_path.write_text(json.dumps(initial), encoding="utf-8")
    monkeypatch.setattr(mcp, "COPILOT_MCP_CONFIG_PATH", copilot_path)

    results = mcp.sync_copilot([STDIO_SERVER])
    assert results == [
        mcp.SyncResult("Atlassian-Rovo-MCP", True, "already configured, skipped")
    ]

    doc = json.loads(copilot_path.read_text(encoding="utf-8"))
    assert doc["otherKey"] == "custom"
    assert doc["mcpServers"]["existing"]["command"] == "echo"
    assert doc["mcpServers"]["Atlassian-Rovo-MCP"]["command"] == "custom-cmd"
    assert doc["mcpServers"]["Atlassian-Rovo-MCP"]["tools"] == ["read"]


# ---------- opencode: persistent via ~/.config/opencode/opencode.json ----------


def test_sync_opencode_stdio_and_remote(tmp_path, monkeypatch):
    opencode_path = tmp_path / "opencode.json"
    monkeypatch.setattr(mcp, "OPENCODE_MCP_CONFIG_PATH", opencode_path)

    env_server = MCPServerConfig(
        name="env-server",
        command="python",
        args=["-m", "server"],
        env={"API_KEY": "123"},
    )
    results = mcp.sync_opencode([env_server, REMOTE_SERVER])
    assert len(results) == 2
    assert all(r.ok for r in results)

    doc = json.loads(opencode_path.read_text(encoding="utf-8"))
    assert doc["mcp"]["env-server"] == {
        "type": "local",
        "command": ["python", "-m", "server"],
        "enabled": True,
        "environment": {"API_KEY": "123"},
    }
    assert doc["mcp"]["example"] == {
        "type": "remote",
        "url": "https://example.com/mcp",
        "enabled": True,
        "headers": {"Authorization": "Bearer abc"},
    }
    if os.name != "nt":
        assert opencode_path.stat().st_mode & 0o777 == 0o600


def test_sync_opencode_preserves_and_idempotent(tmp_path, monkeypatch):
    opencode_path = tmp_path / "opencode.json"
    initial = {
        "permission": {"bash": "deny"},
        "mcp": {
            "existing": {"type": "local", "command": ["echo"], "enabled": False},
        },
    }
    opencode_path.write_text(json.dumps(initial), encoding="utf-8")
    monkeypatch.setattr(mcp, "OPENCODE_MCP_CONFIG_PATH", opencode_path)

    results = mcp.sync_opencode([STDIO_SERVER])
    assert results[0].ok is True

    doc = json.loads(opencode_path.read_text(encoding="utf-8"))
    assert doc["permission"] == {"bash": "deny"}
    assert doc["mcp"]["existing"]["enabled"] is False

    results2 = mcp.sync_opencode([STDIO_SERVER])
    assert results2 == [
        mcp.SyncResult("Atlassian-Rovo-MCP", True, "already configured, skipped")
    ]


# ---------- droid: persistent via ~/.factory/mcp.json ----------


def test_sync_droid_creates_config(tmp_path, monkeypatch):
    droid_path = tmp_path / "mcp.json"
    monkeypatch.setattr(mcp, "DROID_MCP_CONFIG_PATH", droid_path)

    results = mcp.sync_droid([STDIO_SERVER, REMOTE_SERVER])
    assert all(r.ok for r in results)

    doc = json.loads(droid_path.read_text(encoding="utf-8"))
    assert doc["mcpServers"]["Atlassian-Rovo-MCP"]["command"] == "npx"
    assert doc["mcpServers"]["example"]["url"] == "https://example.com/mcp"
    if os.name != "nt":
        assert droid_path.stat().st_mode & 0o777 == 0o600


def test_sync_droid_preserves_and_idempotent(tmp_path, monkeypatch):
    droid_path = tmp_path / "mcp.json"
    initial = {"mcpServers": {"existing": {"command": "tool"}}}
    droid_path.write_text(json.dumps(initial), encoding="utf-8")
    monkeypatch.setattr(mcp, "DROID_MCP_CONFIG_PATH", droid_path)

    mcp.sync_droid([STDIO_SERVER])
    results2 = mcp.sync_droid([STDIO_SERVER])
    assert results2 == [
        mcp.SyncResult("Atlassian-Rovo-MCP", True, "already configured, skipped")
    ]

    doc = json.loads(droid_path.read_text(encoding="utf-8"))
    assert "existing" in doc["mcpServers"]
    assert "Atlassian-Rovo-MCP" in doc["mcpServers"]


# ---------- devin: persistent via mcp_config.json ----------


def test_sync_devin_creates_config(tmp_path, monkeypatch):
    devin_path = tmp_path / "mcp_config.json"
    monkeypatch.setattr(mcp, "DEVIN_MCP_CONFIG_PATH", devin_path)

    results = mcp.sync_devin([STDIO_SERVER, REMOTE_SERVER])
    assert all(r.ok for r in results)

    doc = json.loads(devin_path.read_text(encoding="utf-8"))
    assert doc["mcpServers"]["Atlassian-Rovo-MCP"]["command"] == "npx"
    assert doc["mcpServers"]["example"]["url"] == "https://example.com/mcp"
    if os.name != "nt":
        assert devin_path.stat().st_mode & 0o777 == 0o600


def test_sync_devin_preserves_and_idempotent(tmp_path, monkeypatch):
    devin_path = tmp_path / "mcp_config.json"
    initial = {"custom": True, "mcpServers": {"existing": {"command": "custom"}}}
    devin_path.write_text(json.dumps(initial), encoding="utf-8")
    monkeypatch.setattr(mcp, "DEVIN_MCP_CONFIG_PATH", devin_path)

    mcp.sync_devin([STDIO_SERVER])
    results2 = mcp.sync_devin([STDIO_SERVER])
    assert results2 == [
        mcp.SyncResult("Atlassian-Rovo-MCP", True, "already configured, skipped")
    ]

    doc = json.loads(devin_path.read_text(encoding="utf-8"))
    assert doc["custom"] is True
    assert doc["mcpServers"]["existing"]["command"] == "custom"


def test_sync_unsupported_agent_raises():
    with pytest.raises(ValueError) as excinfo:
        mcp.sync("agy", [])
    msg = str(excinfo.value)
    assert "isn't supported for 'agy'" in msg
    assert "Agent MCP support:" in msg
    assert "REFERENCE.md" not in msg
    assert "claude" in msg
    assert "per-run" in msg
    assert "sync" in msg
    assert "none" in msg

    with pytest.raises(ValueError) as excinfo:
        mcp.sync("claude", [])
    msg = str(excinfo.value)
    assert "Agent MCP support:" in msg
    assert "REFERENCE.md" not in msg

