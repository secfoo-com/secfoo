from __future__ import annotations

import json
import stat
import subprocess
import sys

import pytest

from secfoo import mcp
from secfoo.settings import MCPServerConfig


@pytest.fixture(autouse=True)
def _agent_clis_on_path(monkeypatch):
    # Existing sync tests assume the gemini/agent CLIs are installed.
    monkeypatch.setattr(mcp.shutil, "which", lambda name: f"/usr/bin/{name}")


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
    assert captured["cmd"][:4] == ["/usr/bin/gemini", "mcp", "add", "--scope"]
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


def test_sync_cursor_preserves_existing_unrelated_entries(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    cursor_path.write_text(json.dumps({"mcpServers": {"other-server": {"command": "foo"}}}))
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)
    monkeypatch.setattr(mcp.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", ""))

    mcp.sync_cursor([STDIO_SERVER])
    payload = json.loads(cursor_path.read_text())
    assert "other-server" in payload["mcpServers"]
    assert "Atlassian-Rovo-MCP" in payload["mcpServers"]


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


def test_sync_cursor_rejects_non_object_config(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    cursor_path.write_text("[]")
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)

    results = mcp.sync_cursor([STDIO_SERVER])
    assert results[0].ok is False
    assert str(cursor_path) in results[0].message


def test_sync_cursor_rejects_non_object_mcp_servers(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    cursor_path.write_text(json.dumps({"mcpServers": []}))
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)

    results = mcp.sync_cursor([STDIO_SERVER])
    assert results[0].ok is False
    assert str(cursor_path) in results[0].message


def test_sync_cursor_keeps_other_top_level_keys(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    cursor_path.write_text(json.dumps({"mcpServers": {}, "customKey": {"a": 1}}))
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)
    monkeypatch.setattr(mcp.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", ""))

    results = mcp.sync_cursor([STDIO_SERVER])
    assert results[0].ok is True
    payload = json.loads(cursor_path.read_text())
    assert payload["customKey"] == {"a": 1}
    assert "Atlassian-Rovo-MCP" in payload["mcpServers"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
@pytest.mark.parametrize("existing_mode", [None, 0o644], ids=["new-file", "existing-0644"])
def test_sync_cursor_writes_config_owner_only(tmp_path, monkeypatch, existing_mode):
    # The file holds each server's env and headers (bearer keys, API tokens).
    cursor_path = tmp_path / "mcp.json"
    if existing_mode is not None:
        cursor_path.write_text(json.dumps({"mcpServers": {}}))
        cursor_path.chmod(existing_mode)
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)
    monkeypatch.setattr(mcp.subprocess, "run", lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", ""))

    results = mcp.sync_cursor([REMOTE_SERVER])
    assert results[0].ok is True
    assert stat.S_IMODE(cursor_path.stat().st_mode) == 0o600
    assert json.loads(cursor_path.read_text())["mcpServers"]["example"]["headers"] == {"Authorization": "Bearer abc"}


# ---------- dispatch ----------


def test_sync_dispatches_by_agent_id(monkeypatch):
    monkeypatch.setattr(mcp, "sync_gemini", lambda servers: "gemini-result")
    monkeypatch.setattr(mcp, "sync_cursor", lambda servers: "cursor-result")
    assert mcp.sync("gemini", []) == "gemini-result"
    assert mcp.sync("agent", []) == "cursor-result"


def test_sync_unsupported_agent_raises():
    with pytest.raises(ValueError):
        mcp.sync("agy", [])
    with pytest.raises(ValueError):
        mcp.sync("claude", [])


def test_sync_gemini_reports_missing_cli_instead_of_crashing(monkeypatch):
    monkeypatch.setattr(mcp.shutil, "which", lambda name: None)

    def fail_if_called(cmd, **kwargs):
        raise AssertionError("should not run gemini when the CLI is missing")

    monkeypatch.setattr(mcp.subprocess, "run", fail_if_called)
    results = mcp.sync_gemini([STDIO_SERVER])

    assert len(results) == 1
    assert results[0].ok is False
    assert "gemini" in results[0].message


def test_sync_cursor_reports_missing_cli_before_writing_config(tmp_path, monkeypatch):
    cursor_path = tmp_path / "mcp.json"
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", cursor_path)
    monkeypatch.setattr(mcp.shutil, "which", lambda name: None)

    def fail_if_called(cmd, **kwargs):
        raise AssertionError("should not run agent when the CLI is missing")

    monkeypatch.setattr(mcp.subprocess, "run", fail_if_called)
    results = mcp.sync_cursor([STDIO_SERVER])

    assert len(results) == 1
    assert results[0].ok is False
    assert "agent" in results[0].message
    assert not cursor_path.exists()


def test_sync_launches_the_resolved_cli_path(tmp_path, monkeypatch):
    # On Windows npm installs `gemini.cmd`; shutil.which finds it but a bare
    # "gemini" passed to subprocess raises FileNotFoundError.
    monkeypatch.setattr(mcp.shutil, "which", lambda name: rf"C:\npm\{name}.CMD")
    monkeypatch.setattr(mcp, "CURSOR_MCP_CONFIG_PATH", tmp_path / "mcp.json")
    launched = []

    def fake_run(cmd, **kwargs):
        launched.append(cmd[0])
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(mcp.subprocess, "run", fake_run)
    mcp.sync_gemini([STDIO_SERVER])
    mcp.sync_cursor([STDIO_SERVER])
    assert launched == [r"C:\npm\gemini.CMD", r"C:\npm\gemini.CMD", r"C:\npm\agent.CMD"]
