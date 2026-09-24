from __future__ import annotations

import pytest

from secfoo.settings import ConfigError, load_config


def test_load_config_missing_file_returns_empty(tmp_path):
    cfg = load_config(tmp_path / "does-not-exist.toml")
    assert cfg.defaults.agent is None
    assert cfg.mcp_servers == []


def test_load_config_parses_defaults(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('[defaults]\nagent = "gemini"\ndepth = "standard"\ntimeout = 900\n')
    cfg = load_config(path)
    assert cfg.defaults.agent == "gemini"
    assert cfg.defaults.depth == "standard"
    assert cfg.defaults.timeout == 900


def test_load_config_parses_ci_gate_defaults(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('[defaults]\nfail_on = "high"\nmax_cost_usd = 2\n')
    cfg = load_config(path)
    assert cfg.defaults.fail_on == "high"
    assert cfg.defaults.max_cost_usd == 2.0


def test_load_config_gate_defaults_are_none_when_absent(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('[defaults]\nagent = "claude"\n')
    cfg = load_config(path)
    assert cfg.defaults.fail_on is None
    assert cfg.defaults.max_cost_usd is None


@pytest.mark.parametrize(
    "body",
    ['[defaults]\nfail_on = "severe"\n', "[defaults]\nmax_cost_usd = 0\n", "[defaults]\nmax_cost_usd = true\n"],
)
def test_load_config_rejects_invalid_gate_defaults(tmp_path, body):
    path = tmp_path / "config.toml"
    path.write_text(body)
    with pytest.raises(ConfigError):
        load_config(path)


def test_load_config_parses_stdio_mcp_server(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        """
[[mcp_servers]]
name = "Atlassian-Rovo-MCP"
command = "npx"
args = ["-y", "mcp-remote@latest", "https://mcp.atlassian.com/v1/mcp/authv2"]
"""
    )
    cfg = load_config(path)
    assert len(cfg.mcp_servers) == 1
    server = cfg.mcp_servers[0]
    assert server.name == "Atlassian-Rovo-MCP"
    assert server.command == "npx"
    assert server.args == ["-y", "mcp-remote@latest", "https://mcp.atlassian.com/v1/mcp/authv2"]
    assert server.url is None


def test_load_config_parses_remote_mcp_server(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        """
[[mcp_servers]]
name = "example"
url = "https://example.com/mcp"
transport = "http"
headers = { Authorization = "Bearer abc" }
"""
    )
    cfg = load_config(path)
    server = cfg.mcp_servers[0]
    assert server.url == "https://example.com/mcp"
    assert server.transport == "http"
    assert server.headers == {"Authorization": "Bearer abc"}
    assert server.command is None


def test_mcp_server_requires_exactly_one_of_command_or_url(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('[[mcp_servers]]\nname = "bad"\n')
    with pytest.raises(ConfigError):
        load_config(path)

    path.write_text('[[mcp_servers]]\nname = "bad"\ncommand = "npx"\nurl = "https://x"\n')
    with pytest.raises(ConfigError):
        load_config(path)


def test_load_config_rejects_duplicate_server_names(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text(
        """
[[mcp_servers]]
name = "dup"
command = "npx"

[[mcp_servers]]
name = "dup"
command = "npx"
"""
    )
    with pytest.raises(ConfigError):
        load_config(path)


def test_load_config_missing_name_raises(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text('[[mcp_servers]]\ncommand = "npx"\n')
    with pytest.raises(ConfigError):
        load_config(path)


def test_load_config_invalid_toml_raises_config_error(tmp_path):
    path = tmp_path / "config.toml"
    path.write_text("this is not [ valid toml")
    with pytest.raises(ConfigError):
        load_config(path)
