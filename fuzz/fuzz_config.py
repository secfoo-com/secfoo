"""Fuzz `~/.secfoo/config.toml` loading: file bytes -> SecfooConfig.

Input: the raw bytes of a config.toml.

Contract: a SecfooConfig whose every field has its declared type, or
ConfigError naming the bad key -- never another exception. The types matter
beyond load_config: `[defaults]` values reach `secfoo run`, and MCP server
values end up in a subprocess argument list (`claude mcp add`), where a
number or a nested table crashed instead of failing here.

    python fuzz/fuzz_config.py WORK fuzz/corpus/config -max_total_time=60
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from _common import main

from secfoo.settings import (
    MCP_TRANSPORTS,
    VALID_FAIL_ON,
    ConfigError,
    MCPServerConfig,
    SecfooConfig,
    load_config,
)

_PATH = Path(tempfile.mkdtemp(prefix="secfoo-fuzz-config-")) / "config.toml"


def _optional(value, kind) -> bool:
    return value is None or isinstance(value, kind)


def _strings(values) -> bool:
    return isinstance(values, list) and all(isinstance(v, str) for v in values)


def _string_table(table) -> bool:
    return isinstance(table, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in table.items())


def check(data: bytes) -> None:
    _PATH.write_bytes(data)
    try:
        config = load_config(_PATH)
    except ConfigError:
        return
    assert isinstance(config, SecfooConfig)

    defaults = config.defaults
    assert _optional(defaults.agent, str) and _optional(defaults.depth, str)
    assert defaults.timeout is None or (type(defaults.timeout) is int and defaults.timeout > 0)
    assert _strings(defaults.exclude)
    assert defaults.fail_on is None or defaults.fail_on in VALID_FAIL_ON
    assert defaults.max_cost_usd is None or (type(defaults.max_cost_usd) is float and defaults.max_cost_usd > 0)

    assert isinstance(config.memory_enabled, bool)
    assert _strings(config.skill_paths)
    assert all(isinstance(m, str) and m.strip() for m in config.agent_models.values())
    assert all(type(n) is int and n > 0 for n in config.agent_max_input_tokens.values())

    names = [server.name for server in config.mcp_servers]
    assert len(names) == len(set(names))
    for server in config.mcp_servers:
        assert isinstance(server, MCPServerConfig) and isinstance(server.name, str)
        assert _optional(server.command, str) and _optional(server.url, str)
        assert bool(server.command) != bool(server.url)
        assert _strings(server.args) and _string_table(server.env) and _string_table(server.headers)
        assert server.transport in MCP_TRANSPORTS


if __name__ == "__main__":
    main(check)
