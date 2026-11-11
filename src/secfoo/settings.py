"""Loads ~/.secfoo/config.toml: user-configurable defaults and MCP servers.

This is the one place users define MCP servers (e.g. an Atlassian/Confluence
connector) so they don't have to hand-wire each agent CLI separately. How
that config actually reaches each agent varies by what the CLI supports --
see secfoo/mcp.py for the per-agent mechanics.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from secfoo.config import STORE_DIR

CONFIG_PATH = STORE_DIR / "config.toml"


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class MCPServerConfig:
    name: str
    command: str | None = None
    args: list[str] = field(default_factory=list)
    url: str | None = None
    transport: str = "stdio"  # stdio | sse | http
    env: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if bool(self.command) == bool(self.url):
            raise ConfigError(
                f"mcp_servers.{self.name}: set exactly one of `command` (stdio) or `url` (sse/http)"
            )


@dataclass(frozen=True)
class Defaults:
    agent: str | None = None
    depth: str | None = None
    timeout: int | None = None
    # Additive on top of the renderer's built-in exclusions, never a
    # replacement -- see renderer._exclude_section.
    exclude: list[str] = field(default_factory=list)
    # CI gates, overridable per run by `secfoo run --fail-on / --max-cost`.
    # fail_on: lowest severity that fails the run (critical|high|medium|low).
    # max_cost_usd: fail the run when the summed reported spend exceeds this.
    fail_on: str | None = None
    max_cost_usd: float | None = None


VALID_FAIL_ON = ("critical", "high", "medium", "low")


@dataclass(frozen=True)
class SecfooConfig:
    defaults: Defaults
    mcp_servers: list[MCPServerConfig]
    # [memory] enabled -- whether the secfoo-memory MCP server is wired in
    # once a memory key exists (secfoo memory signup/login). On by default;
    # without a key there is nothing to wire in either way.
    memory_enabled: bool = True
    agent_models: dict[str, str] = field(default_factory=dict)
    # [agents.<id>].max_input_tokens -- pre-flight prompt-size cap (#32).
    agent_max_input_tokens: dict[str, int] = field(default_factory=dict)


def _parse_mcp_server(name: str, raw: dict) -> MCPServerConfig:
    try:
        return MCPServerConfig(
            name=name,
            command=raw.get("command"),
            args=list(raw.get("args", [])),
            url=raw.get("url"),
            transport=raw.get("transport", "stdio"),
            env=dict(raw.get("env", {})),
            headers=dict(raw.get("headers", {})),
        )
    except ConfigError:
        raise
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"mcp_servers.{name}: {exc}") from exc


def load_config(path: Path | None = None) -> SecfooConfig:
    path = path or CONFIG_PATH
    if not path.exists():
        return SecfooConfig(defaults=Defaults(), mcp_servers=[])

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc

    defaults_raw = data.get("defaults", {})
    exclude_raw = defaults_raw.get("exclude", [])
    if not isinstance(exclude_raw, list) or not all(isinstance(p, str) for p in exclude_raw):
        raise ConfigError("defaults.exclude must be an array of strings")
    fail_on = defaults_raw.get("fail_on")
    if fail_on is not None and fail_on not in VALID_FAIL_ON:
        raise ConfigError(f"defaults.fail_on must be one of {', '.join(VALID_FAIL_ON)}, got {fail_on!r}")
    max_cost_usd = defaults_raw.get("max_cost_usd")
    if max_cost_usd is not None:
        if isinstance(max_cost_usd, bool) or not isinstance(max_cost_usd, (int, float)) or max_cost_usd <= 0:
            raise ConfigError("defaults.max_cost_usd must be a positive number")
        max_cost_usd = float(max_cost_usd)
    defaults = Defaults(
        agent=defaults_raw.get("agent"),
        depth=defaults_raw.get("depth"),
        timeout=defaults_raw.get("timeout"),
        exclude=list(exclude_raw),
        fail_on=fail_on,
        max_cost_usd=max_cost_usd,
    )

    agents_raw = data.get("agents", {})
    if not isinstance(agents_raw, dict):
        raise ConfigError("[agents] must be a table")
    agent_models = {}
    agent_max_input_tokens = {}
    for agent_id, options in agents_raw.items():
        if not isinstance(options, dict):
            raise ConfigError(f"agents.{agent_id} must be a table")
        model = options.get("model")
        if model is not None:
            if not isinstance(model, str) or not model.strip():
                raise ConfigError(f"agents.{agent_id}.model must be a non-empty string")
            agent_models[agent_id] = model
        max_input_tokens = options.get("max_input_tokens")
        if max_input_tokens is not None:
            if isinstance(max_input_tokens, bool) or not isinstance(max_input_tokens, int) or max_input_tokens <= 0:
                raise ConfigError(f"agents.{agent_id}.max_input_tokens must be a positive integer")
            agent_max_input_tokens[agent_id] = max_input_tokens

    servers = []
    seen_names: set[str] = set()
    for entry in data.get("mcp_servers", []):
        name = entry.get("name")
        if not name:
            raise ConfigError("mcp_servers entry missing required `name` field")
        if name in seen_names:
            raise ConfigError(f"mcp_servers: duplicate server name {name!r}")
        seen_names.add(name)
        servers.append(_parse_mcp_server(name, entry))

    memory_raw = data.get("memory", {})
    if not isinstance(memory_raw, dict):
        raise ConfigError("[memory] must be a table")
    memory_enabled = memory_raw.get("enabled", True)
    if not isinstance(memory_enabled, bool):
        raise ConfigError("memory.enabled must be true or false")

    return SecfooConfig(
        defaults=defaults,
        mcp_servers=servers,
        memory_enabled=memory_enabled,
        agent_models=agent_models,
        agent_max_input_tokens=agent_max_input_tokens,
    )
