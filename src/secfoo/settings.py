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


@dataclass(frozen=True)
class SecfooConfig:
    defaults: Defaults
    mcp_servers: list[MCPServerConfig]


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
        data = tomllib.loads(path.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc

    defaults_raw = data.get("defaults", {})
    exclude_raw = defaults_raw.get("exclude", [])
    if not isinstance(exclude_raw, list) or not all(isinstance(p, str) for p in exclude_raw):
        raise ConfigError("defaults.exclude must be an array of strings")
    defaults = Defaults(
        agent=defaults_raw.get("agent"),
        depth=defaults_raw.get("depth"),
        timeout=defaults_raw.get("timeout"),
        exclude=list(exclude_raw),
    )

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

    return SecfooConfig(defaults=defaults, mcp_servers=servers)
