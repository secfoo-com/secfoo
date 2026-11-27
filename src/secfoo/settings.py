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
    # Documentation hostnames this server can read, e.g. a self-hosted Confluence or Jira; not the server's own `url`
    hosts: list[str] = field(default_factory=list)
    # Tools the `api` agent may call on this server (#123). Empty = only the
    # tools the server annotates `readOnlyHint: true`; set = exactly these.
    tools: list[str] = field(default_factory=list)

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
    # Documentation sources read on every run: https:// URLs or local files
    # and folders (#125). Merged with --context; see context_sources.py.
    context: list[str] = field(default_factory=list)


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
    # [skills] paths -- extra folders of custom skill definitions (#79).
    skill_paths: list[str] = field(default_factory=list)


MCP_TRANSPORTS = ("stdio", "sse", "http")


def _check_mcp_types(name: str, raw: dict) -> dict:
    """These values end up in a subprocess argument list (`claude mcp add`,
    `gemini mcp add`) or an agent's JSON config, where a number or a nested
    table crashed with TypeError instead of naming the bad key (#121).

    Returns `raw` with the shapes that have always worked normalised rather
    than rejected: a blank `command`/`url` is unset, scalar `env`/`headers`
    values (`PORT = 8080`, `DEBUG = true`) become strings. Only values that
    used to crash raise ConfigError."""
    raw = dict(raw)
    for key in ("command", "url"):
        value = raw.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            raise ConfigError(f"mcp_servers.{name}.{key} must be a string")
        if not value.strip():
            raw[key] = None
    args = raw.get("args", [])
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise ConfigError(f"mcp_servers.{name}.args must be an array of strings")
    for key in ("env", "headers"):
        table = raw.get(key, {})
        if not isinstance(table, dict):
            raise ConfigError(f"mcp_servers.{name}.{key} must be a table")
        normalised = {}
        for k, v in table.items():
            if isinstance(v, bool):
                normalised[k] = "true" if v else "false"
            elif isinstance(v, (str, int, float)):
                normalised[k] = str(v)
            else:
                raise ConfigError(f"mcp_servers.{name}.{key}.{k} must be a string, number or boolean")
        raw[key] = normalised
    transport = raw.get("transport", "stdio")
    if not isinstance(transport, str) or not transport.strip():
        raise ConfigError(f"mcp_servers.{name}.transport must be a non-empty string, e.g. {', '.join(MCP_TRANSPORTS)}")
    return raw


def _parse_mcp_server(name: str, raw: dict) -> MCPServerConfig:
    raw = _check_mcp_types(name, raw)
    hosts_raw = raw.get("hosts", [])
    if not isinstance(hosts_raw, list) or not all(isinstance(h, str) for h in hosts_raw):
        raise ConfigError(f"mcp_servers.{name}.hosts must be an array of strings")

    hosts: list[str] = []
    seen_hosts: set[str] = set()
    for h in hosts_raw:
        cleaned = h.strip().lower()
        if not cleaned:
            raise ConfigError(f"mcp_servers.{name}.hosts contains an empty host entry")
        if any(ch in cleaned for ch in ("/", ":", "@")) or any(ch.isspace() for ch in cleaned):
            raise ConfigError(
                f"mcp_servers.{name}.hosts entry {h!r} contains invalid characters ('/', ':', '@', or whitespace)"
            )
        test_part = cleaned.removeprefix("*.")
        if not test_part or "*" in test_part:
            raise ConfigError(f"mcp_servers.{name}.hosts invalid pattern {h!r}")

        if cleaned not in seen_hosts:
            seen_hosts.add(cleaned)
            hosts.append(cleaned)

    tools_raw = raw.get("tools", [])
    if not isinstance(tools_raw, list) or not all(isinstance(t, str) and t.strip() for t in tools_raw):
        raise ConfigError(f"mcp_servers.{name}.tools must be an array of tool names")

    try:
        return MCPServerConfig(
            name=name,
            command=raw.get("command"),
            args=list(raw.get("args", [])),
            url=raw.get("url"),
            transport=raw.get("transport", "stdio"),
            env=dict(raw.get("env", {})),
            headers=dict(raw.get("headers", {})),
            hosts=hosts,
            tools=[t.strip() for t in tools_raw],
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
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{path}: not valid UTF-8 (byte {exc.start})") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}") from exc

    # Every section is checked for its shape before it's read: valid TOML
    # like `defaults = 1` used to escape as AttributeError (#121).
    defaults_raw = data.get("defaults", {})
    if not isinstance(defaults_raw, dict):
        raise ConfigError("[defaults] must be a table")
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
    for key in ("agent", "depth"):
        value = defaults_raw.get(key)
        if value is not None and (not isinstance(value, str) or not value.strip()):
            raise ConfigError(f"defaults.{key} must be a non-empty string")
    timeout = defaults_raw.get("timeout")
    # A whole-number float (`timeout = 1800.0`) has always worked; keep it.
    if isinstance(timeout, float) and timeout.is_integer():
        timeout = int(timeout)
        defaults_raw = {**defaults_raw, "timeout": timeout}
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0):
        raise ConfigError("defaults.timeout must be a positive integer (seconds)")
    context_raw = defaults_raw.get("context", [])
    if not isinstance(context_raw, list) or not all(isinstance(c, str) and c.strip() for c in context_raw):
        raise ConfigError("defaults.context must be an array of non-empty strings")
    defaults = Defaults(
        agent=defaults_raw.get("agent"),
        depth=defaults_raw.get("depth"),
        timeout=defaults_raw.get("timeout"),
        exclude=list(exclude_raw),
        fail_on=fail_on,
        max_cost_usd=max_cost_usd,
        context=list(context_raw),
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
    servers_raw = data.get("mcp_servers", [])
    if not isinstance(servers_raw, list) or not all(isinstance(entry, dict) for entry in servers_raw):
        raise ConfigError("mcp_servers must be an array of tables ([[mcp_servers]])")
    for entry in servers_raw:
        name = entry.get("name")
        if not name:
            raise ConfigError("mcp_servers entry missing required `name` field")
        if not isinstance(name, str):
            raise ConfigError(f"mcp_servers: name must be a string, got {name!r}")
        if name in seen_names:
            raise ConfigError(f"mcp_servers: duplicate server name {name!r}")
        seen_names.add(name)
        servers.append(_parse_mcp_server(name, entry))

    skills_raw = data.get("skills", {})
    if not isinstance(skills_raw, dict):
        raise ConfigError("[skills] must be a table")
    skill_paths = skills_raw.get("paths", [])
    if not isinstance(skill_paths, list) or not all(isinstance(p, str) and p.strip() for p in skill_paths):
        raise ConfigError("skills.paths must be an array of folder paths")

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
        skill_paths=list(skill_paths),
    )
