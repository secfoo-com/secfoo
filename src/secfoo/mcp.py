"""Bridges secfoo's portable MCP server config (settings.py) to each agent
CLI's own mechanism for it. These differ a lot by CLI:

- claude: supports `--mcp-config <file>`, which loads servers scoped to just
  that one invocation -- no global state touched. Handled automatically by
  ClaudeAdapter on every run; no explicit sync step needed.
- gemini: has a `gemini mcp add <name> <commandOrUrl> ...` subcommand that
  registers a server persistently (user or project scope). No per-invocation
  file flag exists, so this must be done once via `secfoo mcp sync`.
- agent (Cursor): has no `mcp add` subcommand at all -- servers are defined
  by editing `~/.cursor/mcp.json` directly, then approved via
  `agent mcp enable <name>`. `secfoo mcp sync` does that merge.
- codex: reads `~/.codex/config.toml` (`[mcp_servers.<name>]`). While Codex has
  a `-c` CLI configuration override flag, passing MCP server commands, URLs, or
  headers via CLI arguments would expose credentials in process table listings
  (`ps`). Persistent configuration with `0600` permissions keeps credentials secure.
- copilot: reads `~/.copilot/mcp-config.json` (`mcpServers`). The Copilot CLI
  does not provide a per-run flag for ephemeral MCP configuration.
- opencode: reads `~/.config/opencode/opencode.json` (`mcp` table). OpenCode's
  `OPENCODE_CONFIG_CONTENT` environment variable is designed for permission
  settings rather than dynamic MCP server arrays.
- droid: reads `~/.factory/mcp.json` (`mcpServers`). Droid has no CLI flag for
  per-run MCP configuration.
- devin: reads `%APPDATA%\\devin\\mcp_config.json` (Windows) or
  `~/.config/devin/mcp_config.json` (Unix). Devin has no per-run MCP configuration flag.
- agy (Antigravity): no MCP subcommand or flag exposed by the CLI (not documented
  as supported; not re-verified (no agy binary available)). Refuses with a clean error.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import tomlkit
from tomlkit.exceptions import TOMLKitError

from secfoo.config import STORE_DIR
from secfoo.settings import MCPServerConfig

logger = logging.getLogger(__name__)

CLAUDE_MCP_CONFIG_PATH = STORE_DIR / "claude-mcp-config.json"
CURSOR_MCP_CONFIG_PATH = Path.home() / ".cursor" / "mcp.json"
CODEX_CONFIG_PATH = Path.home() / ".codex" / "config.toml"
COPILOT_MCP_CONFIG_PATH = Path.home() / ".copilot" / "mcp-config.json"
OPENCODE_MCP_CONFIG_PATH = Path.home() / ".config" / "opencode" / "opencode.json"
DROID_MCP_CONFIG_PATH = Path.home() / ".factory" / "mcp.json"


def _default_devin_path() -> Path:
    if os.name == "nt" and "APPDATA" in os.environ:
        return Path(os.environ["APPDATA"]) / "devin" / "mcp_config.json"
    return Path.home() / ".config" / "devin" / "mcp_config.json"


DEVIN_MCP_CONFIG_PATH = _default_devin_path()

SYNC_SUPPORTED_AGENTS = {
    "gemini",
    "agent",
    "codex",
    "copilot",
    "opencode",
    "droid",
    "devin",
}


class MCPSyncError(ValueError):
    """Raised when an MCP config cannot be synchronized."""


@dataclass
class SyncResult:
    server_name: str
    ok: bool
    message: str


def _write_private_file(path: Path, content: str) -> None:
    """Atomically write a file with 0600 permissions inside path.parent."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp"
    fd = os.open(tmp_path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            fd = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(tmp_path, 0o600)
        except OSError as exc:
            logger.warning("Failed to chmod 0600 on %s: %s", tmp_path, exc)
        os.replace(tmp_path, path)
    finally:
        if fd != -1:
            with contextlib.suppress(OSError):
                os.close(fd)
        if tmp_path.exists():
            with contextlib.suppress(OSError):
                tmp_path.unlink()


def effective_servers(configured: list[MCPServerConfig]) -> list[MCPServerConfig]:
    """The user's own [[mcp_servers]] plus the default secfoo-memory
    server when memory is on (memory.memory_server). A user-defined server
    with the same name wins -- that is how a self-hosted enterprise memory
    service, or a staging URL, replaces the default."""
    from secfoo import memory

    servers = list(configured)
    default = memory.memory_server()
    if default is not None and all(server.name != default.name for server in servers):
        servers.append(default)
    return servers


def _server_to_standard_shape(server: MCPServerConfig) -> dict:
    """The de facto standard mcpServers entry shape shared by Claude Code,
    VS Code, and Cursor's own config files."""
    if server.command:
        entry: dict = {"command": server.command, "args": list(server.args)}
        if server.env:
            entry["env"] = dict(server.env)
        return entry
    entry = {"type": server.transport, "url": server.url}
    if server.headers:
        entry["headers"] = dict(server.headers)
    return entry


def _sync_json_mcp_config(
    path: Path,
    root_key: str,
    servers: list[MCPServerConfig],
    shape_fn: Callable[[MCPServerConfig], dict],
    *,
    post_add_hook: Callable[[list[str], list[SyncResult]], None] | None = None,
) -> list[SyncResult]:
    """Generic format-preserving JSON sync helper for agents using JSON config."""
    data: dict = {}
    if path.exists():
        try:
            raw = path.read_bytes().decode("utf-8")
            parsed = json.loads(raw)
        except UnicodeDecodeError as exc:
            return [SyncResult("*", False, f"{path} is not valid UTF-8: {exc}")]
        except (json.JSONDecodeError, OSError) as exc:
            return [SyncResult("*", False, f"{path} is not valid JSON: {exc}")]
        if not isinstance(parsed, dict):
            raise MCPSyncError(
                f"{path} does not contain a JSON object (got {type(parsed).__name__})"
            )
        data = parsed

    existing_servers = data.get(root_key)
    if existing_servers is None:
        existing_servers = {}
        data[root_key] = existing_servers
    elif not isinstance(existing_servers, dict):
        raise MCPSyncError(f"'{root_key}' in {path} is not a JSON object")

    results: list[SyncResult] = []
    newly_added: list[str] = []
    for server in servers:
        if server.name in existing_servers:
            results.append(SyncResult(server.name, True, "already configured, skipped"))
            continue
        existing_servers[server.name] = shape_fn(server)
        newly_added.append(server.name)
        results.append(SyncResult(server.name, True, f"added to {path}"))

    if newly_added:
        _write_private_file(path, json.dumps(data, indent=2) + "\n")
        if post_add_hook is not None:
            post_add_hook(newly_added, results)

    return results


# ---------- claude: ephemeral, per-invocation ----------


def write_claude_mcp_config(servers: list[MCPServerConfig]) -> Path | None:
    """Writes ~/.secfoo/claude-mcp-config.json from the configured servers,
    for use with `claude --mcp-config <path>`. Returns None (and writes
    nothing) if no servers are configured, so the adapter can skip the flag
    entirely.
    """
    if not servers:
        return None
    payload = {"mcpServers": {s.name: _server_to_standard_shape(s) for s in servers}}
    _write_private_file(CLAUDE_MCP_CONFIG_PATH, json.dumps(payload, indent=2) + "\n")
    return CLAUDE_MCP_CONFIG_PATH


# ---------- gemini: persistent, via `gemini mcp add` ----------

_GEMINI_LIST_NAME_RE = re.compile(r"^[^\sA-Za-z0-9]*\s*([^\s:]+):")


def _gemini_existing_names() -> set[str]:
    try:
        proc = subprocess.run(
            ["gemini", "mcp", "list"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except FileNotFoundError:
        raise MCPSyncError(
            "Gemini CLI ('gemini') is not installed or not on PATH"
        ) from None
    names = set()
    for line in proc.stdout.splitlines():
        match = _GEMINI_LIST_NAME_RE.match(line.strip())
        if match:
            names.add(match.group(1))
    return names


def _gemini_add_command(server: MCPServerConfig) -> list[str]:
    target = server.url if server.url else server.command
    cmd = ["gemini", "mcp", "add", "--scope", "user", server.name, target]
    if server.command:
        cmd += list(server.args)
    if server.transport != "stdio":
        cmd += ["-t", server.transport]
    for key, value in server.env.items():
        cmd += ["-e", f"{key}={value}"]
    for key, value in server.headers.items():
        cmd += ["-H", f"{key}: {value}"]
    return cmd


def sync_gemini(servers: list[MCPServerConfig]) -> list[SyncResult]:
    existing = _gemini_existing_names()
    results = []
    for server in servers:
        if server.name in existing:
            results.append(SyncResult(server.name, True, "already configured, skipped"))
            continue
        try:
            proc = subprocess.run(
                _gemini_add_command(server),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except FileNotFoundError:
            raise MCPSyncError(
                "Gemini CLI ('gemini') is not installed or not on PATH"
            ) from None
        if proc.returncode == 0:
            results.append(SyncResult(server.name, True, "added"))
        else:
            results.append(SyncResult(server.name, False, proc.stderr.strip() or proc.stdout.strip()))
    return results


# ---------- agent (Cursor): persistent, via ~/.cursor/mcp.json merge ----------


def _cursor_post_add(newly_added: list[str], results: list[SyncResult]) -> None:
    for name in newly_added:
        try:
            proc = subprocess.run(
                ["agent", "mcp", "enable", name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if proc.returncode != 0:
                for result in results:
                    if result.server_name == name:
                        result.ok = False
                        result.message += f" (enable failed: {proc.stderr.strip()})"
        except FileNotFoundError:
            for result in results:
                if result.server_name == name:
                    result.ok = False
                    result.message += (
                        " (written, but agent binary not found on PATH to enable)"
                    )
        except (OSError, subprocess.TimeoutExpired) as exc:
            for result in results:
                if result.server_name == name:
                    result.ok = False
                    result.message += (
                        f" (written, but agent mcp enable could not run: {exc})"
                    )


def sync_cursor(servers: list[MCPServerConfig]) -> list[SyncResult]:
    return _sync_json_mcp_config(
        CURSOR_MCP_CONFIG_PATH,
        "mcpServers",
        servers,
        _server_to_standard_shape,
        post_add_hook=_cursor_post_add,
    )


# ---------- codex: persistent, via ~/.codex/config.toml merge ----------


def sync_codex(servers: list[MCPServerConfig]) -> list[SyncResult]:
    if CODEX_CONFIG_PATH.exists():
        try:
            raw = CODEX_CONFIG_PATH.read_bytes().decode("utf-8")
            doc = tomlkit.parse(raw)
        except UnicodeDecodeError as exc:
            return [
                SyncResult("*", False, f"{CODEX_CONFIG_PATH} is not valid UTF-8: {exc}")
            ]
        except (TOMLKitError, OSError) as exc:
            return [
                SyncResult("*", False, f"{CODEX_CONFIG_PATH} is not valid TOML: {exc}")
            ]
        if not isinstance(doc, dict):
            raise MCPSyncError(f"{CODEX_CONFIG_PATH} does not contain a TOML table")
    else:
        doc = tomlkit.document()

    if "mcp_servers" not in doc:
        doc["mcp_servers"] = tomlkit.table(is_super_table=True)
    elif isinstance(doc["mcp_servers"], tomlkit.items.InlineTable):
        super_table = tomlkit.table(is_super_table=True)
        for k, v in doc["mcp_servers"].value.items():
            super_table[k] = v
        doc["mcp_servers"] = super_table

    mcp_servers_table = doc["mcp_servers"]
    if not isinstance(mcp_servers_table, dict):
        raise MCPSyncError(f"'mcp_servers' in {CODEX_CONFIG_PATH} is not a TOML table")

    results: list[SyncResult] = []
    newly_added = False
    for server in servers:
        if server.name in mcp_servers_table:
            results.append(SyncResult(server.name, True, "already configured, skipped"))
            continue

        if server.command:
            server_tbl = tomlkit.table()
            server_tbl["command"] = server.command
            server_tbl["args"] = list(server.args)
            if server.env:
                env_tbl = tomlkit.table()
                for k, v in server.env.items():
                    env_tbl[k] = v
                server_tbl["env"] = env_tbl
            mcp_servers_table[server.name] = server_tbl
            newly_added = True
            results.append(
                SyncResult(server.name, True, f"added to {CODEX_CONFIG_PATH}")
            )
        elif server.url:
            if server.transport == "sse":
                results.append(
                    SyncResult(
                        server.name,
                        False,
                        "Codex does not support SSE transport for remote MCP servers (only streamable-HTTP is supported)",
                    )
                )
                continue
            server_tbl = tomlkit.table()
            server_tbl["url"] = server.url
            if server.headers:
                headers_tbl = tomlkit.table()
                for k, v in server.headers.items():
                    headers_tbl[k] = v
                server_tbl["http_headers"] = headers_tbl
            mcp_servers_table[server.name] = server_tbl
            newly_added = True
            results.append(
                SyncResult(server.name, True, f"added to {CODEX_CONFIG_PATH}")
            )
        else:
            results.append(
                SyncResult(
                    server.name, False, "server must define either 'command' or 'url'"
                )
            )

    if newly_added:
        _write_private_file(CODEX_CONFIG_PATH, tomlkit.dumps(doc))

    return results


# ---------- copilot: persistent, via ~/.copilot/mcp-config.json merge ----------


def _server_to_copilot_shape(server: MCPServerConfig) -> dict:
    if server.command:
        entry: dict = {
            "type": "local",
            "command": server.command,
            "args": list(server.args),
            "tools": ["*"],
        }
        if server.env:
            entry["env"] = dict(server.env)
        return entry
    entry = {
        "type": "sse" if server.transport == "sse" else "http",
        "url": server.url,
        "tools": ["*"],
    }
    if server.headers:
        entry["headers"] = dict(server.headers)
    return entry


def sync_copilot(servers: list[MCPServerConfig]) -> list[SyncResult]:
    return _sync_json_mcp_config(
        COPILOT_MCP_CONFIG_PATH,
        "mcpServers",
        servers,
        _server_to_copilot_shape,
    )


# ---------- opencode: persistent, via ~/.config/opencode/opencode.json merge ----------


def _server_to_opencode_shape(server: MCPServerConfig) -> dict:
    if server.command:
        cmd_list = [server.command, *server.args]
        entry: dict = {"type": "local", "command": cmd_list, "enabled": True}
        if server.env:
            entry["environment"] = dict(server.env)
        return entry
    entry = {"type": "remote", "url": server.url, "enabled": True}
    if server.headers:
        entry["headers"] = dict(server.headers)
    return entry


def sync_opencode(servers: list[MCPServerConfig]) -> list[SyncResult]:
    return _sync_json_mcp_config(
        OPENCODE_MCP_CONFIG_PATH,
        "mcp",
        servers,
        _server_to_opencode_shape,
    )


# ---------- droid: persistent, via ~/.factory/mcp.json merge ----------


def sync_droid(servers: list[MCPServerConfig]) -> list[SyncResult]:
    return _sync_json_mcp_config(
        DROID_MCP_CONFIG_PATH,
        "mcpServers",
        servers,
        _server_to_standard_shape,
    )


# ---------- devin: persistent, via mcp_config.json merge ----------


def sync_devin(servers: list[MCPServerConfig]) -> list[SyncResult]:
    return _sync_json_mcp_config(
        DEVIN_MCP_CONFIG_PATH,
        "mcpServers",
        servers,
        _server_to_standard_shape,
    )


def sync(agent_id: str, servers: list[MCPServerConfig]) -> list[SyncResult]:
    if agent_id == "gemini":
        return sync_gemini(servers)
    if agent_id == "agent":
        return sync_cursor(servers)
    if agent_id == "codex":
        return sync_codex(servers)
    if agent_id == "copilot":
        return sync_copilot(servers)
    if agent_id == "opencode":
        return sync_opencode(servers)
    if agent_id == "droid":
        return sync_droid(servers)
    if agent_id == "devin":
        return sync_devin(servers)
    raise ValueError(
        f"secfoo mcp sync isn't supported for {agent_id!r}. "
        f"claude uses --mcp-config automatically on every run (no sync needed); "
        f"agy doesn't expose any MCP configuration mechanism via its CLI yet; "
    )
