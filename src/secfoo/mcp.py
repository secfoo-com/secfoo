"""Bridges secfoo's portable MCP server config (settings.py) to each agent
CLI's own mechanism for it. These differ a lot by CLI (verified directly
against each `--help` output, Aug 2026):

- claude: supports `--mcp-config <file>`, which loads servers scoped to just
  that one invocation -- no global state touched. Handled automatically by
  ClaudeAdapter on every run; no explicit sync step needed.
- gemini: has a `gemini mcp add <name> <commandOrUrl> ...` subcommand that
  registers a server persistently (user or project scope). No per-invocation
  file flag exists, so this must be done once via `secfoo mcp sync`.
- agent (Cursor): has no `mcp add` subcommand at all -- servers are defined
  by editing `~/.cursor/mcp.json` directly, then approved via
  `agent mcp enable <name>`. `secfoo mcp sync` does that merge.
- agy (Antigravity): no MCP subcommand or flag exposed by the CLI at all as
  of this writing. Not supported; `secfoo mcp sync --agent agy` refuses with
  a clear error rather than silently doing nothing.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from secfoo.config import STORE_DIR
from secfoo.settings import MCPServerConfig

CLAUDE_MCP_CONFIG_PATH = STORE_DIR / "claude-mcp-config.json"
CURSOR_MCP_CONFIG_PATH = Path.home() / ".cursor" / "mcp.json"

SYNC_SUPPORTED_AGENTS = {"gemini", "agent"}


@dataclass
class SyncResult:
    server_name: str
    ok: bool
    message: str


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
    STORE_DIR.mkdir(parents=True, exist_ok=True)
    CLAUDE_MCP_CONFIG_PATH.write_text(json.dumps(payload, indent=2))
    return CLAUDE_MCP_CONFIG_PATH


# ---------- gemini: persistent, via `gemini mcp add` ----------

_GEMINI_LIST_NAME_RE = re.compile(r"^[^\sA-Za-z0-9]*\s*([^\s:]+):")


def _gemini_existing_names() -> set[str]:
    proc = subprocess.run(["gemini", "mcp", "list"], capture_output=True, text=True, timeout=30)
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
        proc = subprocess.run(_gemini_add_command(server), capture_output=True, text=True, timeout=30)
        if proc.returncode == 0:
            results.append(SyncResult(server.name, True, "added"))
        else:
            results.append(SyncResult(server.name, False, proc.stderr.strip() or proc.stdout.strip()))
    return results


# ---------- agent (Cursor): persistent, via ~/.cursor/mcp.json merge ----------


def sync_cursor(servers: list[MCPServerConfig]) -> list[SyncResult]:
    CURSOR_MCP_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing: dict = {}
    if CURSOR_MCP_CONFIG_PATH.exists():
        try:
            existing = json.loads(CURSOR_MCP_CONFIG_PATH.read_text()).get("mcpServers", {})
        except json.JSONDecodeError as exc:
            return [SyncResult("*", False, f"{CURSOR_MCP_CONFIG_PATH} is not valid JSON: {exc}")]

    results = []
    newly_added: list[str] = []
    for server in servers:
        if server.name in existing:
            results.append(SyncResult(server.name, True, "already configured, skipped"))
            continue
        existing[server.name] = _server_to_standard_shape(server)
        newly_added.append(server.name)
        results.append(SyncResult(server.name, True, f"added to {CURSOR_MCP_CONFIG_PATH}"))

    if newly_added:
        CURSOR_MCP_CONFIG_PATH.write_text(json.dumps({"mcpServers": existing}, indent=2))
        for name in newly_added:
            proc = subprocess.run(["agent", "mcp", "enable", name], capture_output=True, text=True, timeout=30)
            if proc.returncode != 0:
                for result in results:
                    if result.server_name == name:
                        result.ok = False
                        result.message += f" (enable failed: {proc.stderr.strip()})"
    return results


def sync(agent_id: str, servers: list[MCPServerConfig]) -> list[SyncResult]:
    if agent_id == "gemini":
        return sync_gemini(servers)
    if agent_id == "agent":
        return sync_cursor(servers)
    raise ValueError(
        f"secfoo mcp sync isn't supported for {agent_id!r}. "
        f"claude uses --mcp-config automatically on every run (no sync needed); "
        f"agy doesn't expose any MCP configuration mechanism via its CLI yet."
    )
